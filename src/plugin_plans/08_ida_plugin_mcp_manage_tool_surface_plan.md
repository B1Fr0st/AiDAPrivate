# AiDA IDA Plugin MCP Manage Tool Surface Plan

This plan defines the production MCP tool surface for the AiDA IDA Pro plugin. It is scoped to the IDA plugin only. Standalone MCP code is referenced only to learn the consolidated manage-tool pattern where one MCP tool exposes many operations through structured parameters.

The plan supersedes the one-off tool naming model in earlier plugin plans where it conflicts with MCP-first reverse engineering workflows. The implementation goal is a low-count, high-capability, deterministic MCP surface that supports multi-IDA routing, long-running jobs, cancellation, pagination, evidence export, and strict machine-readable reports without modal UI.

## Scope

In scope:

- IDA plugin MCP tool registration, schema, routing, response envelopes, resources, jobs, pagination, cancellation, export, cache/index management, diagnostics, and compatibility wrappers.
- AI/MCP-first workflows for binary inventory, corpus work, function and instruction extraction, types, xrefs, decompiler and microcode extraction, vulnerability chain verification, trigger tracing, boundary matching, report export, evidence navigation, and deterministic diagnostics.
- Compatibility with existing `instance_id` and `pid` routing for multi-IDA sessions.

Out of scope:

- Standalone IDE MCP changes.
- Server, driver, protector, bootstrap, or deployment changes.
- Build-system changes.
- Source implementation in this planning pass.

## Required Evidence Read

The existing plan set establishes the operating constraints this MCP surface must preserve:

- `01_ida_lifecycle_ui_stability_plan.md`: IDA work must avoid modal wait boxes and UI-thread stalls. Long operations need bounded main-thread slices, nonblocking Hex-Rays use where possible, and cancellable job state.
- `02_multibinary_project_model_plan.md`: multi-binary analysis needs durable module identity using module IDs plus RVAs, corpus-level manifests, cross-IDB instance routing, chain specs, and state tracking across multiple open IDBs.
- `03_chain_verification_engine_plan.md`: chain verification requires structured claims, links, boundaries, trigger paths, proof state, confidence, and exportable reports. The one-off tool names in that plan should be consolidated behind manage operations.
- `04_ida_extraction_decompiler_plan.md`: extraction must expose raw bytes, instructions, xrefs, functions, CFG, decompiler text, ctree-derived facts, and microcode-derived facts with budgeted, paginated, repeatable results.
- `05_performance_reliability_plan.md`: expensive work must run through jobs with generations, snapshots, cache invalidation, bounded slices, partial results, and cancellation.
- `06_existing_plugin_audit_and_workbreakdown.md`: the current IDA plugin already has broad tool coverage, but the public MCP surface is too fragmented for AI agents and must be consolidated.
- `driver/PROGRESS.md` final section: recent verification lessons show that MCP-first inspection, export, and cancellation are necessary. The NTFS to ETW case was resolved by proving zero bytes against controlled input, the AFD UAF case required exposing hidden `LIST_ENTRY` self-reference evidence around `_setjmp`, and the `pvScan0` case required proving a logical dataflow contradiction rather than accepting a plausible-looking chain.

## Current IDA MCP Audit

### Registration Model

`src/agent_tools.hpp` defines `tool_result_t`, `tool_definition_t`, and `ToolRegistry`. The current metadata includes:

- `name`
- `category`
- `description`
- `parameters`
- `handler`
- `read_only`
- `output_schema`
- `destructive`
- `deterministic`
- `required_indices`

`src/agent_tools.cpp` enforces several useful rules:

- Empty names and missing handlers are rejected.
- Duplicate tool names are rejected.
- Known mutating names are migrated to `destructive=true`.
- `read_only && destructive` is rejected.
- `generate_tools_schema()` exposes name, category, description, parameters, `read_only`, `destructive`, `deterministic`, `required_indices`, and `output_schema`.
- `execute_tool()` normalizes parameter variants, catches C++ exceptions, and returns structured success/error fields.

The missing production feature is per-operation metadata. Once manage tools consolidate many operations behind a single MCP tool name, `read_only`, `destructive`, `deterministic`, budget limits, job behavior, cache behavior, and required indices must be declared per operation, not only per tool.

### Execution And Routing

`src/mcp_server.cpp` currently routes `tools/call` through `handle_tools_call()`:

- `instance_id` and `pid` can target another IDA instance.
- Requests are proxied to peer plugin HTTP endpoints when the target is not the current instance.
- `list_ida_instances`, `get_local_instance_info`, and `query_all_instances` are registered as aggregator tools.
- Normal tools run via `execute_tool_in_main_thread()`.
- `MFF_READ` or `MFF_WRITE` is selected from `read_only`.
- Deterministic non-destructive results can be cached.
- Destructive tools flush the deduplication cache.
- Large output is truncated and cached behind `/output/<id>.json`.
- Progress notifications are emitted through MCP progress events.

The current batch path also has behavior that must not be used for MCP-first long work:

- `mcp_batch_exec_request_t` can display `show_wait_box()`, call `replace_wait_box()`, check `user_cancelled()`, and hide the wait box. MCP jobs must not use this pattern.
- Parallel batch helper code uses wall-clock cancellation and wait-box cancellation state. MCP job cancellation must be explicit through job IDs and request cancellation tokens.

### Current Tool Surface

The IDA plugin already exposes many capabilities, but as fragmented one-off tools and aliases:

- Function extraction and analysis: `get_function`, `list_functions`, `decompile_function`, `disassemble_function`, `get_xrefs_to`, `get_xrefs_from`, `build_call_graph`, `get_basic_blocks`, `get_stack_frame`, `set_function_signature`.
- Memory and database mutation: `read_bytes`, `read_integer`, `read_string`, `patch_bytes`, `make_code`, `make_data`, `undefine`, `rename_function`, `define_function`.
- Comments, types, imports, exports, search, segments, binary metadata, navigation, analysis, deobfuscation, GraphRAG, batch aliases, and metadata tools.
- Vulnerability tools across `src/vuln/*`: callsite discovery, input-source discovery, microcode dataflow, SMT path solving, taint tracing, CFG reachability, kernel IOCTL detection, user-pointer dereference detection, attack surface classification, protocol router discovery, callback enumeration, weak crypto and credential discovery.
- Verification tools in `src/vuln/verification_tools.cpp`: `verify_status`, `verify_taint_path`, `solve_for_exploit_input`, `prove_loop_bound`, `prove_pointer_alias`, `simplify_function_arithmetic`, `check_path_satisfiability`, `solve_smt_query`, `triage_sink`, `list_verified`, `verify_ledger_persist`, `cancel_verification`, `extract_wire_path_constraints`, and `synthesize_exploit_payload`.

This breadth is good, but the public MCP surface is hard for AI agents to discover and use efficiently. The same workflow currently requires many tool names, inconsistent parameters, inconsistent cancellation, and inconsistent output shapes.

### Current Resources

`src/mcp_server.cpp` already exposes useful resources:

- Static resources: `ida://binary-info`, `ida://database-info`, `ida://segments`, `ida://imports`, `ida://exports`, `ida://entry-points`, `ida://idb/metadata`, `ida://idb/segments`, `ida://idb/entrypoints`, `ida://cursor`, `ida://selection`, `ida://types`, `ida://structs`, `ida://databases`.
- Dynamic templates: `ida://function/{address}`, `ida://address/{address}`, `ida://struct/{name}`, `ida://import/{name}`, `ida://export/{name}`, `ida://xrefs/from/{addr}`.

These resources should remain compatible, but the final model needs module-aware and job-aware resources so AI agents can work across multiple IDBs without address ambiguity.

### Instance Registry

`src/instance_registry.hpp` and `src/instance_registry.cpp` already track:

- `instance_id`
- `pid`
- `port`
- MCP and HTTP URLs
- IDB path
- input file path and basename
- file MD5 and SHA-256
- processor and bitness
- hostname and IDA version
- heartbeat timestamps

The final tool surface should use this registry as the authority for multi-IDA routing and corpus binding. Tool responses must echo the resolved instance identity so AI agents can detect stale peers and wrong-IDB results.

## Standalone Manage-Pattern Findings

The standalone tree does not contain the exact `feature_manage` or `feature2_manage` names, but it does contain the desired pattern:

- `sessions_manage` in `src/standalone/src/core/tools/session_tools_standalone.cpp` exposes many session operations through one tool. It accepts `action`, also accepts `operation` as an alias, flattens an optional `payload`, removes routing fields, and dispatches to operation handlers.
- `standalone_compat.hpp` centralizes `action` or `operation` extraction, payload flattening, and unknown-action errors.
- `burp_scanner_manage` exposes start, status, list, cancel, issues, modules, and passive scanning operations through one tool.
- `burp_repeater_manage` exposes send, raw send, tab listing, tab retrieval, close, replay from exchange, request update, and target update through one tool.
- Other standalone tools use manage-style dispatch for feature groups that would otherwise create a large tool catalog.

IDA plugin MCP should adopt the pattern but tighten it:

- Use `operation` as the documented field. Accept `action` only as a migration alias.
- Require per-operation metadata in the registry.
- Use a single response envelope across all manage tools.
- Use strict schemas for each operation payload.
- Declare per-operation `read_only`, `destructive`, `deterministic`, `job_mode`, `cache_policy`, `budget`, and `required_indices`.
- Return job handles for long operations rather than using modal UI.
- Expose operation documentation and examples through discovery resources.

## IDA SDK Evidence For API Rules

Every SDK recommendation in this plan is backed by the IDA SDK headers under `ida-sdk/src/include`.

### Multi-IDB Plugin Model

Use the plugmod and multi-IDB plugin model because MCP routing can target multiple open IDBs.

`ida-sdk/src/include/loader.hpp`:

```cpp
#define PLUGIN_MULTI 0x0100 ///< The plugin can work with multiple idbs in parallel.
                            ///< The kernel will call init() to create a new
                            ///< plugmod_t instance for each idb.
                            ///< run() and term() are not used for PLUGIN_MULTI plugins.
```

`ida-sdk/src/include/idp.hpp`:

```cpp
struct plugmod_t
{
  virtual ~plugmod_t() {}
  virtual bool idaapi run(size_t arg) = 0;
  bool hook_event_listener(hook_type_t hook_type, event_listener_t *cb, void *ud=nullptr)
  {
    return ::hook_event_listener(hook_type, cb, ud, this);
  }
};
```

### Main-Thread Execution And Exception Containment

IDA database access must continue to use `execute_sync()` with read/write flags, but manage-tool implementations must keep main-thread work bounded and route expensive computation through jobs.

`ida-sdk/src/include/kernwin.hpp`:

```cpp
#define MFF_READ        0x0001
#define MFF_WRITE       0x0002
#define MFF_NOWAIT      0x0004
struct exec_request_t
{
  virtual int idaapi execute(void) = 0;
};
idaman int ida_export execute_sync(exec_request_t &req, int reqf);
```

The same header warns that uncontained exceptions can prevent `execute_sync()` from returning:

```cpp
// If this function raises an exception, execute_sync() never returns.
```

### No Modal Wait Boxes For MCP Jobs

MCP long operations must not call IDA modal wait-box APIs. Modal wait boxes are UI constructs and can disable the interface if not balanced.

`ida-sdk/src/include/kernwin.hpp`:

```cpp
idaman AS_PRINTF(1, 2) void ida_export show_wait_box(const char *format, ...);
idaman void ida_export replace_wait_box(const char *format, ...);
idaman void ida_export hide_wait_box(void);
idaman bool ida_export user_cancelled(void);
```

The header also documents that wait boxes need exact balancing:

```cpp
// For each call to show_wait_box() you have to call hide_wait_box().
// In some cases the wait box can be hidden by the user. If your plugin
// calls hide_wait_box() at this time, IDA will display a warning about
// the wait box being already hidden.
```

### Decompiler And Microcode Extraction

Decompiler extraction should use explicit nonblocking behavior where available, and microcode extraction must be budgeted.

`ida-sdk/src/include/hexrays.hpp`:

```cpp
#define DECOMP_NO_WAIT 0x0001
idaapi cfuncptr_t decompile(ea_t entry_ea, hexrays_failure_t *hf=nullptr, int flags=0);
idaapi mba_t *gen_microcode(const mba_ranges_t &mba_ranges,
                            hexrays_failure_t *hf,
                            const mlist_t *retlist,
                            int decomp_flags,
                            int maturity);
class mba_t
{
  int for_all_insns(minsn_visitor_t &mv) const;
};
```

### Functions, Instructions, Xrefs, And Thunks

Function and instruction extraction must use IDA function boundaries and item iterators rather than guessing ranges.

`ida-sdk/src/include/funcs.hpp`:

```cpp
idaman func_t *ida_export get_func(ea_t ea);
idaman func_t *ida_export getn_func(size_t n);
idaman size_t ida_export get_func_qty(void);
idaman ea_t ida_export calc_thunk_func_target(func_t *pfn);
class func_item_iterator_t
{
  bool set(func_t *pfn);
  bool next_code(void);
};
```

Xref extraction should use `xrefblk_t` and preserve direction, code/data status, and type.

`ida-sdk/src/include/xref.hpp`:

```cpp
class xrefblk_t
{
public:
  ea_t from;
  ea_t to;
  uchar iscode;
  uchar type;
  bool first_from(ea_t from, int flags);
  bool next_from(void);
  bool first_to(ea_t to, int flags);
  bool next_to(void);
};
```

### Binary Inventory

Binary inventory must rely on loader metadata, entry APIs, segment APIs, and import enumeration.

`ida-sdk/src/include/nalt.hpp`:

```cpp
idaman ssize_t ida_export get_input_file_path(char *buf, size_t bufsize);
idaman const uchar *ida_export retrieve_input_file_md5(void);
idaman const uchar *ida_export retrieve_input_file_sha256(void);
idaman ea_t ida_export get_imagebase(void);
idaman uint ida_export get_import_module_qty(void);
idaman bool ida_export enum_import_names(uint mod_index, enum_import_names_cb_t *callback, void *param);
```

`ida-sdk/src/include/entry.hpp`:

```cpp
idaman size_t ida_export get_entry_qty(void);
idaman const char *ida_export get_entry_forwarder(size_t ord);
```

`ida-sdk/src/include/segment.hpp`:

```cpp
idaman int ida_export get_segm_qty(void);
idaman segment_t *ida_export getseg(ea_t ea);
idaman segment_t *ida_export getnseg(int n);
```

### Types And Function Signatures

Type operations must use IDA type APIs and report whether changes are mutating.

`ida-sdk/src/include/nalt.hpp`:

```cpp
idaman bool ida_export get_tinfo(tinfo_t *tif, ea_t ea);
```

`ida-sdk/src/include/typeinf.hpp`:

```cpp
idaman bool ida_export apply_callee_tinfo(ea_t caller, const tinfo_t &tif);
idaman int ida_export get_arg_addrs(eavec_t *out, ea_t caller);
struct func_type_data_t;
class tinfo_t
{
  bool get_func_details(func_type_data_t *r, gtd_func_t gtd=GTD_CALC_LAYOUT) const;
};
```

### Persistent Plugin State

Plugin-owned indexes, ledgers, and cache manifests should use IDA netnodes or existing AiDA persistence. User netnode names must follow IDA rules.

`ida-sdk/src/include/netnode.hpp`:

```cpp
// User-defined netnodes should have names starting with "$ ".
class netnode
{
  ssize_t getblob(void *buf, size_t bufsize, nodeidx_t start, char tag) const;
  bool setblob(const void *buf, size_t size, nodeidx_t start, char tag);
};
```

### Autoanalysis Settling

Long extraction should report whether autoanalysis is settled and should not hide unsettled state from AI agents.

`ida-sdk/src/include/auto.hpp`:

```cpp
idaman bool ida_export auto_wait_range(ea_t ea1, ea_t ea2);
idaman bool ida_export auto_is_ok(void);
```

## Design Principles

1. Keep the public MCP tool count low. The default public catalog should contain eight consolidated IDA manage tools plus the existing routing compatibility tools.
2. Use `operation` enums instead of many one-off tool names.
3. Return one response envelope for every operation.
4. Declare per-operation metadata. Tool-level metadata is insufficient for manage tools.
5. Treat every long operation as a job. MCP paths must not display modal UI, wait boxes, file dialogs, warnings, or info dialogs.
6. Make all list-like results paginated and cursor-based.
7. Make all large results exportable through resources or output handles.
8. Keep multi-IDA identity explicit. Every response must identify the resolved instance, module, and corpus context when applicable.
9. Keep mutating IDB operations isolated behind one explicit mutation tool.
10. Preserve security: no license bypasses, no hidden destructive behavior, no raw secrets in chat-facing output, and no fail-open paths.

## Common Request Shape

All manage tools use this request shape:

```json
{
  "operation": "string enum",
  "schema_version": "aida.ida.mcp.manage.v1",
  "instance_id": "optional target IDA instance id",
  "pid": "optional target IDA process id",
  "request_id": "optional caller id for correlation",
  "idempotency_key": "optional caller id for retry-safe job creation",
  "job_mode": "inline|job|auto",
  "cursor": "optional opaque page cursor",
  "limit": 100,
  "budget": {
    "timeout_ms": 10000,
    "max_items": 1000,
    "max_bytes": 1048576,
    "max_functions": 500,
    "max_depth": 5,
    "solver_timeout_ms": 5000,
    "allow_partial": true,
    "priority": "low|normal|high"
  },
  "payload": {}
}
```

Compatibility rule: `action` is accepted as an alias for `operation` during migration. Documentation, examples, and generated schemas must use `operation`.

## Common Response Envelope

Every operation returns this envelope:

```json
{
  "ok": true,
  "schema": "aida.ida.mcp.response.v1",
  "tool": "ida_extract_manage",
  "operation": "function",
  "request_id": "caller supplied or generated id",
  "instance": {
    "instance_id": "ida-...",
    "pid": 1234,
    "idb_path": "C:/cases/driver.i64",
    "input_sha256": "hex",
    "processor": "metapc",
    "bitness": 64,
    "database_generation": 42
  },
  "module": {
    "module_id": "sha256:imagebase:input-basename",
    "imagebase": "0x140000000",
    "address_model": "module_id+rva"
  },
  "job": null,
  "page": {
    "cursor": null,
    "next_cursor": null,
    "limit": 100,
    "returned": 12,
    "truncated": false
  },
  "data": {},
  "warnings": [],
  "resources": [],
  "error": null
}
```

Error responses use the same envelope:

```json
{
  "ok": false,
  "schema": "aida.ida.mcp.response.v1",
  "tool": "ida_chain_manage",
  "operation": "submit",
  "request_id": "caller supplied or generated id",
  "instance": null,
  "module": null,
  "job": null,
  "page": null,
  "data": null,
  "warnings": [],
  "resources": [],
  "error": {
    "code": "bad_param",
    "message": "chain.links[2].source is required",
    "retryable": false,
    "details": {
      "field": "payload.chain.links[2].source",
      "expected": "module_id+rva address object"
    }
  }
}
```

Allowed error codes:

- `bad_param`
- `unsupported_operation`
- `unknown_operation`
- `schema_version_unsupported`
- `peer_unavailable`
- `peer_timeout`
- `wrong_instance`
- `idb_unavailable`
- `analysis_not_settled`
- `hexrays_unavailable`
- `index_required`
- `budget_exhausted`
- `result_too_large`
- `cursor_expired`
- `job_not_found`
- `job_conflict`
- `cancelled`
- `timeout`
- `stale_generation`
- `destructive_denied`
- `license_required`
- `rate_limited`
- `internal_error`

## Per-Operation Metadata

`tool_definition_t` needs an operation metadata map for manage tools:

```json
{
  "operations": {
    "function": {
      "read_only": true,
      "destructive": false,
      "deterministic": true,
      "job_mode": "inline|job|auto",
      "cache_policy": "none|dedupe|generation|persistent",
      "required_indices": ["functions"],
      "default_budget": {
        "timeout_ms": 1000,
        "max_bytes": 262144
      },
      "required_fields": ["payload.address"],
      "result_schema": "aida.ida.extract.function.v1"
    }
  }
}
```

`tools/list` should expose operation metadata for public tools. Legacy wrappers should be hidden by default and visible only through `ida_discover_manage` with `include_legacy=true`.

## Final Public MCP Tool Set

The default public MCP tool catalog should contain these IDA plugin tools:

1. `ida_discover_manage`
2. `ida_project_manage`
3. `ida_extract_manage`
4. `ida_analysis_manage`
5. `ida_chain_manage`
6. `ida_job_manage`
7. `ida_cache_manage`
8. `ida_mutation_manage`
9. `ida_diagnostics_manage`

The existing routing primitives may remain public for compatibility:

- `list_ida_instances`
- `get_local_instance_info`
- `query_all_instances`

All other one-off tools become compatibility wrappers or internal helpers.

## Tool Specifications

### `ida_discover_manage`

Purpose: make the IDA plugin MCP surface self-describing and route-aware.

Tool-level metadata:

- `read_only`: true
- `destructive`: false
- `deterministic`: false
- `job_mode`: inline only

Operations:

| Operation | Payload fields | Result |
| --- | --- | --- |
| `server_status` | none | MCP server status, plugin version, schema versions, uptime, request counters |
| `capabilities` | `include_operations`, `include_examples`, `include_legacy` | public tools, operation metadata, budgets, resources, examples |
| `operation_docs` | `tool`, optional `operation` | one tool or operation contract with params, examples, errors, migration names |
| `schema` | `tool`, optional `operation` | JSON schema for request and result |
| `instances` | `include_stale`, `hostname`, `idb_filter` | live and stale IDA instances from `instance_registry` |
| `local_instance` | none | current instance identity and database metadata |
| `route_check` | `instance_id` or `pid` | resolved target, peer URL, staleness, route status |
| `resource_catalog` | `include_templates` | available resources and templates |
| `health` | `deep` | local health, registry health, Hex-Rays availability, job runtime health |

Required response fields:

- `data.capabilities.schema_versions`
- `data.capabilities.tools[].operations[]`
- `data.instances[]` for instance operations
- `data.route` for `route_check`

### `ida_project_manage`

Purpose: expose binary/project inventory, multi-binary corpus management, and corpus indexing.

Tool-level metadata:

- `read_only`: false because some operations bind or update plugin-owned project state.
- `destructive`: false by default.
- Per-operation destructive metadata controls cache or corpus deletion.

Operations:

| Operation | Read-only | Job | Payload fields | Result |
| --- | --- | --- | --- | --- |
| `inventory_current` | true | auto | `include_segments`, `include_imports`, `include_exports`, `include_entries`, `include_hashes` | current IDB inventory |
| `inventory_all` | true | auto | `include_stale`, `corpus_id`, `limit` | inventory for live routed instances |
| `corpus_create` | false | inline | `name`, `case_id`, `modules[]` | corpus record |
| `corpus_list` | true | inline | filters | corpus summaries |
| `corpus_get` | true | inline | `corpus_id` | corpus manifest |
| `corpus_bind_instance` | false | inline | `corpus_id`, `instance_id`, `module_role` | binding record |
| `corpus_unbind_instance` | false | inline | `corpus_id`, `instance_id` | updated manifest |
| `corpus_index_start` | false | job | `corpus_id`, `index_kinds[]`, `force_generation` | job handle |
| `corpus_index_status` | true | inline | `corpus_id` | index generations and coverage |
| `corpus_index_cancel` | false | inline | `corpus_id`, `job_id` | cancellation result |
| `corpus_export_manifest` | true | auto | `corpus_id`, `format` | resource URI and hash |

Address identity:

```json
{
  "module_id": "sha256:imagebase:input-basename",
  "rva": "0x1234",
  "ea": "0x140001234"
}
```

Corpus records must never rely on raw EAs alone. EAs may be echoed as current-instance convenience fields, but module ID plus RVA is the stable address model.

### `ida_extract_manage`

Purpose: expose deterministic extraction from IDB, functions, instructions, xrefs, types, decompiler, and microcode through one read-oriented tool.

Tool-level metadata:

- `read_only`: true
- `destructive`: false
- `deterministic`: true when database generation and cache generation match

Operations:

| Operation | Job | Required payload | Result |
| --- | --- | --- | --- |
| `binary` | inline | optional `include_hashes` | binary metadata |
| `segments` | inline | optional filters | segment list |
| `imports` | auto | `module_filter`, `name_filter`, paging | imports |
| `exports` | auto | filters, paging | exports |
| `entrypoints` | inline | none | entry points |
| `functions` | auto | filters, cursor, limit | function summaries |
| `function` | inline | `address` or `module_id+rva` | function details |
| `instructions` | auto | `range` or `function`, `include_bytes`, `include_xrefs` | instruction rows |
| `bytes` | inline | `address`, `size`, optional `encoding` | bytes and hashes |
| `xrefs` | auto | `address`, `direction`, `xref_kind` | xref rows |
| `callgraph` | job | `roots[]`, `direction`, `max_depth` | graph resource |
| `cfg` | auto | `function` | basic blocks and edges |
| `types` | auto | `scope`, filters, cursor | types and structs |
| `decompile` | job | `function`, `layers[]` | decompiler text and facts |
| `microcode` | job | `function`, `maturity`, `facts[]` | microcode facts |
| `search` | job | `kind`, `query`, `scope`, limits | matches |
| `path_window` | auto | `source`, `sink`, `max_blocks`, `include_conditions` | local path evidence |
| `signatures` | auto | `function`, `include_thunks`, `include_args` | function signatures |

`decompile.layers` enum:

- `pseudocode`
- `ctree_facts`
- `calls`
- `locals`
- `arg_uses`
- `return_facts`
- `microcode_summary`

`microcode.facts` enum:

- `ssa_defs`
- `uses`
- `value_ranges`
- `memory_refs`
- `calls`
- `conditions`
- `taint_hints`

All operations returning rows must include:

- `page.returned`
- `page.next_cursor`
- `data.rows[]`
- `data.generation`
- `resources[]` when an export was generated

### `ida_analysis_manage`

Purpose: expose vulnerability-oriented static analysis and reverse-engineering queries while keeping chain verification separate.

Tool-level metadata:

- `read_only`: true
- `destructive`: false
- `job_mode`: auto or job for expensive operations

Operations:

| Operation | Job | Payload fields | Result |
| --- | --- | --- | --- |
| `attack_surface` | job | `scope`, `roles[]`, `include_evidence` | attack surface report |
| `input_sources` | job | `scope`, `source_kinds[]` | attacker-controlled sources |
| `sinks` | job | `scope`, `sink_kinds[]` | sink catalog |
| `callsites` | job | `callee`, `name_pattern`, `scope` | callsites |
| `taint_trace` | job | `source`, `sink`, `constraints`, `max_depth` | taint path candidates |
| `dataflow` | job | `seed`, `direction`, `scope`, `facts[]` | dataflow graph |
| `indirect_calls` | job | `scope`, `resolution_policy` | indirect-call targets |
| `dispatch_tables` | job | `scope`, `table_kinds[]` | dispatch table report |
| `callbacks` | job | `scope`, `callback_kinds[]` | callback candidates |
| `kernel_ioctl` | job | `scope`, `include_dispatch` | IOCTL dispatch report |
| `user_pointer_deref` | job | `scope`, `include_validation` | user-pointer deref report |
| `state_machine` | job | `entry`, `state_vars[]` | state machine graph |
| `parser_shapes` | job | `scope`, `protocol_hints[]` | parser-shaped functions |
| `vuln_candidates` | job | `classes[]`, `scope`, `confidence_min` | vulnerability candidates |
| `boundary_match` | job | `producer`, `consumer`, `boundary_spec` | boundary evidence |
| `trigger_trace` | job | `entry`, `target`, `input_model` | trigger path candidates |
| `value_range` | auto | `expression`, `function`, `path_constraints` | range proof |
| `smt_query` | job | `query`, `solver`, `timeout_ms` | solver result |

Analysis result rows must include:

- `finding_id`
- `class`
- `confidence`
- `module_id`
- `rva`
- `evidence[]`
- `assumptions[]`
- `counterevidence[]`
- `resource_uri` for large graphs or reports

### `ida_chain_manage`

Purpose: make vulnerability chain verification a first-class MCP workflow with submission, proof tracking, cancellation, evidence navigation, and export.

Tool-level metadata:

- `read_only`: false because verification writes plugin-owned ledgers, cache records, and reports.
- `destructive`: false by default.
- Per-operation destructive only for explicit record deletion.

Operations:

| Operation | Read-only | Job | Payload fields | Result |
| --- | --- | --- | --- | --- |
| `validate_spec` | true | inline | `chain` | normalized spec and validation diagnostics |
| `submit` | false | job | `chain`, `budgets`, `export_policy` | chain job handle |
| `status` | true | inline | `chain_id` or `job_id` | chain state |
| `list` | true | inline | filters, cursor, limit | chain ledger rows |
| `cancel` | false | inline | `chain_id` or `job_id`, `reason` | cancellation state |
| `get_report` | true | auto | `chain_id`, `format`, `include_evidence` | report or resource |
| `export_report` | true | job | `chain_id`, `formats[]`, `include_artifacts` | export resources |
| `verify_link` | false | job | `chain_id`, `link_id`, optional override budget | link verification job |
| `match_boundaries` | false | job | `chain_id`, `boundary_ids[]` | boundary proof |
| `trace_trigger` | false | job | `chain_id`, `trigger`, `target` | trigger proof |
| `navigate_evidence` | true | auto | `chain_id`, `evidence_id`, `view` | focused evidence |
| `explain_failure` | true | auto | `chain_id`, `link_id`, `include_counterevidence` | failure explanation |
| `record_delete` | false | inline | `chain_id`, `confirm_destructive` | deleted ledger record |

Chain spec shape:

```json
{
  "chain_id": "optional stable caller id",
  "title": "human readable chain title",
  "corpus_id": "optional corpus id",
  "modules": [
    {
      "module_id": "sha256:imagebase:name",
      "role": "producer|consumer|driver|service|library"
    }
  ],
  "entrypoints": [
    {
      "id": "entry-ioctl",
      "address": {
        "module_id": "sha256:imagebase:name",
        "rva": "0x1234"
      },
      "kind": "ioctl|rpc|ipc|file|network|callback|manual"
    }
  ],
  "links": [
    {
      "id": "link-copy",
      "source": "entry-ioctl",
      "sink": {
        "module_id": "sha256:imagebase:name",
        "rva": "0x4567"
      },
      "claim": "attacker controlled length reaches copy",
      "required_evidence": ["control", "bounds", "reachability"]
    }
  ],
  "boundaries": [
    {
      "id": "kernel-user-buffer",
      "producer": "entry-ioctl",
      "consumer": "link-copy",
      "model": "buffer+length"
    }
  ],
  "trigger": {
    "kind": "ioctl",
    "api": "DeviceIoControl",
    "constraints": {}
  }
}
```

Chain reports must include:

- `verdict`: `proven`, `refuted`, `partial`, `inconclusive`, `cancelled`, `failed`
- `confidence`
- `verified_links[]`
- `refuted_links[]`
- `unresolved_links[]`
- `boundary_results[]`
- `trigger_results[]`
- `assumptions[]`
- `counterevidence[]`
- `evidence_index[]`
- `machine_report_resource`
- `markdown_report_resource`
- `report_hash`

The AFD, NTFS, and `pvScan0` lessons require `counterevidence[]` to be as prominent as positive evidence. Reports must explain contradictions, missing trigger control, boundary mismatch, impossible value ranges, and zero-controlled-data proofs.

### `ida_job_manage`

Purpose: central lifecycle API for every long-running MCP operation.

Tool-level metadata:

- `read_only`: false because cancellation and pruning mutate plugin-owned job state.
- `destructive`: false by default.

Operations:

| Operation | Read-only | Payload fields | Result |
| --- | --- | --- | --- |
| `list` | true | filters, cursor, limit | job summaries |
| `status` | true | `job_id`, optional `include_events` | current job state |
| `events` | true | `job_id`, `after_seq`, limit | event rows |
| `result` | true | `job_id`, optional `cursor` | result page or resource |
| `cancel` | false | `job_id`, `reason` | cancellation state |
| `cancel_all` | false | `scope`, `operation_filter`, `reason`, `confirm` | cancellation summary |
| `export` | true | `job_id`, `format`, `include_events` | export resource |
| `prune` | false | `older_than_ms`, `state_filter`, `confirm_destructive` | prune summary |
| `limits` | true | none | configured job limits and active budget usage |

Job state enum:

- `queued`
- `running`
- `cancelling`
- `cancelled`
- `succeeded`
- `failed`
- `timeout`
- `partial`
- `stale`

Job record shape:

```json
{
  "job_id": "job_...",
  "owner_instance_id": "ida-...",
  "tool": "ida_chain_manage",
  "operation": "submit",
  "target": {
    "corpus_id": "case-...",
    "module_id": "sha256:imagebase:name",
    "address": {
      "rva": "0x1234"
    }
  },
  "state": "running",
  "phase": "microcode_dataflow",
  "progress": {
    "completed": 42,
    "total": 100,
    "message": "checking link link-copy"
  },
  "created_at_ms": 0,
  "started_at_ms": 0,
  "updated_at_ms": 0,
  "deadline_ms": 0,
  "cancel_requested": false,
  "budget": {},
  "result_resource": "ida://job/job_.../result",
  "events_resource": "ida://job/job_.../events"
}
```

### `ida_cache_manage`

Purpose: expose cache, index, and generation state without mixing it into every extraction tool.

Tool-level metadata:

- `read_only`: false because warm, invalidate, and clear mutate plugin-owned cache state.
- `destructive`: true only for clear operations that remove persisted plugin state.

Operations:

| Operation | Read-only | Job | Payload fields | Result |
| --- | --- | --- | --- | --- |
| `status` | true | inline | `scope`, `corpus_id`, `module_id` | cache/index status |
| `generations` | true | inline | `scope` | database, index, decompiler, microcode generations |
| `warm` | false | job | `scope`, `index_kinds[]`, `targets[]` | warm job |
| `invalidate` | false | inline | `scope`, `reason` | invalidated generations |
| `clear` | false | inline | `scope`, `confirm_destructive` | cleared cache state |
| `snapshot` | true | job | `scope`, `format` | snapshot resource |
| `coverage` | true | auto | `scope`, `index_kinds[]` | coverage report |

Scopes:

- `current_idb`
- `corpus`
- `function`
- `decompiler`
- `microcode`
- `vuln`
- `chain`
- `all_plugin_owned`

No cache operation may delete or mutate user program bytes, names, comments, types, or IDB analysis state. IDB mutation belongs only in `ida_mutation_manage`.

### `ida_mutation_manage`

Purpose: keep all IDB-mutating operations explicit, auditable, and isolated from read-first AI workflows.

Tool-level metadata:

- `read_only`: false
- `destructive`: true
- `deterministic`: false

Operations:

| Operation | Payload fields | Required safety fields | Result |
| --- | --- | --- | --- |
| `preview` | `changes[]` | none | normalized change plan |
| `rename` | `target`, `new_name`, `kind` | `confirm_destructive`, `reason` | applied rename |
| `comment_set` | `target`, `comment`, `comment_kind` | `confirm_destructive`, `reason` | applied comment |
| `type_apply` | `target`, `type_decl`, `type_kind` | `confirm_destructive`, `reason` | applied type |
| `patch_bytes` | `address`, `bytes`, `expected_old_bytes` | `confirm_destructive`, `reason` | patch receipt |
| `define_code` | `address`, `size` | `confirm_destructive`, `reason` | analysis receipt |
| `define_function` | `start`, optional `end` | `confirm_destructive`, `reason` | function receipt |
| `make_data` | `address`, `data_type`, `count` | `confirm_destructive`, `reason` | data receipt |
| `undefine` | `address`, `size` | `confirm_destructive`, `reason` | undefine receipt |
| `save_idb` | optional `path` | `confirm_destructive`, `reason` | save receipt |
| `batch_apply` | `changes[]`, `dry_run` | `confirm_destructive`, `reason` | batch receipt |

Safety requirements:

- Default `dry_run=true` for `preview` and batch planning.
- Every mutating operation requires `confirm_destructive=true`.
- Every mutating operation requires a non-empty `reason`.
- `patch_bytes` requires `expected_old_bytes` unless the operation is explicitly marked as forceful with `confirm_destructive=true` and `force=true`.
- Responses must include before/after state, database generation, and cache invalidations.

### `ida_diagnostics_manage`

Purpose: expose observability for MCP, routing, jobs, modal-safety checks, cache health, and recent failures.

Tool-level metadata:

- `read_only`: true except explicit diagnostic cache cleanup routed through `ida_cache_manage`.
- `destructive`: false

Operations:

| Operation | Job | Payload fields | Result |
| --- | --- | --- | --- |
| `recent_errors` | inline | `limit`, `since_ms`, filters | error rows |
| `perf` | inline | `window_ms`, `operation_filter` | latency and budget stats |
| `routing` | inline | `include_stale` | registry and peer route state |
| `jobs` | inline | filters | job runtime diagnostics |
| `resources` | inline | none | resource cache and output-cache state |
| `modal_safety_scan` | auto | `scope` | scan for modal calls in MCP paths |
| `self_test` | job | `checks[]`, `budget` | self-test report |
| `export_bundle` | job | `include_logs`, `include_jobs`, `include_tool_schema` | diagnostic bundle resource |
| `license_state_summary` | inline | none | high-level license gate state without secrets |

Diagnostic output must redact raw credentials, private keys, signing keys, bearer tokens, API keys, and full license keys. It may preserve security-relevant non-secret protocol state, payload context, timing, and MCP routing evidence needed to diagnose failures.

## Resource Model

Existing resources remain compatible. New module-aware and job-aware resources are added:

| Resource | Content |
| --- | --- |
| `ida://instances` | live and stale instance records |
| `ida://instance/{instance_id}/inventory` | resolved IDB and binary inventory |
| `ida://corpus/{corpus_id}/manifest` | corpus manifest |
| `ida://corpus/{corpus_id}/index` | corpus index coverage |
| `ida://module/{module_id}/inventory` | module metadata |
| `ida://module/{module_id}/segments` | segments |
| `ida://module/{module_id}/imports` | imports |
| `ida://module/{module_id}/exports` | exports |
| `ida://module/{module_id}/entrypoints` | entry points |
| `ida://module/{module_id}/functions` | paginated function catalog |
| `ida://function/{module_id}/{rva}` | function detail |
| `ida://function/{address}` | compatibility current-IDB function detail |
| `ida://xrefs/{module_id}/{rva}` | xrefs with `direction` query parameter |
| `ida://types/{module_id}` | types and structs |
| `ida://job/{job_id}/status` | job status |
| `ida://job/{job_id}/events` | job event stream snapshot |
| `ida://job/{job_id}/result` | job result |
| `ida://chain/{chain_id}/report` | chain report |
| `ida://chain/{chain_id}/evidence/{evidence_id}` | focused chain evidence |
| `ida://cache/{scope}/status` | cache status |
| `ida://diagnostics/{kind}` | diagnostic reports |

Resource responses use JSON by default. Large graph and row exports may also provide:

- `application/x-ndjson`
- `application/sarif+json`
- `text/markdown`

Every resource response must include:

- `schema`
- `resource_uri`
- `generated_at_ms`
- `instance_id` when applicable
- `module_id` when applicable
- `generation`
- `content_hash`

## Job Model

All long operations return quickly with a job handle when `job_mode=job` or when `job_mode=auto` determines the operation exceeds inline budget.

Inline budget:

- Default target: return within 500 ms.
- Main-thread IDA database slices target 50 ms or less per slice.
- Any operation expected to enumerate many functions, decompile, generate microcode, solve constraints, analyze taint, traverse a corpus, or export large reports must run as a job.

Job behavior:

- Job IDs are globally unique within the plugin instance.
- The creating operation and payload hash are recorded.
- Idempotency keys prevent duplicate job creation on retry.
- Jobs store events in a bounded ring and summary state in plugin-owned persistence.
- Jobs check cancellation between IDA main-thread slices, decompiler steps, solver steps, graph traversal batches, and export chunks.
- Jobs can return partial results only when `budget.allow_partial=true`.
- Stale database generation marks running extraction jobs `stale` unless the operation is generation-independent.

Cancellation:

- `ida_job_manage.cancel` is the canonical cancellation path.
- `ida_chain_manage.cancel` is a convenience operation for chain jobs and maps to the same job cancellation primitive.
- Existing global `cancel_verification` becomes a compatibility wrapper that cancels matching chain jobs.
- MCP cancellation must not depend on `user_cancelled()`.
- If an IDA `exec_request_t` is pending, cancellation should use IDA cancellation support where safe and mark the job as cancelling.

Export:

- Every completed or partial job can be exported.
- Exports return resource URIs and content hashes.
- Exports are deterministic for the same database generation, corpus manifest, operation payload, and tool version.

## Pagination And Large Output

All list, graph, extraction, report, and evidence operations must support pagination:

```json
{
  "cursor": "opaque cursor",
  "limit": 100,
  "sort": "address|name|confidence|created_at",
  "direction": "asc|desc"
}
```

Cursor rules:

- Cursors are opaque.
- Cursors include operation, generation, target, filter hash, and page position.
- Cursor mismatch returns `cursor_expired` or `stale_generation`.
- Page results must be stable within the same generation.

Large output rules:

- Inline text previews respect the existing MCP output limit.
- Full data is available through `resources[]` or `/output/<id>.json` compatibility handles.
- The envelope must say whether inline data is complete, truncated, or preview-only.

## Security, Rate, And Budget Policy

### Security

- The MCP server remains a localhost trust boundary with mutating capabilities. The public tool catalog must make mutation and destructive behavior explicit.
- No MCP operation may bypass license, ARC, anti-tamper, driver, or server-authority rules.
- Read-only tools must not mutate IDB state, plugin ledgers, caches, or analysis state except for explicit non-semantic telemetry and dedupe caches.
- Plugin-owned chain ledgers, caches, job records, and diagnostics are not IDB program mutations but still need explicit per-operation metadata.
- Destructive operations require `confirm_destructive=true` and a non-empty `reason`.
- Diagnostics must not expose raw credentials, private keys, signing keys, bearer tokens, API keys, or full license keys.

### Rate Limits

Rate limits are enforced per plugin instance, peer route, tool, operation, and client session:

- Inline read operations: high rate, small result budgets.
- Decompiler and microcode operations: medium rate, per-function and per-byte budgets.
- SMT and taint operations: low rate, solver timeout budgets.
- Chain verification: low concurrent count, explicit queue state.
- Mutation operations: serialized per IDB.

### Default Budgets

| Operation class | Default | Hard cap |
| --- | --- | --- |
| Inline metadata | 500 ms, 120 KB preview | 2 s |
| Function extraction | 1 s, 256 KB | 5 s |
| Function list page | 100 rows | 1000 rows |
| Decompile one function | job auto after 500 ms | 30 s |
| Microcode one function | job | 30 s |
| SMT query | 5 s | 60 s |
| Taint/dataflow job | 30 s | 5 min |
| Chain verification | 120 s | 10 min |
| Export job | 60 s | 10 min |

Budget exhaustion returns `budget_exhausted` with partial results only when allowed.

## Backward Compatibility And Migration

### Public Catalog Migration

The registry gains a `visibility` field:

- `public`
- `legacy`
- `internal`

`tools/list` defaults to `public`. `ida_discover_manage.capabilities` can include legacy tools when `include_legacy=true`.

### Wrapper Mapping

Legacy one-off tools remain for one compatibility cycle as wrappers. Each wrapper calls the matching manage operation and adds deprecation metadata in the result.

Representative mappings:

| Legacy tool | Manage replacement |
| --- | --- |
| `get_function` | `ida_extract_manage.function` |
| `list_functions`, `list_funcs` | `ida_extract_manage.functions` |
| `decompile_function`, `decompile` | `ida_extract_manage.decompile` |
| `disassemble_function`, `disasm` | `ida_extract_manage.instructions` |
| `get_xrefs_to`, `get_xrefs_from`, `xref_query` | `ida_extract_manage.xrefs` |
| `read_bytes`, `get_bytes` | `ida_extract_manage.bytes` |
| `list_imports` | `ida_extract_manage.imports` |
| `list_exports` | `ida_extract_manage.exports` |
| `build_call_graph` | `ida_extract_manage.callgraph` |
| `find_vulnerable_sinks` | `ida_analysis_manage.sinks` |
| `find_input_sources` | `ida_analysis_manage.input_sources` |
| `trace_taint_path` | `ida_analysis_manage.taint_trace` |
| `get_microcode_dataflow`, `mc_dataflow_ssa` | `ida_extract_manage.microcode` or `ida_analysis_manage.dataflow` according to payload |
| `find_kernel_ioctl_handlers` | `ida_analysis_manage.kernel_ioctl` |
| `find_user_pointer_deref` | `ida_analysis_manage.user_pointer_deref` |
| `find_indirect_call_targets` | `ida_analysis_manage.indirect_calls` |
| `find_dispatch_tables` | `ida_analysis_manage.dispatch_tables` |
| `verify_status` | `ida_chain_manage.status` |
| `verify_taint_path` | `ida_chain_manage.verify_link` or `ida_analysis_manage.taint_trace` |
| `check_path_satisfiability` | `ida_analysis_manage.smt_query` |
| `solve_smt_query` | `ida_analysis_manage.smt_query` |
| `cancel_verification` | `ida_chain_manage.cancel` |
| `list_verified` | `ida_chain_manage.list` |
| `verify_ledger_persist` | `ida_chain_manage.get_report` |
| `patch`, `patch_bytes` | `ida_mutation_manage.patch_bytes` |
| `rename`, `rename_function` | `ida_mutation_manage.rename` |
| `set_function_signature` | `ida_mutation_manage.type_apply` |
| `idb_save` | `ida_mutation_manage.save_idb` |

### Aggregator Compatibility

The existing aggregator tools remain callable:

- `list_ida_instances`
- `get_local_instance_info`
- `query_all_instances`

They should also be represented as:

- `ida_discover_manage.instances`
- `ida_discover_manage.local_instance`
- `ida_discover_manage.route_check`

`query_all_instances` remains useful for cross-instance fan-out, but agents should prefer corpus-aware operations when possible.

## AI Usability Workflows

### Workflow 1: Discover And Bind A Multi-Binary Corpus

1. Call `ida_discover_manage.instances` to list live IDA databases.
2. Call `ida_project_manage.inventory_all` with `include_hashes=true`.
3. Call `ida_project_manage.corpus_create` with selected module IDs and roles.
4. Call `ida_project_manage.corpus_index_start` for `functions`, `imports`, `xrefs`, `types`, and `vuln_surface`.
5. Poll `ida_job_manage.status`.
6. Query `ida_extract_manage.functions` by module and role.

This replaces many one-off inventory, routing, and function-list calls with six deterministic MCP calls.

### Workflow 2: Verify A Vulnerability Chain

1. Call `ida_chain_manage.validate_spec` to normalize chain addresses and identify missing module bindings.
2. Call `ida_chain_manage.submit` with chain spec and budgets.
3. Poll `ida_job_manage.status` or subscribe to MCP progress.
4. Call `ida_chain_manage.get_report` with `include_evidence=true`.
5. Call `ida_chain_manage.navigate_evidence` for specific proof or counterevidence nodes.
6. Call `ida_chain_manage.export_report` for JSON, markdown, and SARIF when needed.

The workflow makes refutation evidence first-class, which is necessary for the NTFS, AFD, and `pvScan0` lessons.

### Workflow 3: Focused Trigger Trace

1. Call `ida_analysis_manage.trigger_trace` with entrypoint and target.
2. Poll `ida_job_manage.status`.
3. Call `ida_job_manage.result` for paginated candidate paths.
4. Promote one candidate into `ida_chain_manage.submit` as a chain link.

This lets an AI prove whether the trigger exists before spending time on deeper exploitability claims.

### Workflow 4: Boundary Match Before Chain Proof

1. Call `ida_analysis_manage.boundary_match` for producer and consumer.
2. Inspect `counterevidence[]`.
3. Submit a chain only if the boundary result is not refuted.

This prevents plausible but impossible chains from being over-verified.

### Workflow 5: Safe IDB Mutation

1. Call `ida_mutation_manage.preview` with proposed changes.
2. Review before/after and affected generation.
3. Call the specific mutation operation with `confirm_destructive=true` and `reason`.
4. Call `ida_cache_manage.status` to see invalidated derived data.

This keeps AI-authored IDB edits auditable and separated from read-only analysis.

## Exact Implementation Work Packages

### Package 1: Registry And Schema Upgrade

Files:

- `src/agent_tools.hpp`
- `src/agent_tools.cpp`
- `src/mcp_server.cpp`

Work:

- Add operation metadata support to `tool_definition_t`.
- Add `visibility`.
- Add manage-tool dispatch helper that extracts `operation`, accepts `action` as an alias, flattens optional `payload` only after schema validation, and returns `unknown_operation` on mismatch.
- Add common response envelope helpers.
- Add common error-code helpers.
- Extend `generate_tools_schema()` to emit operation metadata.
- Keep existing tool-level `read_only` and `destructive` for non-manage legacy wrappers.

Acceptance:

- Public schema contains operation metadata for every manage tool.
- Legacy tools can be hidden from default `tools/list`.
- `read_only && destructive` remains invalid at both tool and operation level.

### Package 2: Resource Catalog And Output Layer

Files:

- `src/mcp_server.cpp`
- new IDA plugin resource helper files under `src/` as needed

Work:

- Add module-aware resources.
- Add job-aware resources.
- Add chain evidence resources.
- Add cursor encoding and validation helpers.
- Add content-hash fields for resource outputs.
- Preserve existing resource URIs as compatibility endpoints.

Acceptance:

- Existing resources still resolve.
- New resources include schema, generation, hash, and instance/module identity.
- Large outputs are retrievable without overflowing inline MCP text.

### Package 3: Job Runtime

Files:

- new job runtime files under `src/`
- integration points in `src/mcp_server.cpp`
- chain and analysis tool integration files under `src/vuln/`

Work:

- Implement job state machine.
- Implement job IDs, idempotency keys, event ring, status, result pages, export resources, and prune policy.
- Implement cancellation tokens and cancellation checkpoints.
- Route long operations away from modal wait boxes.
- Capture database generation at job start and detect stale generation.

Acceptance:

- Long operations return a job handle quickly.
- Cancellation updates state predictably.
- Partial results are returned only when allowed.
- No MCP job path depends on `show_wait_box()`, `replace_wait_box()`, `hide_wait_box()`, or `user_cancelled()`.

### Package 4: `ida_discover_manage`

Files:

- `src/agent_tools.cpp`
- instance registry integration files

Work:

- Register discovery operations.
- Return operation docs, schemas, examples, resources, route checks, and health.
- Map existing aggregator data into discovery responses.

Acceptance:

- AI clients can discover every operation and schema from one tool.
- Route checks identify current, peer, stale, and unavailable instances.

### Package 5: `ida_project_manage`

Files:

- project/corpus model files under `src/`
- `src/agent_tools.cpp`

Work:

- Implement current and all-instance inventory operations.
- Implement corpus records, binding, unbinding, manifest export, and corpus index job creation.
- Use module ID plus RVA as stable address identity.

Acceptance:

- Multi-IDB corpus manifests are deterministic and exportable.
- Inventory includes hashes, segments, imports, exports, entry points, processor, bitness, and IDB path.

### Package 6: `ida_extract_manage`

Files:

- existing function, memory, type, xref, import/export, search, and decompiler tool implementations
- extraction helper files under `src/`

Work:

- Wrap existing extraction logic behind operation dispatch.
- Normalize address input to module ID plus RVA with current-IDB EA compatibility.
- Add pagination to all row outputs.
- Add decompiler and microcode job integration.
- Include generation and cache metadata in every result.

Acceptance:

- Function, instruction, xref, type, decompiler, and microcode extraction can be performed without legacy one-off tools.
- Large function lists, xrefs, and decompiler outputs are paginated or exported.

### Package 7: `ida_analysis_manage`

Files:

- `src/vuln/vuln_tools.cpp`
- `src/vuln/*engine*`
- `src/agent_tools.cpp`

Work:

- Consolidate callsite, sink, source, taint, CFG, kernel, microcode, attack surface, dispatch, callback, parser, boundary, trigger, value range, and SMT operations.
- Normalize evidence rows.
- Add job integration for expensive analysis.

Acceptance:

- Vulnerability-oriented analysis is accessible through one tool.
- Every finding has stable ID, address identity, confidence, evidence, assumptions, and counterevidence.

### Package 8: `ida_chain_manage`

Files:

- chain verification engine files under `src/vuln/`
- verification tool files
- ledger/cache helper files

Work:

- Implement chain spec validation.
- Implement submit/status/list/cancel/report/export/link/boundary/trigger/evidence/failure operations.
- Store chain ledgers and reports in plugin-owned persistence.
- Promote counterevidence to first-class report fields.
- Map existing verification one-off tools to chain operations.

Acceptance:

- Chain verification can be submitted, cancelled, inspected, refuted, and exported entirely over MCP.
- Reports are deterministic, machine-readable, and include proof and counterevidence.

### Package 9: `ida_cache_manage`

Files:

- cache/index helper files under `src/`
- extraction, analysis, and chain integrations

Work:

- Expose cache status, generations, warm, invalidate, clear, snapshot, and coverage.
- Keep plugin-owned cache mutation separate from IDB mutation.
- Tie cache invalidation to database generation and mutation receipts.

Acceptance:

- AI clients can inspect index readiness before expensive operations.
- Cache clearing cannot mutate user program database content.

### Package 10: `ida_mutation_manage`

Files:

- existing rename, patch, type, comment, make-code/data, undefine, and save tool implementations

Work:

- Consolidate IDB mutation behind explicit operations.
- Add preview and batch apply.
- Require confirmation and reason.
- Include before/after receipts and cache invalidation metadata.

Acceptance:

- No default public read tool mutates IDB state.
- All IDB mutation is auditable and routed through one destructive manage tool.

### Package 11: `ida_diagnostics_manage`

Files:

- MCP server diagnostics
- job runtime diagnostics
- registry diagnostics
- cache diagnostics

Work:

- Expose recent errors, performance counters, routing state, job diagnostics, resource cache state, modal-safety scan, self-test, export bundle, and license state summary.
- Ensure sensitive secret redaction while retaining operational evidence.

Acceptance:

- AI clients can diagnose routing, timeout, modal-safety, cache, and job problems without inspecting local files manually.
- Diagnostic bundles are exportable and content-hashed.

### Package 12: Legacy Wrapper Migration

Files:

- `src/agent_tools.cpp`
- existing tool registration files
- `src/vuln/vuln_tools.cpp`
- `src/vuln/verification_tools.cpp`

Work:

- Convert one-off public tools to wrappers.
- Mark wrappers `legacy`.
- Add `deprecated_by` metadata in wrapper results.
- Ensure wrappers use the same response envelope.
- Preserve existing aggregator tools.

Acceptance:

- Existing MCP clients continue working.
- New clients see the manage surface by default.
- `ida_discover_manage.capabilities(include_legacy=true)` returns the full migration map.

## Verification Plan

Static verification:

- Scan MCP manage paths for `show_wait_box`, `replace_wait_box`, `hide_wait_box`, `warning`, `info`, `ask_file`, `ask_yn`, and direct `user_cancelled` dependency.
- Scan public tool registration to verify only manage tools plus routing compatibility tools are public by default.
- Verify every manage tool has operation metadata, request schema, response schema, budget, cache policy, and error codes.
- Verify every destructive operation requires confirmation.
- Verify every long operation maps to job mode.

Behavioral verification:

- `ida_discover_manage.capabilities` returns the complete public surface and examples.
- `ida_project_manage.inventory_current` returns deterministic binary identity from IDA metadata.
- `ida_project_manage.inventory_all` routes across multiple live instances.
- `ida_extract_manage.functions` paginates and survives cursor reuse within the same generation.
- `ida_extract_manage.decompile` returns a job when over inline budget.
- `ida_analysis_manage.trigger_trace` can be cancelled.
- `ida_chain_manage.submit` returns a job, emits progress, supports cancellation, and exports a report.
- `ida_chain_manage.explain_failure` exposes counterevidence for refuted chains.
- `ida_job_manage.result` serves complete large outputs through resources.
- `ida_mutation_manage.patch_bytes` rejects missing confirmation and rejects stale `expected_old_bytes`.
- Legacy wrappers return compatible results and include deprecation metadata.

Case-study verification:

- NTFS to ETW style chain: report must be able to show controlled data becomes zeros and mark the chain refuted or partial.
- AFD UAF style chain: evidence navigation must expose the hidden `_setjmp` and `LIST_ENTRY` self-reference path that explains the real state transition.
- `pvScan0` style chain: report must be able to show the logical dataflow contradiction and prevent a plausible false positive from becoming `proven`.

Performance verification:

- Inline operations return under the inline budget or convert to jobs.
- Main-thread slices stay bounded.
- Multi-function extraction, decompiler extraction, microcode extraction, taint, SMT, chain verification, and exports do not freeze the IDA UI.
- Cancellation latency is measured and reported in job diagnostics.

Routing verification:

- `instance_id` routing targets the requested peer.
- `pid` routing targets the requested peer.
- Stale peer routes return `peer_unavailable` or `peer_timeout`.
- Every routed response echoes resolved instance identity.
- Corpus operations reject ambiguous raw EAs when module identity is required.

Build verification after implementation:

- The host AI runs the canonical AiDA build wrapper after code implementation.
- Subagents do not build.
- The final report includes build outcome, warning status, and any verification gaps.

## Acceptance Criteria

The implementation is complete when all criteria below are satisfied:

1. The default MCP public catalog exposes the manage tools in this plan plus existing routing compatibility tools.
2. Legacy one-off tools are callable but hidden from default discovery.
3. Every manage operation has strict request and response schemas.
4. Every response uses the common envelope.
5. Every operation exposes per-operation read-only, destructive, deterministic, job, cache, budget, and index metadata.
6. Long operations are jobs with status, events, cancellation, result retrieval, and export.
7. MCP paths do not show modal UI or wait boxes.
8. Binary, project, corpus, function, instruction, xref, type, decompiler, microcode, analysis, chain, job, cache, mutation, and diagnostics workflows are all available over MCP.
9. Vulnerability chain verification supports submission, status, cancellation, link verification, boundary matching, trigger tracing, evidence navigation, failure explanation, and deterministic export.
10. Multi-IDA routing works through `instance_id` and `pid` and all responses echo resolved identity.
11. All list-like operations support cursor pagination.
12. All large outputs are retrievable through resources or output handles.
13. Destructive operations require explicit confirmation and reason.
14. Compatibility wrappers map old tool names to manage operations and report `deprecated_by`.
15. Case-study verification proves positive evidence and counterevidence are both represented.
16. The host build and verification pass after implementation with zero new warnings.

