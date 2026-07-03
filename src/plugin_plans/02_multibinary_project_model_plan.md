# Multi-Binary Project Model Plan

## Implementation Subagent D Source Update

Status: **INCOMPLETE**. The plan remains open and must not be deleted.

Implemented source changes now present:

- Durable page roots were added for function pages, xrefs, signatures, dispatch tables, callbacks, globals, imports, exports, summaries, and cross-edge pages in `src/multibinary_project.cpp`.
- `src/multibinary_index.hpp` and `src/multibinary_index.cpp` now expose `index_page_status` and `index_page` read APIs. `build_current_module_index` writes per-family msgpack pages and manifests with resumable `aida_idx|family|module|page` cursors in addition to the bounded compatibility catalog.
- `src/multibinary_index.cpp` now captures bounded first-byte function signatures with `get_bytes`, captures non-flow code/data xrefs with `xrefblk_t`, derives fail-closed resolver evidence for guard dispatch imports, dispatch/IOCTL/callback naming candidates, and global pointer xrefs, and persists those as separate page families.
- `src/multibinary_index.cpp` now resolves imports through explicit module aliases and supplied API-set maps/contracts, emits unresolved `api_set_map_missing`/`api_set_hosts_not_loaded` gaps when no source-backed API-set host exists, emits syscall/service edges only from supplied `syscall_services` evidence, and emits fail-closed CFG/XFG guard, indirect call, global function pointer, driver dispatch, IOCTL dispatch, and callback-registration edges.
- `src/vuln/chain_verification_tools.hpp` now exposes `index_page_status` and `index_page` through `ida_project_manage`. `inventory_all` now records concrete `peer_data_missing` gaps from `list_ida_instances` when caller-supplied `query_all_instances` fanout results are absent, while still returning the safe fanout request for the MCP aggregator path.
- `src/vuln/chain_verifier.cpp` now evaluates supplied/persisted continuous trace evidence per link: unresolved trace edges, branch blockers, unresolved or indirect call targets, cross-module ABI-transfer proof, target module live-instance bindings, unknown register/memory state, unmodeled side effects, and poison side effects all block confirmation.
- `src/vuln/chain_verifier.cpp` now bundles NTFS/AFD/pvScan0 case-study fixture definitions and exposes them through `case_study_regressions` without synthetic passes; absent source evidence produces inconclusive fixture checks.

Remaining requirements not fully implemented:

1. Cross-instance fanout is not executed directly inside `ida_project_manage` because that handler runs under the normal IDA tool execution path and the local aggregator self-call can queue back to the main thread. Evidence: `src/vuln/chain_verification_tools.hpp` records `peer_data_missing` gaps and returns the safe `query_all_instances` request instead of pretending peer data exists.
2. Syscall/API-set/dispatch/callback/global/indirect resolution is implemented only when source-backed durable evidence is present or supplied in module records/pages; it intentionally fails closed for missing API-set maps, missing syscall tables, unproven dispatch assignments, and unproven guard/indirect targets. Full Windows build-specific service-table extraction is still not implemented.
3. Continuous verification now consumes trace evidence and blocks unknown CFG/register/memory/ABI state, but it does not yet route follow-up ABI state into remote target IDBs or synthesize new target-IDB traces through MCP. Evidence: cross-module calls without a live target binding or proven ABI transfer become `peer_data_missing`/`abi_transfer_unproven`.
4. Deep summaries are paged as bounded summary records derived from the function catalog, signatures, xrefs, and resolver evidence. Full lazy decompiler/microcode/SMT summary generation per page is still not implemented.
5. GraphRAG still serializes `binary_hash` for migration compatibility. New writes use corpus IDs and canonical RVAs, but old field names remain intentionally live so existing graphs can load without fabricated cross-module confidence. Evidence: `src/graphrag.hpp` and `src/graphrag.cpp` remain unchanged by this subagent.
6. Instance registry records themselves were not expanded with index generation, image base, or min/max EA. Durable module records and page manifests capture the relevant index fields instead. Evidence: `src/instance_registry.hpp` remains unchanged.
7. No build was run by this implementation subagent by instruction. Host verification must compile the new source and treat any compiler warning/error as open work.

## Objective

Design the IDA Pro side of AiDA's production-grade multi-binary vulnerability-chain verifier. This slice owns project identity, cross-IDB indexing, cross-module edge resolution, persistence, and the state model needed for continuous chain verification across drivers, ntoskrnl, win32k, user-mode DLLs, and other loaded or required binaries.

The verifier must reject the exact failure classes documented in `driver/PROGRESS.md`:

- Link-local proof cannot become a chain proof unless every boundary postcondition satisfies the next precondition.
- Trigger claims must be proven by tracing from the trigger entry to the claimed behavior.
- Hidden intermediate checks between a link entry and the claimed call site must become explicit path obligations.
- Logical data-flow contradictions must be caught, including self-referential pointer requirements such as `pvScan0 = &pvScan0`.
- Register state, memory state, branch direction, side effects, and call-target identity must remain continuous across function and module boundaries.

## Current-State Findings

AiDA already has strong single-IDB primitives:

- `src/instance_registry.hpp` and `src/instance_registry.cpp` maintain live IDA instance records with `instance_id`, PID, port, IDB path, input file, hashes, processor, bitness, and heartbeat state.
- `src/mcp_server.cpp` exposes `list_ida_instances`, `get_local_instance_info`, and `query_all_instances`, so multi-IDB discovery and fan-out already exist.
- `src/analysis_db.hpp` stores JSON-backed chat, analysis, and binary registry records under the IDA user directory. It is suitable for lightweight project references and per-binary capability summaries.
- `src/agent_tools.cpp` already exposes single-IDB read tools for binary info, segments, imports, exports, functions, xrefs, bytes, entry points, register traces, call argument loads, and batch queries.
- `src/vuln/taint_engine.*`, `src/vuln/cfg_engine.cpp`, `src/vuln/symbolic_engine.*`, and `src/vuln/verification_engine.*` provide local taint summaries, callgraph traversal, indirect-call resolution, path constraints, SMT checks, register tracking hooks, and per-IDB netnode-backed ledgers.
- `src/graphrag.*` already models nodes and edges keyed by `binary_hash`, but the existing graph is still module-local in address semantics and does not represent project-wide module identity or cross-binary state transfer.

The missing production slice is a durable project coordinator that normalizes all local EAs into `module_id + rva`, joins module-local indexes into a cross-module graph, resolves imports/exports/thunks/forwarders/callbacks/syscall edges, and verifies chain state as one continuous trace.

## SDK Evidence Snippets

Every IDA SDK API recommended in this plan is grounded in the local SDK headers under `ida-sdk/src/include`.

### Paths, Input Identity, and Image Base

Use `get_path(PATH_TYPE_IDB)` for IDB identity and `get_input_file_path` plus stored hashes for binary identity.

`ida-sdk/src/include/loader.hpp:1043`

```cpp
enum path_type_t
{
  PATH_TYPE_CMD,
  PATH_TYPE_IDB,
  PATH_TYPE_ID0,
};
idaman const char *ida_export get_path(path_type_t pt);
```

`ida-sdk/src/include/nalt.hpp:1380`

```cpp
inline ssize_t idaapi get_input_file_path(char *buf, size_t bufsize)
{
  return getinf_buf(INF_INPUT_FILE_PATH, buf, bufsize);
}
inline uint32 idaapi retrieve_input_file_crc32(void) { return uint32(getinf(INF_CRC32)); }
inline bool idaapi retrieve_input_file_md5(uchar hash[16]) { return getinf_buf(INF_MD5, hash, 16) == 16; }
inline bool idaapi retrieve_input_file_sha256(uchar hash[32]) { return getinf_buf(INF_SHA256, hash, 32) == 32; }
inline ea_t idaapi get_imagebase(void) { return getinf(INF_IMAGEBASE); }
```

Use IDB metadata for processor, bitness, PE kind, kernel-mode flag, and database bounds.

`ida-sdk/src/include/ida.hpp:631`

```cpp
inline bool inf_is_32bit_exactly(void) { return (getinf(INF_LFLAGS) & (LFLG_PC_FLAT|LFLG_64BIT)) == LFLG_PC_FLAT; }
inline bool inf_is_64bit(void) { return getinf_flag(INF_LFLAGS, LFLG_64BIT); }
inline bool inf_is_dll(void) { return getinf_flag(INF_LFLAGS, LFLG_IS_DLL); }
inline bool inf_is_kernel_mode(void) { return getinf_flag(INF_LFLAGS, LFLG_KERNMODE); }
inline uint inf_get_app_bitness(void)
```

`ida-sdk/src/include/ida.hpp:797`

```cpp
inline ea_t inf_get_min_ea() { return ea_t(getinf(INF_MIN_EA)); }
inline ea_t inf_get_max_ea() { return ea_t(getinf(INF_MAX_EA)); }
```

`ida-sdk/src/include/ida.hpp:1028`

```cpp
inline bool inf_get_procname(char *buf, size_t bufsize=IDAINFO_PROCNAME_SIZE)
inline qstring inf_get_procname()
```

Use `get_user_idadir` for external project files that must outlive one IDB.

`ida-sdk/src/include/diskio.hpp:87`

```cpp
idaman THREAD_SAFE const char *ida_export get_user_idadir(void);
```

### Segments and Address Normalization

Use segment APIs to validate EAs, capture permissions, and preserve segment-relative fallback identity when `EA - imagebase` is insufficient.

`ida-sdk/src/include/segment.hpp:68`

```cpp
class segment_t : public range_t
{
public:
  uval_t name = 0;
  uval_t sclass = 0;
  uval_t orgbase = 0;
```

`ida-sdk/src/include/segment.hpp:124`

```cpp
#define SEGPERM_EXEC  1
#define SEGPERM_WRITE 2
#define SEGPERM_READ  4
```

`ida-sdk/src/include/segment.hpp:642`

```cpp
idaman int ida_export get_segm_qty();
idaman segment_t *ida_export getseg(ea_t ea);
idaman segment_t *ida_export getnseg(int n);
idaman segment_t *ida_export get_next_seg(ea_t ea);
idaman segment_t *ida_export get_first_seg();
```

`ida-sdk/src/include/segment.hpp:1051`

```cpp
idaman ssize_t ida_export get_segm_name(qstring *buf, const segment_t *s, int flags=0);
```

Use byte APIs for signatures, pointer tables, and local value reads.

`ida-sdk/src/include/bytes.hpp:363`

```cpp
idaman bool ida_export is_loaded(ea_t ea);
idaman uint32 ida_export get_dword(ea_t ea);
idaman uint64 ida_export get_qword(ea_t ea);
```

`ida-sdk/src/include/bytes.hpp:720`

```cpp
idaman ssize_t ida_export get_bytes(
        void *buf,
        ssize_t size,
        ea_t ea,
        int gmb_flags=0,
        void *mask=nullptr);
```

### Functions, Thunks, and Function Items

Use function APIs for stable per-module function catalogs, thunk resolution, and instruction iteration.

`ida-sdk/src/include/funcs.hpp:84`

```cpp
class func_t : public range_t
{
public:
  uint64 flags;
#define FUNC_NORET      0x00000001
#define FUNC_LIB        0x00000004
#define FUNC_THUNK      0x00000080
```

`ida-sdk/src/include/funcs.hpp:293`

```cpp
idaman func_t *ida_export get_func(ea_t ea);
idaman func_t *ida_export getn_func(size_t n);
idaman size_t ida_export get_func_qty(void);
```

`ida-sdk/src/include/funcs.hpp:500`

```cpp
idaman ssize_t ida_export get_func_name(qstring *out, ea_t ea);
idaman ea_t ida_export calc_thunk_func_target(func_t *pfn, ea_t *fptr);
```

`ida-sdk/src/include/funcs.hpp:783`

```cpp
class func_item_iterator_t
{
public:
  func_item_iterator_t(func_t *pfn, ea_t _ea=BADADDR) { set(pfn, _ea); }
  bool first(void);
  ea_t current(void) const { return ea; }
  bool next_head(void) { return next(f_is_head, nullptr); }
```

### Imports, Exports, Names, Types, and Arguments

Use import enumeration to create unresolved external edges, then join those edges to loaded export catalogs.

`ida-sdk/src/include/nalt.hpp:1589`

```cpp
idaman uint ida_export get_import_module_qty();
idaman bool ida_export get_import_module_name(qstring *buf, int mod_index);
typedef int idaapi import_enum_cb_t(ea_t ea, const char *name, uval_t ord, void *param);
idaman int ida_export enum_import_names(int mod_index, import_enum_cb_t *callback, void *param=nullptr);
```

Use entry APIs for exports, ordinals, and forwarded exports.

`ida-sdk/src/include/entry.hpp:26`

```cpp
idaman size_t ida_export get_entry_qty(void);
idaman uval_t ida_export get_entry_ordinal(size_t idx);
idaman ea_t ida_export get_entry(uval_t ord);
idaman ssize_t ida_export get_entry_name(qstring *buf, uval_t ord);
idaman ssize_t ida_export get_entry_forwarder(qstring *buf, uval_t ord);
```

Use names and demangling for aliases, but never as the sole identity.

`ida-sdk/src/include/name.hpp:352`

```cpp
inline ssize_t get_name(qstring *out, ea_t ea, int gtn_flags=0)
{
  return get_ea_name(out, ea, gtn_flags);
}
```

`ida-sdk/src/include/name.hpp:734`

```cpp
idaman int32 ida_export demangle_name(
        qstring *out,
        const char *name,
        uint32 disable_mask,
        demreq_type_t demreq=DQT_FULL);
```

Use type and call-argument APIs to improve ABI transfer at call edges.

`ida-sdk/src/include/nalt.hpp:1317`

```cpp
idaman bool ida_export get_tinfo(tinfo_t *tif, ea_t ea);
```

`ida-sdk/src/include/typeinf.hpp:2763`

```cpp
idaman bool ida_export apply_callee_tinfo(ea_t caller, const tinfo_t &tif);
idaman bool ida_export get_arg_addrs(eavec_t *out, ea_t caller);
```

### Xrefs and Cross-Reference Edges

Use xrefs for local call/data edges and for callers of import slots, exports, globals, vtables, and dispatch tables.

`ida-sdk/src/include/xref.hpp:195`

```cpp
struct xrefblk_t
{
  ea_t from;
  ea_t to;
  bool iscode;
  uchar type;
#define XREF_NOFLOW     0x01
#define XREF_DATA       0x02
#define XREF_CODE       0x04
  bool first_from(ea_t _from, int flags=XREF_FLOW);
  bool next_from();
  bool first_to(ea_t _to, int flags=XREF_FLOW);
  bool next_to();
```

### Register Tracking

Use IDA's register tracker only as an evidence source for local snapshots; store the result in verifier state with explicit uncertainty when the tracker cannot prove a unique value.

`ida-sdk/src/include/regfinder.hpp:1599`

```cpp
idaman bool ida_export find_reg_value_info(
        reg_value_info_t *rvi,
        ea_t ea,
        int reg,
        int max_depth = 0);
```

### Persistence

Use netnodes for per-IDB module-local caches and external project files for cross-IDB state.

`ida-sdk/src/include/netnode.hpp:240`

```cpp
class netnode
{
public:
  netnode(const char *_name, size_t namlen=0, bool do_create=false)
  {
    netnode_check(this, _name, namlen, do_create);
  }
  void kill(void) { netnode_kill(this); }
```

`ida-sdk/src/include/netnode.hpp:926`

```cpp
size_t blobsize(nodeidx_t _start, uchar tag);
void *getblob(void *buf, size_t *bufsize, nodeidx_t _start, uchar tag);
bool setblob(const void *buf, size_t size, nodeidx_t _start, uchar tag);
int delblob(nodeidx_t _start, uchar tag);
```

### Nonblocking Scheduling, Cancellation, and Auto-Analysis Readiness

Use `execute_sync(MFF_READ)` for read-only IDB access from workers and never call IDA database APIs directly from arbitrary background threads.

`ida-sdk/src/include/kernwin.hpp:4435`

```cpp
#define MFF_READ   0x0001
#define MFF_WRITE  0x0002
#define MFF_NOWAIT 0x0004
struct exec_request_t
{
  virtual ssize_t idaapi execute() = 0;
};
```

`ida-sdk/src/include/kernwin.hpp:5086`

```cpp
THREAD_SAFE inline ssize_t execute_sync(exec_request_t &req, int reqf) { return callui(ui_execute_sync, &req, reqf).ssize; }
```

Use cancellation and balanced wait boxes for long work.

`ida-sdk/src/include/kernwin.hpp:6323`

```cpp
THREAD_SAFE inline bool user_cancelled() { return callui(ui_test_cancelled).cnd; }
```

`ida-sdk/src/include/kernwin.hpp:6993`

```cpp
Plugins must call hide_wait_box() to close the dialog box, otherwise
the user interface will remain disabled.
THREAD_SAFE AS_PRINTF(1, 2) inline void show_wait_box(const char *format, ...)
THREAD_SAFE inline void hide_wait_box()
```

Use IDA threads and semaphores for parallel read-only orchestration.

`ida-sdk/src/include/pro.h:5477`

```cpp
idaman THREAD_SAFE qthread_t ida_export qthread_create(qthread_cb_t *thread_cb, void *ud);
idaman THREAD_SAFE bool ida_export qthread_join(qthread_t q);
```

`ida-sdk/src/include/pro.h:5528`

```cpp
idaman THREAD_SAFE qsemaphore_t ida_export qsem_create(const char *name, int init_count);
idaman THREAD_SAFE bool ida_export qsem_free(qsemaphore_t sem);
idaman THREAD_SAFE bool ida_export qsem_post(qsemaphore_t sem);
idaman THREAD_SAFE bool ida_export qsem_wait(qsemaphore_t sem, int timeout_ms);
```

Gate index readiness on auto-analysis completion or explicit bounded waits.

`ida-sdk/src/include/auto.hpp:238`

```cpp
idaman bool ida_export auto_wait(void);
idaman ssize_t ida_export auto_wait_range(ea_t ea1, ea_t ea2);
idaman bool ida_export auto_is_ok(void);
```

## Data Model

### Canonical Address

`canonical_addr_t`

- `module_id`: stable identity of one exact binary version.
- `rva`: `ea - image_base` for image-backed addresses.
- `ea`: transient local IDB EA, valid only inside the current IDA instance.
- `segment_name`, `segment_start_rva`, `segment_offset`: fallback identity for packed, rebased, or synthetic segments.
- `kind`: `image_rva`, `segment_offset`, `import_slot`, `export_forwarder`, `synthetic`, `unknown`.

Rule: no project-wide edge may store a raw EA as the primary key. Raw EAs are display and routing hints only.

### Module Identity

`module_identity_t`

- `module_id`: `sha256:<hash>` when available, else `md5:<hash>`, else `basename/timestamp/size/exportset:<hash>`.
- `canonical_name`: lowercase basename without directory, preserving `.sys`, `.dll`, or `.exe`.
- `input_path`, `idb_path`, `input_basename`.
- `file_md5`, `file_sha256`, `file_crc32`.
- `image_base`, `min_ea`, `max_ea`, `size_estimate`.
- `processor`, `bitness`, `filetype`, `is_dll`, `is_kernel`.
- `pdb_guid_age` and `pdb_path` if later exposed by existing PDB code.
- `instance_bindings`: live IDA `instance_id`, PID, port, MCP URL, heartbeat timestamp, index generation.
- `segment_digest`: ordered segment names, start RVAs, sizes, permissions, and type.
- `exportset_digest`: stable hash of export names, ordinals, RVAs, and forwarders.
- `index_status`: `not_indexed`, `partial`, `ready`, `stale`, `missing`, `hash_conflict`, `analysis_incomplete`.

Module names are never trusted as unique. `afd.sys` loaded from two Windows builds becomes two module identities, not one.

### Function Identity

`function_identity_t`

- `function_id`: `module_id + start_rva + end_rva + code_signature_hash`.
- `module_id`, `start_rva`, `end_rva`, `chunk_ranges`.
- `name`, `visible_name`, `demangled_name`, `export_name`, `ordinal`.
- `flags`: thunk, library, noreturn, frame, static, hidden, fuzzy_sp.
- `thunk_target`: canonical target if IDA resolves it.
- `byte_signature`: first stable bytes with relocation/immediate mask.
- `prototype`: rendered type when available.
- `abi`: calling convention, argument locations, return location, volatile register set.
- `local_summary_ref`: key into module-local taint, CFG, symbolic, and verifier summaries.

Names are aliases. The verifier resolves chain entries by exact module plus RVA first, then export/ordinal, then name plus signature, then interactive ambiguity.

### Symbol and Import/Export Records

`symbol_identity_t`

- `symbol_id`: `module_id + namespace + name_or_ordinal`.
- `namespace`: `export`, `import`, `global`, `type`, `syscall`, `callback_slot`.
- `name`, `decorated_name`, `demangled_name`, `ordinal`.
- `rva`, `ea_hint`, `forwarder`, `import_module_name`, `import_slot_rva`.
- `resolution`: `resolved_function`, `resolved_data`, `forwarded`, `missing_module`, `missing_symbol`, `ordinal_only`, `ambiguous`.

Forwarded exports are represented as edges, not collapsed strings.

### Cross-Module Edge

`cross_module_edge_t`

- `edge_id`: deterministic hash of source, kind, target, and evidence.
- `kind`: `direct_call`, `import_call`, `export_resolution`, `forwarded_export`, `thunk`, `cfg_guard_dispatch`, `indirect_call`, `vtable_call`, `global_fptr`, `callback_registration`, `driver_dispatch`, `ioctl_dispatch`, `syscall_dispatch`, `event_trigger`, `data_reference`, `memory_object_transfer`.
- `source`: `module_id`, `function_id`, `site_rva`, `ea_hint`.
- `target`: resolved `function_id` or unresolved `symbol_identity_t`.
- `evidence`: xref type, import module/name/ordinal, export name/ordinal, thunk pointer, guard dispatch site, callback slot, syscall number/name, or manual chain assertion.
- `state_transfer`: ABI map from caller registers/stack/memory to callee entry state.
- `confidence`: `exact`, `strong`, `conditional`, `ambiguous`, `unresolved`.
- `required_modules`: modules that must be loaded before this edge can be proven.

### Continuous Trace State

`trace_state_t`

- `pc`: canonical address.
- `call_stack`: frames with module/function/callsite/return site.
- `registers`: symbolic values for x64 registers and flags, with width and provenance.
- `memory`: object graph keyed by symbolic object IDs, not raw addresses.
- `constraints`: branch predicates, alias predicates, value equalities, object bounds, and path assumptions.
- `side_effects`: reads, writes, interlocked ops, refcount changes, frees, allocations, bugchecks, fastfails, lock acquisitions, callbacks, and external calls.
- `obligations`: facts required but not yet proven, such as "conn+0x48 == &conn+0x48" or "ETW stop path reaches RemoveEntryList".
- `postconditions`: facts produced by the path.

Memory value lattice:

- `controlled(bytes, source)`: attacker-controlled content.
- `zero(bytes, source)`: zero fill or clear.
- `concrete(value)`: known constant.
- `symbolic(expr)`: SMT-backed value.
- `kernel_pointer(module_id, rva)` or `object_pointer(object_id, offset)`.
- `self_reference(object_id, offset)`.
- `unknown(reason)`.
- `poisoned(reason)`: state that makes the chain fail closed, such as fastfail or bugcheck.

This lattice is what catches "overflow exists, but content is zero" and "pvScan0 points to gpHandleManager, not to itself".

### Chain Specification

`chain_spec_t`

- `project_id`, `target_platform`, `os_build`, `architecture`.
- `modules`: required module names, hashes, or acceptable version constraints.
- `links`: ordered link definitions.
- `entry_state`: starting registers, memory objects, loaded modules, handles, runtime bases, and attacker-controlled inputs.
- `proof_policy`: max path depth, max call depth, SMT timeout, missing-module policy, ambiguity policy.

Each `chain_link_t`:

- `link_id`, `description`, `module_ref`, `entry_ref`, `target_behavior_ref`.
- `entry_preconditions`.
- `required_path`: optional exact branch/call sequence or a target behavior to search for.
- `claimed_behavior`: write/read/call/return/branch/trigger.
- `exit_postconditions`.
- `side_effect_allowlist`: side effects that are expected and harmless.

## Algorithms

### Project Discovery

1. Call the existing `list_ida_instances` aggregator.
2. For each live instance, request a read-only local fingerprint package:
   - binary info and fingerprint.
   - segments with permissions and RVAs.
   - entry/export table with forwarders.
   - import modules and symbols.
   - function catalog with names, flags, ranges, thunks, and signatures.
   - selected xref/callgraph pages.
3. Canonicalize each instance into `module_identity_t`.
4. Detect duplicate exact binaries and merge their instance bindings.
5. Detect name collisions with different hashes and keep separate module versions.
6. Mark modules referenced by imports, forwarders, callbacks, or chain specs but not loaded as `missing`.

### Module Indexing

Indexing runs in pages and stores results under the module identity:

1. Wait for auto-analysis readiness or mark the index `analysis_incomplete`.
2. Enumerate segments and build `ea <=> module+rva` maps.
3. Enumerate functions and create `function_identity_t`.
4. Enumerate exports and entry points, including ordinals and forwarders.
5. Enumerate imports and import slots.
6. Enumerate local xrefs from function heads and call sites.
7. Resolve local direct callees and thunks.
8. Collect local summaries from existing taint, CFG, symbolic, and verification engines lazily.
9. Persist module-local cache in an IDB netnode and project-wide cache files.

### Cross-Module Resolution

Resolver priority:

1. Exact loaded module by hash.
2. Exact canonical module name plus matching exportset or PDB identity.
3. Import module name to loaded module name, including API-set and forwarder mapping.
4. Export name or ordinal to target function/data.
5. Forwarded export recursively to the forwarded module and symbol.
6. Known Windows subsystem edge:
   - user-mode `ntdll!Nt*/Zw*` or `win32u!NtUser*/NtGdi*` wrapper to kernel syscall handler when syscall mapping is available for the OS build.
   - driver `DRIVER_OBJECT->MajorFunction[]` and IOCTL dispatch to handler functions.
   - callback registration edges for WDF, WSK, NDIS, FltMgr, DxgkDdi, ETW, ALPC, and object manager patterns when local analysis proves the assignment.
7. Chain-specified controlled indirect target when the trace state proves the register or memory slot value.
8. Unresolved edge with explicit reason.

Resolution never guesses silently. Ambiguity becomes a proof obligation.

### Cross-IDB Edge Transport

Raw IDA APIs operate in one current database. Cross-IDB work is coordinated by AiDA:

- Local extractors run inside each IDA instance via existing MCP tools and `execute_sync(MFF_READ)`.
- The project coordinator joins local JSON/msgpack summaries outside raw EA space.
- Follow-up local queries are routed back to the owning instance by `instance_id`.
- A trace transition from one module to another carries canonical state and asks the target instance to analyze the target function under that entry state.

### Continuous Chain Verification

1. Normalize chain input to canonical modules and functions.
2. Seed `trace_state_t` from the chain entry.
3. For each link, build a path corridor from entry to claimed behavior:
   - use local CFG and xrefs to find candidate paths.
   - include every branch, call, memory read/write, and side effect before the claimed behavior.
   - stop only at proven return, no-return, poison, timeout, or target behavior.
4. At every branch, evaluate the predicate under current state:
   - proven required direction: continue.
   - opposite direction: refute.
   - unknown direction: create an obligation and mark the link inconclusive unless the chain supplies a satisfiable constraint.
5. At every call:
   - direct same-module call: inline or apply a proven summary.
   - import/export/thunk/forwarder call: resolve to target module and continue with ABI state transfer.
   - indirect call: use current symbolic state, IDA local evidence, CFG guard metadata, and chain-controlled values to prove the target.
6. At every memory write:
   - record address expression, width, content lattice, provenance, and object alias.
   - update affected memory objects.
   - flag collateral writes not listed by the chain.
7. At every memory read:
   - require the read object to be initialized, mapped, and compatible with the needed content.
8. At link exit, compare produced postconditions with the next link preconditions.
9. Emit full-chain verdict:
   - `confirmed`: all edges resolved, all branches proven, all state transfers compatible, no unallowed poison side effects.
   - `refuted`: a proven contradiction exists.
   - `inconclusive`: missing module, unsupported API, unresolved indirect call, SMT timeout, or insufficient chain input.
   - `timeout`: bounded work exceeded while preserving partial evidence.

### Case-Study Coverage

NTFS compression overflow to ETW:

- The memory write model records `memmove` output as controlled and `memset` output as zero.
- The adjacent ETW LIST_ENTRY precondition requires controlled Flink/Blink.
- Boundary unification refutes `zero != controlled`.
- Trigger tracing from ETW session stop must resolve to RemoveEntryList or refute the trigger.

AFD UAF to `_setjmp`:

- The path from `AfdCloseConnection` entry to the indirect call includes the LIST_ENTRY empty-list check.
- The false branch requires `conn+0x48 == &conn+0x48` and `conn+0x50 == &conn+0x48`.
- If the chain cannot prove the kernel address of `conn`, the link is inconclusive or refuted by missing precondition.
- If the Timer2 LFH discovery link proves `conn_addr`, the self-reference requirement becomes satisfiable.

pvScan0:

- The bitmap write semantics are modeled as writing to `[pvScan0]`.
- To update `pvScan0`, the state must prove `pvScan0 == &pvScan0`.
- `pvScan0 = gpHandleManager` produces a write to `[gpHandleManager]`, leaving `pvScan0` unchanged, so the next precondition `pvScan0 == target` is refuted.

## Persistence Format

### Project Root

Location:

`<get_user_idadir()>/aida_projects/<project_id>/`

Files:

- `project.json`: human-readable manifest and module list.
- `modules/<module_id>.json`: module identity, segment summaries, import/export catalogs.
- `functions/<module_id>.msgpack`: function catalog and local call edges.
- `edges/cross_edges.msgpack`: resolved and unresolved cross-module edges.
- `chains/<chain_id>.json`: chain specs and latest verdict summary.
- `traces/<chain_id>/<run_id>.msgpack`: detailed trace evidence.
- `locks/project.lock`: single-writer guard with PID and timestamp.

### IDB Netnodes

Per-IDB caches:

- `$ AiDA.multibinary.module`: module identity and index generation for the current IDB.
- `$ AiDA.multibinary.functions`: paged function catalog for current IDB.
- `$ AiDA.multibinary.edges`: paged local edge cache for current IDB.

Netnodes are not the source of truth for cross-IDB project state. They are accelerators for the owning IDB.

### Schema Versioning

All persisted documents include:

- `schema`: fixed string, such as `aida.multibinary.project`.
- `version`: integer.
- `created_at_ms`, `updated_at_ms`.
- `producer`: AiDA version.
- `sdk_context`: IDA version, processor, bitness.
- `signature_db_rev`: vulnerability signature database revision.
- `module_index_generation`: monotonically increasing per module.

On version mismatch, the loader keeps the manifest, discards incompatible derived caches, and schedules reindexing.

## Performance and Stability Plan

IDA stability rules:

- All IDA database reads run through `execute_sync(MFF_READ)`.
- Mutating operations are not required for this slice.
- Background threads may coordinate, parse JSON/msgpack, solve constraints, and join project data, but must not directly call IDA database APIs.
- Every long operation checks `user_cancelled`.
- Wait boxes use RAII so `hide_wait_box` is called exactly once per `show_wait_box`.
- Cross-instance fan-out is capped, cancellable, and returns partial results with per-instance errors.

Indexing strategy:

- Page all catalogs by offset and limit.
- Build a minimal identity index first, then imports/exports, then functions, then xrefs, then deep summaries.
- Defer decompilation, microcode, SMT, and byte signatures until a chain or query needs them.
- Cache exact module fingerprints and invalidate only when input hashes, IDB path, segment digest, function count, or signature database revision changes.
- Bound per-module indexing by time and memory budgets; store `partial` status with the last completed page.

Trace strategy:

- Build path corridors rather than whole-program inlining.
- Use summaries at function boundaries and inline only when summaries are missing or state-sensitive.
- Use cross-module edge confidence to prune impossible targets early.
- Enforce max path depth, max call depth, max indirect targets, max side-effect records, and SMT timeouts.
- Keep all partial evidence, including first unproven branch and first unresolved edge.

Target budgets:

- Listing live modules: under 2 seconds for 20 open IDA instances.
- Minimal module index: under 30 seconds for a large kernel driver after auto-analysis.
- Full import/export/function/xref index for ntoskrnl-sized IDB: bounded, cancellable, resumable, and never blocks UI message handling.
- Chain verification: first useful evidence within 5 seconds, final bounded verdict or partial verdict within the configured timeout.

## Failure Modes and Required Behavior

- Missing binary: create a missing module record and mark dependent edges unresolved.
- Unloaded but required binary: verdict is inconclusive unless the chain policy explicitly allows assumed summaries.
- Same basename, different hash: keep both modules and require exact version selection.
- Same export name in multiple versions: ambiguous until module identity is selected.
- Import by ordinal only: resolve by ordinal if exact module is loaded; otherwise unresolved.
- Forwarded export target missing: edge is unresolved with forwarder string evidence.
- Image base mismatch: recompute RVAs from the indexed image base; runtime base is separate chain state.
- EA outside loaded segment: reject the address normalization.
- IDA auto-analysis incomplete: index status is partial; verification cannot confirm affected paths.
- Hex-Rays unavailable: fall back to disassembly, xrefs, register tracker, and microcode-independent summaries; mark high-level path facts unsupported when needed.
- Register tracker unsupported or non-unique: state value becomes unknown with cited API evidence.
- Indirect call target unresolved: no chain confirmation unless state proves the target.
- CFG/XFG guard present: unwrap only when target register or memory slot is proven at guard dispatch entry.
- Syscall mapping missing for OS build: unresolved syscall edge.
- SMT timeout: preserve constraints and return timeout/inconclusive instead of blocking IDA.
- Side effect not modeled: emit an obligation and prevent confirmed verdict.
- Poison side effect, fastfail, bugcheck, or no-return before target behavior: refute unless the chain target is that terminal effect.
- Stale peer instance: remove live binding but keep persisted module identity.
- Project file lock held by dead process: recover only after PID liveness and timestamp checks.
- Corrupt project cache: discard derived cache, keep manifest, and reindex.

## Files Likely Affected in Implementation

- `src/analysis_db.hpp`: add project manifest references and richer module registry metadata while preserving current JSON compatibility.
- `src/instance_registry.hpp` and `src/instance_registry.cpp`: optionally add image base, min/max EA, and index generation to live instance records.
- `src/agent_tools.cpp`: add read-only tools for module project fingerprint, paged function export, paged local edge export, project create/list/load, index current module, index all live modules, resolve cross edges, and verify chain spec.
- `src/mcp_server.cpp`: expose project resources and route project operations through existing instance targeting and fan-out.
- `src/graphrag.hpp` and `src/graphrag.cpp`: add project-wide node/edge kinds keyed by module identity instead of only `binary_hash`.
- `src/vuln/cfg_engine.cpp`: expose structured local edge summaries and indirect-call evidence in canonical-address form.
- `src/vuln/taint_engine.*`: export summaries using `module_id+rva` and accept imported summaries for cross-module reachability.
- `src/vuln/symbolic_engine.*`: add serialization for entry/exit symbolic state summaries.
- `src/vuln/verification_engine.*`: add chain-level state unification, link-pair postcondition/precondition checks, and cross-module verdict ledger records.
- New `src/multibinary_project.hpp` and `src/multibinary_project.cpp`: project manifest, persistence, locking, module registry, canonical address conversion.
- New `src/multibinary_index.hpp` and `src/multibinary_index.cpp`: local extraction schema, index pages, digest computation, resolver inputs.
- New `src/vuln/chain_verifier.hpp` and `src/vuln/chain_verifier.cpp`: continuous trace state, chain spec parser, state transfer, verdict generation.

## Acceptance Criteria

Project model:

- Opening `afd.sys`, `ntoskrnl.exe`, `win32kbase.sys`, `win32kfull.sys`, `ntdll.dll`, and `win32u.dll` in separate IDA instances produces one project with exact module identities, hashes, IDB paths, image bases, segments, imports, exports, functions, and live instance bindings.
- Every function and edge stored in the project uses `module_id+rva` as primary identity.
- Closing and reopening IDA preserves the project manifest and reloads module caches without raw EA drift.
- Same-name different-version modules are represented distinctly and never merged by basename alone.

Cross-module resolution:

- Driver imports from `ntoskrnl.exe` resolve to the exact loaded ntoskrnl module by name or ordinal.
- Forwarded exports create explicit forwarder edges and resolve recursively when the forwarded target module is loaded.
- Import thunks, local thunks, CFG guard dispatch, and global function-pointer calls are represented as distinct edge kinds with evidence.
- Missing modules and missing symbols are visible in the project graph and block confirmed verdicts.

Chain verification:

- The NTFS-to-ETW case is refuted because the overflow postcondition is zero-filled content and does not satisfy controlled LIST_ENTRY preconditions; the unproven RemoveEntryList trigger is separately reported.
- The AFD-to-`_setjmp` case without Timer2 address discovery is not confirmed because the LIST_ENTRY self-reference precondition is not proven before the indirect call.
- The AFD-to-`_setjmp` case with Timer2 LFH address discovery can satisfy the LIST_ENTRY precondition and continue to the call target check.
- The `pvScan0 = gpHandleManager` design is refuted because `SetBitmapBits` writes to `[gpHandleManager]` and does not update `pvScan0`.
- The `pvScan0 = buffer3_va + 0x900` self-reference design satisfies the pointer-update precondition if the fake object layout is otherwise proven.
- A confirmed verdict requires all branch directions, call targets, register transfers, memory contents, side effects, and link boundaries to be proven.

Stability and performance:

- All project and index tools are read-only unless explicitly saving project files.
- IDA remains responsive during large module indexing and chain verification.
- Cancellation returns partial evidence and releases all waits and locks.
- Timeouts produce deterministic partial verdicts with the first blocking edge or condition.
- No crash in IDA when a peer disappears, a project cache is corrupt, Hex-Rays is unavailable, or auto-analysis is incomplete.

## Verification Plan

Static review:

- Confirm every IDA database API call in new implementation occurs inside `execute_sync` or an existing main-thread tool handler.
- Confirm every project-wide address is `module_id+rva` and raw EAs are marked as local hints.
- Confirm every cross-module edge has evidence and an explicit confidence/resolution state.
- Confirm no confirmed verdict path can contain an unresolved edge, unknown branch direction, incompatible pre/post boundary, unallowed side effect, or poison terminal event.

Unit tests with pure data fixtures:

- Module identity collision tests for same basename/different hash.
- RVA conversion tests for rebased modules and synthetic segments.
- Import/export/forwarder resolver tests, including missing module and ordinal-only cases.
- State lattice tests for controlled, zero, concrete, symbolic, self-reference, and unknown values.
- Postcondition/precondition unification tests for the three documented case-study failures.

IDA integration tests:

- Index one small user-mode DLL and verify imports, exports, functions, segments, xrefs, and persistence.
- Index one driver plus ntoskrnl and resolve driver imports.
- Run `query_all_instances` based project discovery across multiple live IDAs and verify stale peer removal.
- Save, close, reopen, and reload the project without identity drift.

Case-study regression tests:

- Build chain specs for NTFS-to-ETW, AFD-to-`_setjmp` without Timer2, AFD-to-`_setjmp` with Timer2, and both pvScan0 designs.
- Verify each emits the acceptance-criteria verdict and cites the exact first failure marker.

Stress and failure tests:

- Index ntoskrnl-sized and win32k-sized IDBs with cancellation at multiple phases.
- Inject corrupt project files and verify recovery by discarding derived caches.
- Kill a peer IDA during fan-out and verify partial results.
- Force SMT timeout and verify partial constraints are persisted.
- Run chain verification while auto-analysis is incomplete and verify no confirmed verdict is emitted for affected paths.

Host verification after implementation:

- Run the canonical AiDA build from the repository root.
- Run targeted IDA plugin smoke tests for startup, instance discovery, project save/load, index current module, index all live modules, and chain verification.
- Verify zero build errors, zero new warnings, no IDA UI freeze, no unbalanced wait box, and no stale project lock.
