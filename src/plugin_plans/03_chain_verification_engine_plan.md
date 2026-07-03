# AiDA IDA Pro Chain Verification Engine Plan

## Objective

Design a production-grade core engine that verifies a vulnerability chain as one continuous execution trace across every involved binary, instead of verifying isolated links. The engine must prove or refute whether the exact state produced by link N satisfies the exact state required by link N+1, while also discovering hidden intermediate checks, branch requirements, indirect-call target mismatches, trigger gaps, and collateral side effects.

This plan covers the core chain-verification engine, its IR/state model, algorithms, schemas, IDA integration points, performance strategy, acceptance criteria, and verification plan. It does not implement code.

## Required Progress Context

`driver/PROGRESS.md` defines the key failure pattern in the critical section at lines 2229-2516:

- Per-link verification answered local questions such as whether `_setjmp` writes `RBX` to `[RCX+8]`, whether `AfdCloseConnection` reads `conn+0x10`, whether an NTFS compression overflow goes past a buffer, and whether an ETW structure has a `LIST_ENTRY`.
- Complete chain verification must trace "from user-mode entry through every function call across every binary", resolving branches, data state, side effects, call boundaries, and indirect calls.
- The three concrete failures were all boundary failures:
  - NTFS compression overflow produced zeros, not controlled bytes, and the claimed ETW stop trigger never reached a list unlink.
  - AFD UAF to `_setjmp` missed a hidden `LIST_ENTRY` self-reference check before the indirect call.
  - The fake bitmap chain set `pvScan0` to the wrong value; the pointer write targeted `gpHandleManager`, not the `pvScan0` slot itself.

The engine must own every instruction between a claimed trigger and the claimed behavior. No assumption is verified unless it is represented as a state fact, branch fact, trigger proof, or postcondition/precondition match in the final report.

## Current-State Findings

AiDA already has several strong single-binary analysis components that should be reused:

- `src/aida.cpp:895-917` initializes tool registration, starts MCP, and installs Hex-Rays fixups during operational plugin startup:

```cpp
895:    aida_ipc::trace_breadcrumb("initialize_operational_tools_init_begin");
896:    agent_tools::initialize_all_tools();
897:    aida_ipc::trace_breadcrumb("initialize_operational_tools_init_done");
904:    aida_ipc::trace_breadcrumb("initialize_operational_mcp_start_begin port=%d", g_settings.mcp_port);
905:    if (!start_mcp_server())
913:    aida_ipc::trace_breadcrumb("initialize_operational_hexrays_fixups_begin");
914:    analysis_fixer::install_hexrays_fixups();
```

- `src/agent_tools.cpp:12528-12543` is the current canonical registration path for plugin tools:

```cpp
12528:    memory_tools::register_tools();
12539:    graphrag_tools::register_tools();
12540:    vuln_tools::register_tools();
12541:    vuln_tools::register_advanced_tools();
12542:    aida::vuln::verify::tools::register_verification_tools();
12543:    aida_ida_batch_tools::register_tools();
```

- `src/agent_tools.cpp:11684-11701` already exposes index warming with explicit engine names and cancellation expectations. The chain engine should add `chain_verification_engine` to this surface.

```cpp
11686:    def.name = OBFSTR("build_index");
11689:        "Warm one or more engine indices (graphrag, taint_engine, microcode_engine, cfg_engine, "
11690:        "kernel_engine, surface_engine, symbolic_engine, smt_solver, or 'all'). Per-engine timing "
11691:        "and partial flags are reported. Cooperatively cancellable via user_cancelled().");
11697:    def.read_only = false;     // engines may populate caches
```

- `src/vuln/verification_engine.hpp` exposes SMT-backed single source-to-sink checks, exploit input solving, loop bound proofs, alias proofs, arithmetic simplification, and netnode-backed verdict persistence.
- `src/vuln/verification_engine.cpp:639-677` shows the current verification scope is one enclosing function for the sink. It calls `get_func(sink_ea)`, loads that one function symbolically, and collects path constraints to one target EA:

```cpp
639:    func_t* pfn = get_func(sink_ea);
648:    cache_key_t key{pfn->start_ea, sink_ea, source_ea, sig::SIGNATURE_DATABASE_REVISION};
664:    if (!m_impl->sym.load_function(pfn->start_ea))
677:    out.constraints = m_impl->sym.collect_path_to(sink_ea, 64);
```

- `src/vuln/microcode_engine.hpp` and `src/vuln/microcode_engine.cpp:750-770` already wrap Hex-Rays microcode generation using `init_hexrays_plugin`, `get_func`, and `gen_microcode`.
- `src/vuln/microcode_engine.cpp:969-1038` already resolves direct and some thunked call targets from microcode and extracts call arguments.
- `src/vuln/cfg_engine.cpp` already contains same-IDB CFG/callgraph and indirect-call helpers: `find_indirect_calls`, `resolve_indirect_calls_batched`, `find_bypass_paths`, `reachable_under_constraints`, switch dispatch enumeration, and postdominator checks.
- `src/instance_registry.hpp` and `src/mcp_server.cpp` already provide multi-instance IDA discovery and remote tool routing. Each IDA instance publishes `instance_id`, PID, input path, hashes, bitness, and port. `src/mcp_server.cpp:271-275` documents that every tool accepts `instance_id` or `pid`, which is the right substrate for cross-binary verification when each binary is open in a separate IDB.

Current gap:

- No existing engine maintains one continuous symbolic/concrete state across multiple functions, multiple binaries, and multiple chain links.
- No existing engine compares link postconditions to the next link's preconditions as typed facts.
- No existing engine proves a claimed trigger path by tracing from the trigger entry to the claimed behavior.
- No existing engine records every intermediate check, memory write, call, exception path, fastfail, and side effect as a first-class chain report item.
- No existing engine proves that an indirect call target follows from the current state rather than only from local heuristic resolution.
- No existing engine models logical pointer-write intent, such as distinguishing "write to `[pvScan0]`" from "write to the `pvScan0` field itself".

## IDA SDK API Basis

Every IDA and decompiler API recommendation in this plan is grounded in `ida-sdk/src/include`.

### Plugin Lifetime

Use the existing `PLUGIN_MULTI` pattern already present in AiDA and keep chain engine state per IDB instance. The SDK states:

`ida-sdk/src/include/loader.hpp:578-610`

```cpp
580:  int version;                  ///< Should be equal to #IDP_INTERFACE_VERSION
581:  int flags;                    ///< \ref PLUGIN_
601:#define PLUGIN_FIX  0x0080      ///< Load plugin when IDA starts and keep it in the memory until IDA stops
602:#define PLUGIN_MULTI    0x0100  ///< The plugin can work with multiple idbs in parallel.
603:                                ///< init() returns a pointer to a plugmod_t object
610:  plugmod_t *(idaapi *init)(void);  ///< Initialize plugin - returns a pointer to plugmod_t
```

Recommendation: keep the chain engine owned by the existing `aida_plugin_t`/tool registry lifecycle; do not introduce a singleton that assumes one global IDB.

### Binary Identity

Use IDA's input-file path, hashes, and image base to bind a chain module record to the correct IDB and reject stale caches.

`ida-sdk/src/include/nalt.hpp:1379-1408`

```cpp
1379:/// Get full path of the input file
1380:inline ssize_t idaapi get_input_file_path(char *buf, size_t bufsize)
1381:{
1382:  return getinf_buf(INF_INPUT_FILE_PATH, buf, bufsize);
1383:}
1395:/// Get input file md5
1396:inline bool idaapi retrieve_input_file_md5(uchar hash[16]) { return getinf_buf(INF_MD5, hash, 16) == 16; }
1398:/// Get input file sha256
1399:inline bool idaapi retrieve_input_file_sha256(uchar hash[32]) { return getinf_buf(INF_SHA256, hash, 32) == 32; }
1407:/// Get image base address
1408:inline ea_t idaapi get_imagebase(void) { return getinf(INF_IMAGEBASE); }
```

Recommendation: key every module summary by `{input_sha256, imagebase, processor, bitness, database_change_count, signature_db_rev}` and by the chain schema's module ID.

### Function Discovery

Use `get_func`, `getn_func`, and `get_func_qty` to build function indexes and to validate every chain entry, target, and intermediate address.

`ida-sdk/src/include/funcs.hpp:293-327`

```cpp
293:idaman func_t *ida_export get_func(ea_t ea);
305:inline bool func_contains(func_t *pfn, ea_t ea)
307:  return get_func_chunknum(pfn, ea) >= 0;
317:/// Get pointer to function structure by number.
322:idaman func_t *ida_export getn_func(size_t n);
325:/// Get total number of functions in the program
327:idaman size_t ida_export get_func_qty(void);
```

Recommendation: all supplied EAs/RVAs must normalize to a `func_t` before microcode generation; unmatched addresses produce `unsupported` rather than guessed function boundaries.

### Names and Symbols

Use `get_ea_name`/`get_name` to resolve human-readable targets and produce stable reports.

`ida-sdk/src/include/name.hpp:329-354`

```cpp
329:        qstring *out,
330:        ea_t ea,
331:        int gtn_flags=0,
332:        getname_info_t *gtni=nullptr);
337:#define GN_VISIBLE   0x0001 ///< replace forbidden characters by SUBSTCHAR
339:#define GN_DEMANGLED 0x0004 ///< return demangled name
350:// Convenience functions for get_ea_name returning ssize_t
352:inline ssize_t get_name(qstring *out, ea_t ea, int gtn_flags=0)
354:  return get_ea_name(out, ea, gtn_flags);
```

Recommendation: report every cited EA with module, RVA, function name, and raw EA; never rely on names alone for matching.

### Segments and Module Ownership

Use segment APIs to determine code/data ownership, reject addresses outside loaded ranges, and distinguish image globals from stack/heap symbolic regions.

`ida-sdk/src/include/segment.hpp:645-684`

```cpp
645:/// Get pointer to segment by linear address.
649:idaman segment_t *ida_export getseg(ea_t ea);
652:/// Get pointer to segment by its number.
658:idaman segment_t *ida_export getnseg(int n);
673:/// Get pointer to the first segment
674:idaman segment_t *ida_export get_first_seg();
679:/// Get pointer to segment by its name.
684:idaman segment_t *ida_export get_segm_by_name(const char *name);
```

Recommendation: the chain engine should classify every concrete address as image code, image data, import slot, unknown kernel object, stack, user buffer, sprayed allocation, or unresolved before it is consumed by a branch or call.

### Bytes and Concrete Reads

Use IDB bytes for concrete global slots, import descriptors, jump tables, and vtable-like targets.

`ida-sdk/src/include/bytes.hpp:361-419,721-725`

```cpp
363:idaman bool ida_export is_loaded(ea_t ea);
405:idaman uint32 ida_export get_dword(ea_t ea);
412:idaman uint64 ida_export get_qword(ea_t ea);
419:idaman uint64 ida_export get_wide_byte(ea_t ea);
721:        void *buf,
722:        ssize_t size,
723:        ea_t ea,
724:        int gmb_flags=0,
725:        void *mask=nullptr);
```

Recommendation: every concrete memory read must record whether the IDB byte was loaded; unloaded bytes become symbolic or unknown, never silently zero.

### Xrefs

Use `xrefblk_t` for call/data relationship indexes, trigger path discovery, imports/exports, callback owner discovery, and report evidence.

`ida-sdk/src/include/xref.hpp:170-242`

```cpp
170:/// Structure to enumerate all xrefs.
175:///      xrefblk_t xb;
176:///      for ( bool ok=xb.first_from(ea, XREF_FLOW); ok; ok=xb.next_from() )
178:///         // xb.to - contains the referenced address
183:///      xrefblk_t xb;
184:///      for ( bool ok=xb.first_to(ea, XREF_FLOW); ok; ok=xb.next_to() )
186:///         // xb.from - contains the referencing address
195:struct xrefblk_t
197:  ea_t from;            ///< the referencing address - filled by first_to(),next_to()
198:  ea_t to;              ///< the referenced address - filled by first_from(), next_from()
228:  /// Get first xref from the given address (store in #to)
229:  bool first_from(ea_t _from, int flags=XREF_FLOW)
237:  bool first_to(ea_t _to, int flags=XREF_FLOW)
241:  bool next_to()
```

Recommendation: trigger confirmation must start from actual xrefs/callers/dispatch entries where available, then prove reachability with CFG and state constraints.

### Hex-Rays Availability and Ctree

Use `init_hexrays_plugin` before all decompiler operations. Use ctree for readable fallback and source-expression citation, not as the authoritative state IR.

`ida-sdk/src/include/hexrays.hpp:9187-9190`

```cpp
9187:inline bool init_hexrays_plugin(int flags=0)
9189:  hexdsp_t *dummy;
9190:  return callui(ui_broadcast, HEXRAYS_API_MAGIC, &dummy, flags).i == (HEXRAYS_API_MAGIC >> 32);
```

`ida-sdk/src/include/hexrays.hpp:7718-7738`

```cpp
7718:cfuncptr_t hexapi decompile(
7724:/// Decompile a function.
7725:/// Multiple decompilations of the same function return the same object.
7732:inline cfuncptr_t decompile_func(
7733:        func_t *pfn,
7737:  mba_ranges_t mbr(pfn);
7738:  return decompile(mbr, hf, decomp_flags);
```

`ida-sdk/src/include/hexrays.hpp:7021-7074`

```cpp
7022:  int cv_flags;           ///< \ref CV_
7026:#define CV_FAST    0x0000 ///< do not maintain parent information
7028:#define CV_PARENTS 0x0002 ///< maintain parent information
7048:  /// This function may be called by a visitor() to skip all children of the current item.
7065:  ctree_visitor_t(int _flags) : cv_flags(_flags) {}
7068:  /// Traverse ctree.
7074:  int hexapi apply_to(citem_t *item, citem_t *parent);
```

Recommendation: ctree visitors should support user-readable branch/call expressions and type recovery, but microcode remains the authoritative execution IR because it exposes SSA-like use/def, branch operations, low-level memory writes, and call operands.

### Hex-Rays Microcode

Use `gen_microcode` for the authoritative per-function IR.

`ida-sdk/src/include/hexrays.hpp:7767-7772`

```cpp
7767:mba_t *hexapi gen_microcode(
7768:        const mba_ranges_t &mbr,
7769:        hexrays_failure_t *hf=nullptr,
7770:        const mlist_t *retlist=nullptr,
7771:        int decomp_flags=0,
7772:        mba_maturity_t reqmat=MMAT_GLBOPT3);
```

Use `mba_t` basic blocks and visitors to enumerate all instructions and operands.

`ida-sdk/src/include/hexrays.hpp:5290-5351`

```cpp
5290:  /// Get basic block by its serial number.
5291:  const mblock_t *get_mblock(uint n) const { QASSERT(52719, n < qty); return natural[n]; }
5342:  /// Visit all operands of all instructions.
5345:  int hexapi for_all_ops(mop_visitor_t &mv);
5347:  /// Visit all instructions.
5351:  int hexapi for_all_insns(minsn_visitor_t &mv);
```

Recommendation: build Chain IR from microcode at `MMAT_GLBOPT3` for optimized semantics, and optionally compare with `MMAT_LVARS` for stable local variable names and report readability.

### Type Information

Use `tinfo_t`, `parse_decl`, `get_named_type`, and `guess_tinfo` to decode prototypes, structures, fields, and argument conventions. Keep the chain engine read-only by default; use `apply_tinfo` only in a separate explicit annotation action.

`ida-sdk/src/include/typeinf.hpp:2160-2165`

```cpp
2160:idaman bool ida_export parse_decl(
2161:        tinfo_t *out_tif,
2162:        qstring *out_name,
2163:        til_t *til,
2164:        const char *decl,
2165:        int pt_flags);
```

`ida-sdk/src/include/typeinf.hpp:2724-2735`

```cpp
2724:idaman bool ida_export apply_tinfo(
2725:        ea_t ea,
2726:        const tinfo_t &tif,
2727:        uint32 flags);
2732:#define TINFO_GUESSED    0x0000 ///< this is a guessed type
2733:#define TINFO_DEFINITE   0x0001 ///< this is a definite type
2734:#define TINFO_DELAYFUNC  0x0002 ///< if type is a function and no function exists at ea,
```

`ida-sdk/src/include/typeinf.hpp:2803-2806,3212-3218`

```cpp
2803:idaman int ida_export guess_tinfo(tinfo_t *out, tid_t id);
3212:        const til_t *til,
3213:        const char *name,
3214:        type_t decl_type=BTF_TYPEDEF,
3218:  inline bool get_named_type(const char *name, type_t decl_type=BTF_TYPEDEF, bool resolve=true, bool try_ordinal=true) { return get_named_type(nullptr, name, decl_type, resolve, try_ordinal); }
```

Recommendation: pre/postcondition schemas should support named struct fields, but the normalized engine form must be offset/width based. Types are evidence helpers, not trust anchors.

### Netnode Cache

Use netnodes for persistent per-IDB summaries and chain verdict ledgers.

`ida-sdk/src/include/netnode.hpp:251-293,822-839`

```cpp
251:  /// Constructor to create a netnode to access information about the
253:  netnode(nodeidx_t num=BADNODE) { netnodenumber = num; }
258:  /// Construct an instance of netnode class to access the specified netnode.
265:  netnode(const char *_name, size_t namlen=0, bool do_create=false)
285:  /// Create a named netnode.
293:  bool create(const char *_name, size_t namlen=0)
822:  /// Get value of the specified hash element.
827:  nodeidx_t hashval_long(const char *idx, uchar tag=htag) const
830:  /// Set value of hash element.
838:  bool hashset(const char *idx, const void *value, size_t length=0, uchar tag=htag)
```

Recommendation: use content-addressed summary records and page large JSON/msgpack blobs as the current verification ledger already does.

### Thread Safety, UI, and Cancellation

Use `execute_sync` for IDA API access from worker contexts, `user_cancelled` for cooperative cancellation, wait boxes for long runs, and `msg` for concise operator-visible diagnostics.

`ida-sdk/src/include/kernwin.hpp:5086,6323,7019-7030,7241-7245`

```cpp
5086:THREAD_SAFE inline ssize_t execute_sync(exec_request_t &req, int reqf) { return callui(ui_execute_sync, &req, reqf).ssize; }
6323:THREAD_SAFE inline bool user_cancelled() { return callui(ui_test_cancelled).cnd; }
7019:/// Hide the "Please wait dialog box"
7021:THREAD_SAFE inline void hide_wait_box()
7028:/// Replace the label of "Please wait dialog box"
7030:THREAD_SAFE AS_PRINTF(1, 2) inline void replace_wait_box(const char *format, ...)
7241:THREAD_SAFE AS_PRINTF(1, 2) inline int msg(const char *format, ...)
```

Recommendation: IDA database reads and Hex-Rays generation run on the safe IDA thread boundary; pure SMT, JSON comparison, and state matching run on worker threads with cancellation checks.

## Formal Chain Input Schema

The engine accepts `chain_document_v1`, encoded as JSON. All addresses support either `{module_id, rva}` or `{instance_id, ea}`. The normalized internal representation must always store module ID, image hash, image base, RVA, raw EA in that IDB, and function start.

```json
{
  "schema": "aida.chain_document.v1",
  "chain_id": "afd_setjmp_gp_handle_manager_bitmap_rw",
  "description": "Human-readable summary",
  "modules": [
    {
      "id": "afd",
      "name": "afd.sys",
      "instance_id": "optional-live-ida-instance-id",
      "sha256": "optional-required-file-sha256",
      "image_base": "0x1c0000000",
      "bitness": 64,
      "role": "kernel_driver"
    }
  ],
  "symbols": [
    {
      "id": "AfdCloseConnection",
      "module_id": "afd",
      "name": "AfdCloseConnection",
      "rva": "0x373d1",
      "kind": "function"
    }
  ],
  "state_declarations": [
    {
      "id": "conn",
      "kind": "kernel_object",
      "address": {"symbolic": "conn_va"},
      "size": 272,
      "lifetime": "spray_reclaimed_lfh_slot",
      "address_known_at": "after_timer2_discovery"
    },
    {
      "id": "gpHandleManager",
      "kind": "image_global",
      "module_id": "win32kbase",
      "rva": "0x..."
    }
  ],
  "links": [
    {
      "id": "link_afd_close_to_setjmp",
      "module_id": "afd",
      "entry": {"symbol": "AfdCloseConnection"},
      "trigger": {
        "kind": "call_path",
        "source": {"symbol": "AfdCloseCore"},
        "must_reach": {"symbol": "AfdCloseConnection"}
      },
      "target_behavior": {
        "kind": "indirect_call",
        "callsite": {"module_id": "afd", "rva": "0x..."},
        "expected_target": {"module_id": "ntoskrnl", "symbol": "_setjmp"}
      },
      "preconditions": [
        {
          "id": "conn_list_empty",
          "expr": "mem64(conn + 0x48) == conn + 0x48 && mem64(conn + 0x50) == conn + 0x48",
          "required_by": "AfdCloseConnection.list_empty_check"
        }
      ],
      "postconditions": [
        {
          "id": "setjmp_store",
          "expr": "mem64(rcx + 8) == rbx",
          "after": "expected_target_return"
        }
      ],
      "expected_side_effects": [
        {
          "kind": "write",
          "target": "gpHandleManager",
          "width": 8,
          "controlledness": "controlled"
        }
      ],
      "collateral_tolerance": {
        "allow_unread_global_writes_before_goal": true,
        "allowed_ranges": []
      }
    }
  ],
  "goal": {
    "kind": "arbitrary_kernel_rw",
    "success_conditions": [
      "read_primitive(target_addr, len) returns mem[target_addr:target_addr+len]",
      "write_primitive(target_addr, bytes) writes bytes to mem[target_addr]"
    ]
  },
  "budgets": {
    "max_functions": 4096,
    "max_inlined_depth": 8,
    "max_paths_per_link": 64,
    "max_solver_ms_per_query": 5000,
    "max_total_ms": 120000
  }
}
```

### Input Fact Model

Every condition must normalize into typed facts:

- `value_fact`: equality, inequality, range, bitmask, arithmetic, controlledness, initializedness.
- `address_fact`: concrete address, symbolic address, module RVA, field path, address-known phase.
- `memory_fact`: `mem(width, region, offset) = value`, with read/write provenance.
- `alias_fact`: must-alias, may-alias, no-alias, self-reference, points-to set.
- `branch_fact`: branch EA, required direction, predicate expression.
- `call_fact`: caller/callee/callsite, argument mapping, expected return, expected clobbers.
- `trigger_fact`: event entry must reach behavior under the current state.
- `lifetime_fact`: object allocation/free/reclaim order, address discovery phase, use-after-free window.
- `collateral_policy`: writes/calls that are acceptable, fatal, or unknown until proven safe.

### Output Schema

The engine returns `chain_verification_report_v1`:

```json
{
  "schema": "aida.chain_verification_report.v1",
  "chain_id": "afd_setjmp_gp_handle_manager_bitmap_rw",
  "verdict": "confirmed|refuted|inconclusive|timeout|unsupported",
  "confidence": "confirmed|likely|plausible|speculative",
  "reason": "short final explanation",
  "module_bindings": [],
  "trace": {
    "functions": [],
    "edges": [],
    "branches": [],
    "calls": [],
    "returns": [],
    "indirect_calls": []
  },
  "link_results": [],
  "boundary_results": [],
  "trigger_results": [],
  "side_effects": [],
  "collateral_damage": [],
  "assumption_gaps": [],
  "logical_contradictions": [],
  "solver": {
    "queries": [],
    "total_solve_ms": 0,
    "timeouts": 0
  },
  "witness": {
    "available": false,
    "model": [],
    "concrete_bytes": []
  },
  "citations": [
    {
      "module_id": "afd",
      "function": "AfdCloseConnection",
      "rva": "0x...",
      "ea": "0x...",
      "kind": "branch|write|call|read|return"
    }
  ]
}
```

## Data Structures: Chain IR and State Model

### Module IR

`chain_module_t`:

- `module_id`, input path, basename, MD5/SHA256, image base, bitness, processor.
- `instance_id` and MCP route when the module is hosted by another live IDA.
- Segment map: code, data, rdata, import slots, export table, unloaded ranges.
- Function index: RVA to function, name to functions, import/export/thunk map.
- Type environment: named structs, function prototypes, field offset aliases.

### Function IR

`chain_function_ir_t`:

- Function identity: module, start RVA, raw EA, name, hash of microcode dump.
- Basic blocks from `mba_t`, with entry/exit block IDs.
- Micro-instructions normalized into `chain_op_t`:
  - `assign`, `load`, `store`, `branch`, `call`, `return`, `phi`, `helper`, `fastfail`, `exception`, `barrier`.
- Operand model:
  - Register, stack slot, global, memory dereference, immediate, helper return, lvar, unknown.
- Def-use edges and memory use/def lists.
- Callsite records:
  - Direct target, indirect target expression, argument expressions, return destination, calling convention.
- Branch records:
  - Predicate expression, true/false successors, branch EA, source text.
- Side-effect inventory:
  - All writes, all calls, all potential exception/fastfail paths, all helper operations that mutate state.

### Value Lattice

`chain_value_t`:

- `unknown`: no useful facts.
- `unmodeled`: value comes from an instruction/helper not modeled precisely.
- `concrete`: exact integer/bytes.
- `symbolic`: SMT expression plus provenance.
- `interval`: min/max range.
- `bitmask`: known-one and known-zero masks.
- `points_to`: set of regions/field paths with may/must classification.
- `aggregate`: struct/object with known fields.
- `poison`: invalid, freed, uninitialized, or impossible state.

Every value carries:

- width in bits.
- signedness when relevant.
- endianness.
- controlledness: attacker-controlled, derived-controlled, zero, constant, kernel-derived, unknown.
- provenance: link ID, instruction EA, source fact, concrete read, call summary, solver model.
- confidence: exact, overapprox, underapprox, heuristic.

### Register State

`register_state_t` tracks:

- All x64 GPRs: `RAX`, `RBX`, `RCX`, `RDX`, `RSI`, `RDI`, `RSP`, `RBP`, `R8` through `R15`.
- Flags used by branches: `ZF`, `CF`, `SF`, `OF`, `PF`, plus a combined predicate expression when microcode hides flag materialization.
- SIMD/vector registers as opaque symbolic values unless a function writes scalar memory through them.
- Volatile/nonvolatile classification under Windows x64 ABI.
- Per-call argument mapping: `RCX`, `RDX`, `R8`, `R9`, stack arguments, shadow space.
- Return mapping: `RAX` and any out parameters proven by memory writes.

Call handling must preserve nonvolatile registers unless the callee summary proves a write, clobber volatile registers unless the callee is inlined or summarized precisely, and always carry explicit evidence for assumptions about `RBX`, `RDI`, `RSI`, `R12` through `R15`.

### Stack State

`stack_state_t` tracks:

- Symbolic `RSP` base and delta.
- Return addresses.
- Shadow space and stack arguments.
- Local stack slots from decompiler frame/lvar metadata.
- Saved nonvolatile registers.
- Caller/callee frame transitions.
- Unknown writes through stack pointers.

The engine must detect when a link relies on a register value after an intervening call without a preservation proof.

### Memory State

`memory_state_t` tracks regions:

- `image_code(module)`.
- `image_data(module)`.
- `import_slot(module)`.
- `stack(thread/frame)`.
- `user_buffer(id)`.
- `kernel_object(id,type,size)`.
- `pool_allocation(id,tag,bucket,size,lifetime)`.
- `spray_slot(id,bucket,size,address_known_phase)`.
- `global_symbol(module,rva)`.
- `unknown_kernel`.
- `unknown_user`.

Each write produces a `memory_event_t`:

- write EA and function.
- address expression.
- resolved region/field path.
- width.
- value expression.
- controlledness and provenance.
- overwrite classification: expected, collateral, fatal, unknown.

Memory aliases are represented as `alias_class_t`:

- must-alias group.
- may-alias edges.
- no-alias facts.
- self-reference facts such as `mem64(surface+0x50) == surface+0x50`.
- address-knowledge phase facts such as `conn_va known before spray fill`.

### Path State

`path_state_t` is immutable per search node and contains:

- Current module/function/block/instruction.
- Register, stack, and memory states.
- Active constraints in SMT form.
- Branch decisions.
- Call stack.
- Link phase.
- Satisfied preconditions and produced postconditions.
- Side-effect ledger.
- Confidence ledger.
- Resource counters.

State joins are only allowed at explicitly compatible control-flow merge points. If two incoming states disagree on a value that matters to a later precondition, the engine preserves a disjunction instead of discarding the conflict.

## Engine Phases

### Phase 1: Chain Import and Normalization

1. Validate schema version and required fields.
2. Resolve modules to live IDA instances using `instance_id`, SHA256, basename, and image base.
3. Normalize every address to `{module_id, image_sha256, image_base, rva, ea, function_start}`.
4. Normalize named symbols to EAs using function/name indexes.
5. Convert all preconditions/postconditions into typed facts.
6. Reject ambiguous module/symbol bindings unless the chain explicitly permits a target set.

### Phase 2: Module Indexing

For each module:

1. Enumerate functions, segments, names, xrefs, imports, exports, thunks, and switch/dispatch structures.
2. Build a local callgraph using direct calls plus existing indirect-call candidates.
3. Cache function metadata keyed by binary hash and database change count.
4. Export a compact `module_summary_t` for cross-instance use.

### Phase 3: Microcode Lifting

For each demanded function:

1. Call `init_hexrays_plugin`.
2. Generate microcode at `MMAT_GLBOPT3`.
3. Convert `mba_t` blocks and `minsn_t` instructions into Chain IR.
4. Attach ctree text snippets for report readability.
5. Extract all calls, branches, memory reads/writes, helper operations, and potential fastfail/exception exits.
6. Build local def-use and memory-use indexes.

### Phase 4: Link Entry State Seeding

1. Start with declared initial facts.
2. Apply all preceding postconditions for the current link.
3. Materialize trigger-specific facts, such as UAF object lifetime or allocation reuse.
4. Check whether required preconditions are currently satisfied, unknown, or contradicted.
5. Refute immediately on a hard contradiction.

### Phase 5: Trigger Path Confirmation

For a link claiming "event X triggers behavior Y":

1. Resolve event entry functions and dispatch/callback sites.
2. Trace actual call paths from X to Y.
3. For every candidate path, symbolically execute branch and call transitions with the current state.
4. Confirm Y only if at least one complete path reaches Y under satisfiable constraints.
5. If no path reaches Y, report `trigger_never_reaches_behavior`.
6. If reachability depends on a missing state fact, report `trigger_unproven` with the exact missing fact.

### Phase 6: Continuous Path Search

Path search is not per-link matching. It traces every basic block from the current entry until the link behavior and its exit postconditions are reached:

1. Use a worklist over `path_state_t`.
2. Interpret each micro-instruction with transfer functions.
3. At each branch:
   - Build the predicate expression.
   - Evaluate under current concrete facts.
   - Ask SMT for satisfiability when symbolic.
   - Record required direction and whether the chain schema declared it.
4. At each call:
   - Resolve target.
   - Inline if within budget and relevant to the link goal.
   - Use a precise summary if known.
   - Use an opaque ABI summary only for irrelevant calls with no relevant memory alias.
5. At each memory write:
   - Resolve alias and region.
   - Update memory state.
   - Add side-effect record.
6. At each fastfail/bugcheck/exception path:
   - Mark path fatal unless the chain explicitly models and catches that path.
7. Stop only when the link's target behavior and exit state are proven, refuted, or all budgets expire.

### Phase 7: Cross-Binary Call and Return Handling

Direct cross-binary calls:

1. Resolve import/export/thunk/name/RVA target.
2. Bind target module by chain module map.
3. Request or build the callee summary from the owning IDA instance.
4. Map caller state into callee ABI arguments.
5. Trace/invoke summary.
6. Map return state and side effects back to caller module.

Indirect cross-binary calls:

1. Evaluate the call target expression from current state.
2. If concrete, map to module/RVA and validate executable segment ownership.
3. If points-to set, enumerate all feasible targets and require the chain's expected target to be the only feasible target unless the schema permits alternatives.
4. If unresolved but controlled, prove the controlled value equals the expected target under current constraints.
5. If routed through guard dispatch, model guard dispatch as a target-preserving call gate only if the dispatch input target is proven.
6. Report `indirect_target_unproven` when the target is guessed from a local heuristic but not implied by the state.

Returns:

1. Restore caller frame and return address.
2. Apply ABI return and clobber rules.
3. Apply callee memory side effects.
4. Check preserved-register claims.
5. Continue the caller trace through all intermediate return-path code, including cleanup functions and completion routines.

### Phase 8: Boundary Matching

For each adjacent link pair:

1. Convert link N postconditions into normalized facts.
2. Convert link N+1 preconditions into normalized facts.
3. Compare value equality, controlledness, address knowledge, lifetime, alias class, initialization, and width.
4. Classify each requirement:
   - `satisfied_exact`.
   - `satisfied_by_alias`.
   - `satisfied_by_constraint`.
   - `unproven`.
   - `contradicted`.
5. Refute on hard contradictions, such as zeros where controlled pointers are required.
6. Emit a boundary matrix showing the producer EA/fact and consumer precondition for every match.

### Phase 9: Logical Goal Verification

After all links are locally feasible, the engine verifies the actual final exploit goal as logical data flow:

1. Define the primitive semantics, such as read/write through `pvScan0`.
2. Simulate the sequence of operations the chain claims will provide the primitive.
3. Verify that pointer writes update the intended pointer field, not merely the target pointed to by that field.
4. Verify read/write target redirection after each operation.
5. Verify that collateral writes before the first successful primitive do not destroy required objects or call paths.

This phase exists specifically to catch mechanical-but-wrong chains like `pvScan0 = gpHandleManager`.

### Phase 10: Report and Ledger

1. Emit a complete JSON report.
2. Emit a concise text summary for MCP.
3. Persist deterministic function summaries and chain verdicts in netnodes.
4. Include all cited EAs and module hashes.
5. Include every assumption gap; do not hide gaps behind a positive confidence label.

## Algorithms

### Microcode Transfer Functions

Every `chain_op_t` implements:

- `uses()`: registers/memory/flags read.
- `defs()`: registers/memory/flags written.
- `transfer(path_state_t) -> path_state_t set`.
- `side_effects()`.
- `smt_expr()`, when symbolic.

Core operations:

- Arithmetic: preserve bit width, overflow flags, signedness annotations.
- Load: resolve address; read concrete memory if image-loaded; otherwise read symbolic memory region.
- Store: resolve address; update alias classes and side effects.
- Compare/branch: create predicate and branch event.
- Call: call resolver plus ABI mapper.
- Return: ABI return mapper and stack/frame restoration.
- Helper: model known helpers precisely; unknown mutating helpers become `unmodeled` and reduce confidence.

### Alias Analysis

The alias engine combines:

- Concrete equality.
- Module/RVA identity.
- Region disjointness.
- Field-path identity, such as `conn+0x48`.
- Points-to sets.
- SMT equality/inequality checks.
- Self-reference facts.
- Lifetime/address-known facts.

Alias verdicts:

- `must_alias`: required for exact field updates.
- `may_alias`: possible collateral; preserve both possibilities or mark inconclusive if relevant.
- `no_alias`: safe disjointness.
- `unresolved`: engine could not prove enough.

Self-reference is a first-class predicate:

```text
self_ref(region.field) := mem64(address(region.field)) == address(region.field)
```

The engine must distinguish:

```text
mem64(surface + 0x50) == gpHandleManager
```

from:

```text
mem64(surface + 0x50) == surface + 0x50
```

### Branch Satisfiability

For each branch:

1. Build normalized predicate.
2. Substitute known concrete facts.
3. Query SMT for required direction.
4. Query SMT for opposite direction when needed to classify whether the branch is forced or merely feasible.
5. Record:
   - `forced_taken`.
   - `forced_not_taken`.
   - `both_possible`.
   - `unsat_required`.
   - `unknown_timeout`.

A chain branch is confirmed only if the required direction is satisfiable and every missing assumption needed to choose it is represented.

### Function Summaries

A function summary contains:

- Preconditions over arguments, globals, memory regions, and alias facts.
- Postconditions over return value, out parameters, globals, and memory regions.
- Clobber set.
- Reads/writes/calls.
- Branch obligations.
- Fatal exits.
- Relevant heap/object lifetime effects.
- Confidence and coverage.

Summary types:

- `precise`: built by inlining and proving all relevant paths.
- `path_specific`: valid only under a caller path predicate.
- `opaque_safe`: no relevant side effects or aliases.
- `opaque_mutating`: side effects unknown; confidence drops or path becomes inconclusive.
- `external_declared`: user-provided function contract, marked as assumption unless independently verified.

### Indirect Call Resolution

Resolution sources are ranked:

1. Current-state concrete target.
2. Current-state symbolic target proven equal to expected target.
3. Points-to set with a single feasible executable target.
4. Guard dispatch input target proven by state.
5. Type/xref/vtable/microcode heuristic from existing `cfg_engine`.

Only levels 1-4 can confirm an exploit chain. Level 5 can guide search but cannot alone prove a chain.

### Side-Effect and Collateral Analysis

Every side effect is classified:

- `expected`: declared and matched.
- `benign`: proven not to alias future required state and not on return/trigger path.
- `collateral_survivable`: aliases noncritical state and no later read/call depends on it before the goal.
- `collateral_unproven`: no proof of safety.
- `fatal`: reaches fastfail, bugcheck, invalid dereference, required object destruction, or corrupts a later required field.

Collateral safety is a data-flow proof, not a name-based allowlist.

### Confidence Rules

Use AiDA's existing confidence vocabulary:

- `confirmed`: every required path is reached, every branch predicate is SAT in the required direction, every indirect target is state-proven, every boundary precondition is satisfied, every relevant side effect is classified, and the final logical goal is proven.
- `likely`: all critical facts are proven, but at least one irrelevant helper/library call is modeled by an opaque-safe summary.
- `plausible`: a path exists, but noncritical aliases or summaries remain overapproximated.
- `speculative`: useful evidence exists, but one or more chain-critical facts are missing.

A `refuted` verdict overrides confidence when any critical contradiction exists.

## Handling the Three PROGRESS.md Failure Modes

### Case 1: NTFS Compression Overflow to ETW LIST_ENTRY

Required checks:

1. Trace the actual fallback path through the NTFS compression write code.
2. Model both `memmove` and `memset` side effects with source/content provenance.
3. Produce a postcondition for the overflow content:
   - `memmove`: user-controlled bytes, bounded by original size.
   - `memset`: zero bytes, length based on final compressed size.
4. Compare the produced postcondition to the ETW `LIST_ENTRY` precondition requiring controlled `Flink` and `Blink`.
5. Refute with `postcondition_precondition_mismatch` when zeros reach the ETW fields.
6. Independently trace the ETW stop/flush/cleanup trigger path.
7. Refute with `trigger_never_reaches_behavior` if no `RemoveEntryList` or equivalent unlink write is reached.

Expected report finding:

```text
Link N produces: mem[EtwL+344:EtwL+360] = zero_bytes from memset at ntfs.sys RVA ...
Link N+1 requires: controlled pointer values at EtwL+344 and EtwL+352
Boundary verdict: refuted
Trigger verdict: refuted, ETW stop path does not reach RemoveEntryList
```

### Case 2: AFD UAF to _setjmp LIST_ENTRY Self-Reference

Required checks:

1. Trace from the UAF-triggered `AfdCloseConnection` entry, not only from the indirect-call site.
2. Enumerate all branches between entry and the indirect call.
3. Detect the `LIST_ENTRY` empty-list check before the call.
4. Normalize its precondition:
   - `mem64(conn+0x48) == conn+0x48`.
   - `mem64(conn+0x50) == conn+0x48`.
5. Check whether `conn` address is known at spray-fill time.
6. If not known, report `address_knowledge_gap` and mark the branch to the indirect call unproven/refuted depending on schema requirements.
7. If the chain includes the Timer2/WaitCompletionPacket address-discovery link, verify that the discovered address postcondition precedes spray data construction.
8. Re-run the branch proof with the self-reference facts and confirm the path reaches the indirect call only after those facts are satisfied.

Expected report finding before the address-discovery fix:

```text
Hidden intermediate check at AfdCloseConnection RVA ...
Required fact: self_ref(conn+0x48)
Producer: none before spray fill
Verdict: refuted or inconclusive by policy, because reaching _setjmp is not proven
```

Expected report finding after the fix:

```text
Producer: address_discovery_link yields conn_va before spray fill
Boundary: conn_va satisfies self_ref(conn+0x48)
Indirect call target: state-proven target equals _setjmp
```

### Case 3: pvScan0 Self-Referencing Logic

Required checks:

1. Model bitmap operation semantics as memory effects:
   - `SetBitmapBits(h, 8, &target)` writes `target` to `mem64(pvScan0_value)`.
   - `GetBitmapBits(h, len, out)` reads from `mem(pvScan0_value, len)`.
2. Model the fake handle table as an alias from bitmap handle to fake `SURFACE`.
3. Model the `SURFACE+0x50` field as the `pvScan0` slot.
4. Verify the logical goal "change pvScan0 to target".
5. Compute write destination:
   - If `pvScan0_value == gpHandleManager`, then write destination is `gpHandleManager`.
   - The `SURFACE+0x50` slot is unchanged.
6. Refute with `logical_dataflow_contradiction`.
7. Confirm only when `pvScan0_value == address(SURFACE+0x50)`.

Expected report finding for the bad layout:

```text
Operation: SetBitmapBits writes to mem64(mem64(surface+0x50))
State: mem64(surface+0x50) = gpHandleManager
Actual write destination: gpHandleManager
Required updated slot: surface+0x50
Verdict: refuted
```

Expected report finding for the corrected layout:

```text
State: mem64(surface+0x50) = surface+0x50
SetBitmapBits destination: surface+0x50
Postcondition: mem64(surface+0x50) = target_addr
Verdict: confirmed for pointer redirection
```

## Performance and Stability Strategy

### Tiered Execution

1. `schema_only`: validate module bindings, symbol resolution, and required facts.
2. `index_only`: build module and function summaries.
3. `path_skeleton`: callgraph/CFG reachability without deep SMT.
4. `state_trace`: execute microcode transfer functions with bounded symbolic state.
5. `solver_deep`: solve branch, alias, indirect-target, and boundary constraints.
6. `goal_deep`: run final logical primitive verification.

The MCP tool should expose the tier and final phase reached, matching the existing `triage_sink` style.

### Caching

Cache units:

- Module summary by binary hash and database change count.
- Function IR by function RVA and microcode maturity.
- Function summary by function IR hash and summary policy.
- Indirect-call candidates by callsite.
- SMT query result by normalized formula hash.
- Chain report by chain document hash plus module binding hashes.

Invalidation:

- IDB database change count changes.
- Input SHA256 changes.
- Signature DB revision changes.
- Chain schema hash changes.
- User-provided type/schema version changes.

### Search Bounds

Default budgets:

- Functions per chain: 4096.
- Inlining depth: 8.
- Paths per link: 64.
- Branch constraints per path: 256.
- Loop unroll: 2 unless loop summary proves a bound.
- Solver query: 5000 ms default, 60000 ms max for explicit deep runs.
- Total verification: 120000 ms default.

Loops:

- Use widening when loop-carried state does not affect any pending precondition/goal.
- Use loop-bound proof when the loop controls a write or index relevant to the chain.
- Mark relevant unbounded loops as inconclusive, not confirmed.

### IDA Stability

- All IDA SDK reads and Hex-Rays generation happen under a safe IDA thread boundary.
- Pure state matching and SMT solving run outside IDA's UI-critical path.
- Every long phase checks cancellation.
- Wait boxes are paired and updated; MCP responses include phase progress.
- Decompiler failures produce `unsupported` for the affected function and do not crash the plugin.
- The engine is read-only by default; it does not patch, rename, type-apply, or comment unless a separate explicit annotation command is added later.

### Multi-Instance Stability

- The orchestrating IDA instance binds modules by `instance_id` and SHA256.
- Remote summaries are requested through existing MCP routing.
- Remote result payloads include module hash and image base so the orchestrator can reject stale or wrong-instance results.
- If a required module is not open in any live IDA instance, the report returns `unsupported_missing_module` with the exact module ID.
- Remote timeouts degrade only the affected module/link and preserve partial evidence.

## Files Likely Affected by Implementation

New core files:

- `src/vuln/chain_ir.hpp`
- `src/vuln/chain_state.hpp`
- `src/vuln/chain_schema.hpp`
- `src/vuln/chain_report.hpp`
- `src/vuln/chain_verification_engine.hpp`
- `src/vuln/chain_verification_engine.cpp`
- `src/vuln/chain_verification_tools.cpp`
- `src/vuln/chain_verification_tools.hpp`

Existing integration points:

- `src/vuln/microcode_engine.hpp` and `.cpp`: reuse generation, dump, call target, call argument, and use/def helpers. Extend only if a reusable helper is genuinely missing.
- `src/vuln/symbolic_engine.hpp` and `.cpp`: reuse expression/SMT conversion where compatible; avoid forcing it to become the multi-function state engine if that would distort current single-function behavior.
- `src/vuln/smt_solver.hpp` and `.cpp`: reuse context pool, timeouts, model extraction, and SMT-LIB handling.
- `src/vuln/cfg_engine.cpp`: reuse indirect-call candidate discovery, switch dispatch enumeration, postdominator logic, and callgraph scaffolding.
- `src/vuln/verification_engine.hpp` and `.cpp`: keep existing APIs stable; optionally add an adapter so chain results can reuse verdict/confidence serialization.
- `src/vuln/verification_tools.cpp`: either register chain tools beside existing `vuln_verify` tools or delegate to new `chain_verification_tools.cpp`.
- `src/vuln/vuln_tools.cpp` and `.hpp`: add advanced registration only if chain tools belong in `vuln_advanced`; preferred category is `vuln_chain_verify`.
- `src/agent_tools.cpp`: register chain tools from `initialize_all_tools` and add `chain_verification_engine` to `index_status`/`build_index`.
- `src/instance_registry.hpp` and `.cpp`: likely no change unless module lookup needs a helper by SHA256/basename.
- `src/mcp_server.cpp`: likely no change because generic `instance_id` routing already exists; add only if chain orchestration needs a dedicated multi-peer aggregate endpoint.
- Build configuration files: add new sources to the existing plugin target when implementation happens.

No generated encrypted headers or driver/protector assets should be touched for this plugin engine.

## Tool Surface

Read-only MCP tools:

- `verify_vulnerability_chain`
  - Input: full `chain_document_v1`, tier, budgets.
  - Output: full `chain_verification_report_v1`.
  - Category: `vuln_chain_verify`.
  - Required indices: `chain_verification_engine`.

- `chain_verify_status`
  - Engine availability, loaded module bindings, cache counts, last error, in-flight count.

- `chain_verify_link`
  - Verify one link under supplied entry state for focused diagnostics.

- `chain_match_boundaries`
  - Run only postcondition/precondition matching over a chain document.

- `chain_confirm_trigger`
  - Confirm a trigger path from event to behavior.

- `chain_explain_failure`
  - Return the smallest contradiction slice from a report: producer fact, consumer fact, trace EAs, branch/call context.

- `chain_verify_cancel`
  - Cooperative cancellation.

Cache-mutating but non-destructive tools:

- `chain_verify_build_index`
  - Warm module/function summaries.

- `chain_verify_ledger_persist`
  - Save/load/clear chain report summaries in netnodes.

No default tool should mutate the IDB.

## Acceptance Criteria

Core correctness:

- Verifies a chain as a single continuous trace, not as independent link checks.
- Resolves every function entry, target behavior, branch, call, and return to concrete module/RVA citations where possible.
- Tracks registers, flags, stack, memory regions, aliases, symbolic/concrete values, side effects, and object lifetimes across function and binary boundaries.
- Compares every adjacent link boundary using typed facts.
- Proves or refutes trigger paths from event entry to claimed behavior.
- Resolves indirect calls from current state, not only from heuristic local target recovery.
- Reports collateral damage and proves whether it is survivable before the goal.
- Produces deterministic JSON with cited EAs, branch ledger, call ledger, memory writes, assumption gaps, and solver details.

Case-study gates:

- NTFS to ETW bad chain is refuted because the overflow content is zero bytes and the ETW stop trigger does not reach the claimed unlink write.
- AFD to `_setjmp` bad chain is refuted or marked inconclusive with a precise unmet fact because `conn+0x48` self-reference requires `conn` address knowledge before spray fill.
- AFD to `_setjmp` corrected chain with address discovery is confirmed through the hidden `LIST_ENTRY` check when all state facts are provided and proven.
- Bad `pvScan0 = gpHandleManager` layout is refuted because `SetBitmapBits` writes to `gpHandleManager`, not to the `pvScan0` slot.
- Correct `pvScan0 = &pvScan0` layout is confirmed for pointer redirection.

Stability:

- Missing module, decompiler failure, unsupported instruction, solver timeout, or remote peer timeout never crashes IDA.
- Cancellation returns a partial report with phase reached and preserved evidence.
- Engine stays read-only by default.
- Reports never claim `confirmed` when a branch, boundary, trigger, or indirect call target is unproven.

Performance:

- Indexing a large kernel binary is incremental and cacheable.
- A focused chain verification with under 100 relevant functions completes in the default 120-second budget on a warmed cache.
- Re-running the same chain on an unchanged IDB uses cached summaries and avoids regenerating all microcode.

## Verification Plan for Implementation

Static/unit verification:

- Schema parser tests for valid and invalid `chain_document_v1`.
- Address normalization tests for `{module_id,rva}`, `{instance_id,ea}`, symbol names, image-base changes, and hash mismatches.
- Value lattice tests for concrete/symbolic/unknown/poison propagation.
- Alias tests for must/may/no alias and self-reference.
- Boundary matcher tests for exact match, alias match, controlledness mismatch, width mismatch, zero-vs-controlled mismatch, and address-knowledge gaps.
- Branch predicate tests for forced, feasible, contradictory, and timeout cases.
- Call ABI tests for argument mapping, return mapping, volatile clobbers, and nonvolatile preservation.

Golden case tests:

- Encode the NTFS to ETW failure as a chain document and require:
  - zero-byte overflow postcondition.
  - controlled `LIST_ENTRY` precondition mismatch.
  - missing ETW unlink trigger.
  - final verdict `refuted`.
- Encode the AFD `_setjmp` chain before address discovery and require:
  - hidden `LIST_ENTRY` check citation.
  - missing `conn_va` fact.
  - no confirmed reachability to `_setjmp`.
- Encode the corrected AFD address-discovery chain and require:
  - self-reference fact produced before spray fill.
  - indirect target state-proven as `_setjmp`.
  - return-path collateral classified.
- Encode the bad and corrected `pvScan0` layouts and require the exact contradiction/pass described above.

Integration verification:

- Open multiple IDA instances for different modules and verify module binding by `instance_id` and SHA256.
- Run `chain_verify_build_index` and confirm netnode cache creation.
- Run `verify_vulnerability_chain` twice and confirm second run uses cached summaries.
- Route a cross-binary callee summary request to a peer IDA and reject the result when the peer hash is intentionally mismatched.
- Exercise cancellation during microcode generation, path search, and SMT solve.

Regression verification:

- Existing `verify_taint_path`, `solve_for_exploit_input`, `prove_pointer_alias`, and `extract_wire_path_constraints` behavior remains unchanged.
- Existing MCP routing by `instance_id` and `pid` remains unchanged.
- Existing plugin startup still initializes `agent_tools::initialize_all_tools()` and starts MCP normally.

Implementation completion requirements:

- The host AI, not any investigation/planning subagent, must run the canonical AiDA build after code implementation.
- Chain tools must return structured errors rather than throwing across MCP boundaries.
- Incomplete behavior, unverifiable confirmations, and "assumed verified" states are unacceptable.
- A chain report must make the difference between `confirmed`, `likely`, `plausible`, `speculative`, `refuted`, `timeout`, and `unsupported` mechanically auditable from cited facts.
