# Universal Multi-Link Verification Engine Perfection Plan

Scope: AiDA IDA Pro plugin vulnerability-chain verification. This plan supersedes the chain-specific assumptions in plans 02 through 06 while preserving their useful extraction, multi-IDB, cache, and job-system architecture. The engine verifies arbitrary multi-stage chains across arbitrary binaries as one continuous trace. The `driver/PROGRESS.md` case studies are regression evidence only, not the architecture boundary.

## Source Verification Status - 2026-07-03

Verdict: **NOT 100% implemented. Keep this plan open.**

Source evidence proves partial implementation exists:

- `src/vuln/chain_model.hpp` defines `aida_chain_document_v2`, `chain_verification_report_v2`, generic fact kinds, value kinds, provenance kinds, link roles, objective kinds, trigger kinds, budgets, evidence refs, assumptions, links, objectives, target model, and verification policy.
- `src/vuln/chain_schema.cpp` parses and validates the v2 document shape, rejects unknown fields, supports legacy v1 migration, validates corpus/link/objective references, and exposes schema/self-check helpers.
- `src/vuln/chain_state.hpp` defines register, memory, alias, lifetime, allocator, callback, side-effect, and final-goal state structures.
- `src/vuln/chain_report.cpp` defines the v2 report model, acceptance finalization, failure codes, and self-check behavior that blocks accepted confirmation when critical facts remain unknown.
- `src/vuln/chain_extraction.cpp` extracts module and function snapshots with raw instruction facts, xrefs, type facts, ctree, microcode status, imports, entries, and segments under `execute_sync(..., MFF_READ)`.
- `src/vuln/chain_solver.cpp` evaluates explicit branch/value/alias/protocol/objective SMT obligations with cache keys and maps unknown/timeout to non-confirming verdicts.
- `src/vuln/chain_verification_engine.cpp` implements a contract-based verifier over declared facts, preconditions, postconditions, solver obligations, corpus availability, boundaries, and objectives.
- `src/vuln/chain_verification_tools.hpp` registers consolidated MCP surfaces through `ida_chain_manage`, `ida_project_manage`, `ida_extract_manage`, `ida_report_manage`, and `ida_job_manage`, with action/operation aliases, pagination cursors, in-memory jobs, report export, and extraction operations.

Source evidence also proves this plan is still incomplete:

- The required MCP tool names `chain_verify_manage`, `chain_verify_query`, and `chain_extract_query` are not registered. The current registered names are `ida_chain_manage`, `ida_project_manage`, `ida_extract_manage`, `ida_report_manage`, and `ida_job_manage`.
- The registered `ida_chain_manage` submit/start path does not call `aida::vuln::chain::engine().verify()`. It builds reports through local `build_chain_report()` and per-link `verify_link_data()`, so it is not the universal continuous-trace engine.
- `ChainVerificationEngine::verify()` never calls the extraction service, path corridor builder, trigger tracer, side-effect classifier over live snapshots, cross-domain logic, or MCP peer routing. It consumes facts and obligations already present in the JSON document.
- Package C is not implemented as planned: there are no `chain_transfer.*`, `chain_alias.*`, `chain_lifetime.*`, or `chain_protocol.*` files. `chain_state.*` models these domains, but there is no generic transfer engine that derives content, alias, allocator, lifetime, protocol, and poison/fatal facts from execution.
- Package D is not implemented as planned: there are no `chain_cross_domain.*` files, and the existing `chain_path_trace.cpp`/`chain_trigger_trace.cpp` are same-function snapshot helpers, not universal cross-binary/cross-domain ABI, message, callback, interrupt, firmware, and protocol transition proof.
- Package F is incomplete: there are no `chain_job_manager.*`, `chain_cache.*`, or `chain_recovery.*` files. The registered tools use process-local in-memory job/report maps, and report ledger operations call the old `verify::engine().persist_ledger()` path instead of the chain store.
- Package G is incomplete: there is no `chain_mcp_tools.cpp`, no required `chain_verify_manage/query/extract_query` names, and no MCP chain resource templates. Report responses include `ida://chain/reports/...` resource descriptors with `available_via`, but `src/mcp_server.cpp` only exposes generic resource templates such as function/address/struct/import/export/xrefs.
- Package H is incomplete: `chain_report.*` exists, but no `chain_report_view.*` source exists and the registered submit path does not emit the full `chain_report_t` model from `chain_report.cpp`.
- Package I is incomplete: there is no `src/vuln/tests` chain test tree and no `src/vuln/tests/chain_regression_specs/*.json`; `ChainVerificationEngine::universal_synthetic_regression_specs()` embeds only five synthetic specs, not suites A through I.
- The IDA-safety acceptance is not fully met. `chain_extraction.cpp` uses bounded `MFF_READ` slices, but `src/vuln/chain_verification_tools.hpp` also calls IDA APIs such as `get_func()`, `getn_func()`, xref enumeration, segment access, imports, entries, and byte reads directly from handlers instead of through the extraction slice layer.
- The path trace source is not proven build-clean by inspection: `src/vuln/chain_path_trace.cpp` refers to `instruction_fact`, while `src/vuln/chain_extraction.hpp` declares `instruction_fact_t` and no source-visible alias was found.
- The plan's strict acceptance rule is not enforced on the registered submit path. `build_chain_report()` can mark a chain `confirmed` and `accepted` from independent per-link verdict counts and simple boundary results, without requiring full P0-P6 proof completeness.

Remaining work required before this plan can be deleted:

1. Decide and implement the canonical MCP names, or update this plan only after the shipped API names are intentionally accepted. The current mismatch is not a completed implementation of this plan.
2. Wire the registered submit/query/extract surface to the production `aida::vuln::chain` schema, report, extraction, solver, store, and verifier layers.
3. Replace per-link report assembly with a single continuous trace engine that derives facts from extraction and transfer rather than declared JSON postconditions.
4. Implement the missing transfer, alias, lifetime, protocol, cross-domain, job-manager, cache, recovery, MCP resource-template, optional report-view, and regression-test packages.
5. Ensure every IDA SDK read in verifier/extraction paths runs through bounded `MFF_READ` slices and no raw SDK pointer escapes serialized snapshots.
6. Implement resource-backed paginated chain reports through MCP resources/templates, not only tool-response resource hints.
7. Encode and run suites A through I, including the PROGRESS.md cases as ordinary specs with no hardcoded exploit-family logic.
8. Make the registered submit path enforce P0-P6 proof completeness before any `confirmed`/`accepted` verdict can be emitted.

## Required Evidence Read

1. `driver/PROGRESS.md:2229-2516` documents the failure class this engine must eliminate:
   - Per-link checks passed, but complete chains failed at boundaries.
   - NTFS to ETW failed because the overflowing content was zero-filled, not controlled, and because the claimed trigger path never reached the unlink write.
   - AFD to `_setjmp` failed because an intermediate `LIST_ENTRY` self-reference check existed before the indirect call and required address knowledge not produced by earlier links.
   - `pvScan0` failed because the design confused writing to the address stored in a pointer field with updating the pointer field itself.
2. `src/plugin_plans/02_multibinary_project_model_plan.md` correctly establishes module identity, canonical addresses, cross-module edges, and a trace-state skeleton, but it is still Windows/LPE example-heavy.
3. `src/plugin_plans/03_chain_verification_engine_plan.md` correctly defines microcode, alias, boundary, and logical-goal phases, but its schema and tool surface remain too shaped by the AFD/NTFS/pvScan0 studies and allow confidence labels that can be mistaken for acceptance.
4. `src/plugin_plans/04_ida_extraction_decompiler_plan.md` correctly requires raw, ctree, microcode, xref, and type facts with failure statuses, but the plan must explicitly support protocols, firmware, allocator families, callback/event systems, and negative evidence as generic facts.
5. `src/plugin_plans/05_performance_reliability_plan.md` correctly defines async jobs, snapshots, generation-aware caches, cancellation, and peer failure behavior, and these are mandatory for this engine.
6. `src/plugin_plans/06_existing_plugin_audit_and_workbreakdown.md` correctly maps the initial work into `src/vuln/`, but its MCP surface is too many single-purpose tools and its regression suite is too centered on `PROGRESS.md`.
7. Current code evidence:
   - `src/vuln/verification_engine.hpp:24-31` exposes only `confirmed`, `refuted`, `inconclusive`, `timeout`, and `unsupported`.
   - `src/vuln/verification_engine.hpp:144-190` exposes single source/sink verification, payload solving, loop bounds, pointer alias, path satisfiability, ledger, cancellation, and wire constraints.
   - `src/vuln/verification_engine.cpp:67-70` combines a global cancel flag with `user_cancelled()`.
   - `src/vuln/verification_engine.cpp:86-99` uses modal wait boxes.
   - `src/vuln/verification_engine.cpp:681-687` treats an empty local path-constraint set as confirmed. The chain engine must not inherit that rule because "no extracted constraints" can mean unconditional reachability, missing extraction, unsupported path, or an insufficient corridor.
   - `src/vuln/verification_tools.cpp:611-828` registers many single-purpose verifier MCP tools. The chain engine should expose a compact operation-based interface instead.
   - `src/mcp_server.cpp:1750-1808` already publishes JSON schemas, read-only/destructive/idempotent hints, and `instance_id`/`pid` routing for every exposed tool.
   - `src/mcp_server.cpp:1895-2007` already supports tools, resources, prompts, `resources/list`, and `resources/read`.
   - `src/mcp_server.cpp:2639-2675` already exposes `list_ida_instances`, `get_local_instance_info`, and `query_all_instances`.
   - `src/standalone/src/core/tools/session_tools_standalone.cpp:565-603` shows the desired consolidated `action`/`operation` plus `payload` compatibility pattern.

## Gaps In Current Plans

1. The architecture is not universal enough. Plans 02, 03, 04, 05, and 06 repeatedly use kernel/LPE concepts as examples, but the final engine must model user-mode programs, firmware images, protocol parsers, allocator internals, callback systems, object lifetimes, data formats, and hardware-facing state with the same primitives.
2. The schema vocabulary is split across plans. The final implementation needs one chain document, one fact model, one trace-state model, one proof ledger, and one report schema.
3. The plans do not separate verdict from confidence strongly enough. `likely`, `plausible`, and `speculative` are useful search labels, but they must never be accepted as chain verification. Unknown never confirms a chain.
4. Negative evidence is under-specified. "No path reaches behavior" is a proof only when the traversed graph, missing edges, unresolved calls, timeout state, and completeness boundary are recorded.
5. Missing binary behavior is under-specified. A chain cannot be confirmed when a required binary, firmware region, protocol handler, import target, callback target, or type layout is missing.
6. Trigger modeling is still Windows-trigger biased. The engine needs a generic event model for API calls, syscalls, IOCTLs, interrupts, timers, message queues, GUI callbacks, signal handlers, RPC dispatch, protocol state-machine transitions, firmware hooks, and destructor/finalizer paths.
7. Allocator and object lifetime modeling is too pool/LFH specific. The engine must model generic allocate, initialize, publish, borrow, free, recycle, destruct, reclaim, and address-discovery phases across CRT heaps, custom heaps, slab allocators, firmware pools, arenas, object caches, and kernel pools.
8. Protocol and content provenance are not explicit enough. A byte range must carry source, transform, encoding, endian, checksum/decompression/decryption status, control degree, and exact producer operation.
9. The MCP tool surface in plan 03 explodes into many chain tools. AiDA standalone already favors consolidated manage-style APIs. The verifier should use a small tool set with operation-specific payloads and resource-backed artifacts.
10. Plans mention reports, but not a stable MCP resource model. Large traces must be inspectable through paginated resources and resource templates, not oversized tool responses.
11. Existing per-function engines are useful but not chain-safe. The chain engine must treat them as fact producers and solver helpers, not as final authorities.

## IDA SDK Basis

Every IDA SDK interaction must be justified by local SDK headers under `C:\Users\ruar1337\AiDAPrivate\ida-sdk\src\include`. The following snippets are the source of truth for implementation recommendations.

1. Main-thread read/write scheduling:
   - `ida-sdk/src/include/kernwin.hpp:4441-4444`: `MFF_READ` executes when IDA is idle and safe to query the database, and is recommended for code that does not modify the database.
   - `ida-sdk/src/include/kernwin.hpp:4449-4454`: `MFF_WRITE` executes when safe to modify the database and implies `MFF_READ`.
   - `ida-sdk/src/include/kernwin.hpp:4485-4487`: if `exec_request_t::execute()` raises an exception, `execute_sync()` never returns.
   - Recommendation: all IDA and Hex-Rays reads run in bounded `execute_sync(..., MFF_READ)` slices with exception containment inside the request. Verification itself runs on serialized snapshots outside the IDA slice.
2. Async request cancellation:
   - `ida-sdk/src/include/kernwin.hpp:4891-4894`: `cancel_exec_request(int req_id)` cancels a pending request.
   - `ida-sdk/src/include/kernwin.hpp:4901-4904`: `cancel_thread_exec_requests(qthread_t tid)` cancels asynchronous requests from a thread.
   - `ida-sdk/src/include/kernwin.hpp:4919-4924`: `set_execute_sync_availability()` controls execute-sync availability per thread.
   - Recommendation: job cancellation must cancel queued main-thread slices and mark the job token. It must not rely on `user_cancelled()` as the primary state.
3. UI cancellation:
   - `ida-sdk/src/include/kernwin.hpp:6320-6323`: `user_cancelled()` returns UI cancel state and displays a message.
   - Recommendation: chain jobs use explicit job tokens. `user_cancelled()` can be sampled only in UI slices as a secondary signal.
4. Plugin lifetime and multi-IDB:
   - `ida-sdk/src/include/loader.hpp:602-605`: `PLUGIN_MULTI` means the plugin can work with multiple IDBs in parallel and uses `plugmod_t`.
   - `ida-sdk/src/include/loader.hpp:623-627`: `term` and `run` must be null for `PLUGIN_MULTI` plugins.
   - Recommendation: every IDB owns a separate verifier context, generation counters, snapshot store, and job registry. Cross-binary verification uses MCP instance routing, not raw pointer sharing.
5. Auto-analysis readiness:
   - `ida-sdk/src/include/auto.hpp:245`: `auto_wait_range(ea_t ea1, ea_t ea2)`.
   - `ida-sdk/src/include/auto.hpp:263-266`: `auto_is_ok()` reports whether all auto-analysis queues are empty.
   - Recommendation: the engine records auto-analysis status and only waits for required ranges under an explicit job policy. Whole-database blocking is not allowed in an interactive path.
6. Binary identity:
   - `ida-sdk/src/include/nalt.hpp:1371-1383`: `get_root_filename()` and `get_input_file_path()`.
   - `ida-sdk/src/include/nalt.hpp:1388-1399`: input size, CRC32, MD5, and SHA256 retrieval.
   - `ida-sdk/src/include/nalt.hpp:1407-1408`: `get_imagebase()`.
   - `ida-sdk/src/include/ida.hpp:634-654`: bitness, DLL, endian, and kernel-mode flags.
   - `ida-sdk/src/include/ida.hpp:797-800`: `inf_get_min_ea()` and `inf_get_max_ea()`.
   - `ida-sdk/src/include/ida.hpp:1028-1034`: `inf_get_procname()`.
   - Recommendation: every address fact must include module identity, digest, image base, bitness, processor, min/max EA, segment, and RVA.
7. Segments:
   - `ida-sdk/src/include/segment.hpp:125-127`: segment permissions are execute, write, read.
   - `ida-sdk/src/include/segment.hpp:642-676`: segment enumeration and lookup APIs.
   - `ida-sdk/src/include/segment.hpp:1051`: `get_segm_name()`.
   - `ida-sdk/src/include/segment.hpp:1092`: `get_segm_class()`.
   - `ida-sdk/src/include/segment.hpp:1116`: `segtype()`.
   - Recommendation: executable/data/writable mapping, import slots, firmware memory classes, and MMIO-like regions must be derived from segment facts where possible and carried into memory-region facts.
8. Functions and raw instructions:
   - `ida-sdk/src/include/funcs.hpp:288-293`: `get_func(ea_t)` returns a function pointer or null.
   - `ida-sdk/src/include/funcs.hpp:783-829`: `func_item_iterator_t` enumerates function items and code/data heads.
   - `ida-sdk/src/include/ua.hpp:1501-1509`: `decode_insn()` interprets bytes as an instruction and does not modify the database.
   - Recommendation: raw extraction is mandatory for every relevant function and remains the fallback when Hex-Rays fails.
9. Xrefs and graph edges:
   - `ida-sdk/src/include/xref.hpp:170-194`: `xrefblk_t` enumerates xrefs, and its contents are read-only.
   - `ida-sdk/src/include/xref.hpp:208-214`: flags distinguish flow, no-flow, data, code, EA, and type xrefs.
   - `ida-sdk/src/include/xref.hpp:228-242`: `first_from`, `next_from`, `first_to`, and `next_to`.
   - Recommendation: trigger reachability, call graph, data references, callback registration, protocol dispatch, and negative evidence must record xref traversal flags and completeness.
10. Imports and entries:
   - `ida-sdk/src/include/nalt.hpp:1589-1615`: import module count, import module name, and import enumeration.
   - `ida-sdk/src/include/entry.hpp:26`: entry-point count.
   - `ida-sdk/src/include/entry.hpp:65-80`: entry ordinal, address, and name.
   - `ida-sdk/src/include/entry.hpp:108`: entry forwarder retrieval.
   - Recommendation: import/export/forwarder resolution is an evidence source, not a proof by name. Exact digest plus RVA beats symbol-name matching.
11. Netnode persistence:
   - `ida-sdk/src/include/netnode.hpp:258-267`: named netnode constructor can create or open a node.
   - `ida-sdk/src/include/netnode.hpp:285-292`: user-defined netnode names must use the `$ ` prefix to avoid clashes.
   - `ida-sdk/src/include/netnode.hpp:942-1018`: blob get/set APIs.
   - `ida-sdk/src/include/netnode.hpp:1114-1115`: netnode availability checks.
   - Recommendation: IDB-local caches and ledgers use bounded, chunked netnode blobs with schema/generation keys.
12. Hex-Rays ctree and microcode:
   - `ida-sdk/src/include/hexrays.hpp:15-37`: microcode uses `mba_t`, `mblock_t`, `minsn_t`, `mop_t`, and ctree uses `cfunc_t`.
   - `ida-sdk/src/include/hexrays.hpp:117-124`: microinstructions have operands including immediates, registers, memory references, and nested instruction results.
   - `ida-sdk/src/include/hexrays.hpp:2405-2434`: `mop_t`, `minsn_t`, `mblock_t`, and lvar refs are specific to one `mba_t` and cannot migrate between them.
   - `ida-sdk/src/include/hexrays.hpp:3637-3644`: `minsn_t` records opcode, EA, and left/right/destination operands.
   - `ida-sdk/src/include/hexrays.hpp:4262-4271`: `mblock_t` carries start/end, instruction list, parent `mba_t`, serial, and type.
   - `ida-sdk/src/include/hexrays.hpp:4473-4487`: use/def lists model locations read or modified by instructions.
   - `ida-sdk/src/include/hexrays.hpp:4771-4780`: maturity levels include `MMAT_CALLS`, `MMAT_GLBOPT3`, and `MMAT_LVARS`.
   - `ida-sdk/src/include/hexrays.hpp:5282-5288`: modified microcode must be verified and chains marked dirty. The verifier must not modify microcode.
   - `ida-sdk/src/include/hexrays.hpp:7026-7038`: `CV_PARENTS` preserves ctree parent information.
   - `ida-sdk/src/include/hexrays.hpp:7732-7772`: `decompile_func()` and `gen_microcode()` return ctree and microcode or null on failure.
   - `ida-sdk/src/include/hexrays.hpp:7865-7906` and `13039-13048`: Hex-Rays callbacks and install/remove APIs.
   - Recommendation: Hex-Rays facts are serialized inside read slices, raw SDK pointers never leave the slice, ctree extraction uses `CV_PARENTS` when parent context matters, microcode extraction records maturity and failure state, and callbacks only dirty generations.

## Universal Design Corrections

1. The engine verifies a chain of state transitions, not a chain of vulnerability families.
2. A link is any transition that consumes facts and produces facts. Examples: parser field copy, callback registration, destructor path, allocator reuse, firmware interrupt handler, syscall dispatch, object method call, indirect branch, protocol state transition, data transform, privilege boundary, or memory write primitive.
3. A binary is any analyzed code corpus: PE, ELF, Mach-O, firmware blob, raw ROM segment, bootloader, driver, DLL, executable, plugin module, sandbox fixture, or extracted code region. PE-specific fields are optional module facts, not schema fundamentals.
4. The engine treats protocol messages, heap objects, register state, memory objects, callbacks, and final objectives as the same typed fact system.
5. The complete trace owns the space between links. There is no "between links" gap where hidden checks, writes, clobbers, or event preconditions can escape analysis.
6. Unknown is a first-class terminal state. It is never coerced into success, and it cannot be hidden behind confidence.
7. Assumptions are evidence gaps until proven. An external user assertion may make a conditional diagnostic useful, but it cannot yield final `confirmed`.
8. Negative evidence must include traversal completeness. Absence of a call name, xref, or string is not a refutation unless the reachable set was completely bounded and every unresolved edge is accounted for.
9. Existing vuln engines become producers:
   - `taint_engine` supplies source/sink and reachability candidate facts.
   - `microcode_engine` supplies serialized microcode, def-use, call, branch, and side-effect facts.
   - `symbolic_engine` supplies branch/value/alias formulas and path constraints.
   - `smt_solver` supplies bounded SAT/UNSAT/UNKNOWN answers.
   - `verification_engine` supplies reusable verdict types and some solver helpers, but not chain acceptance.
10. MCP is not a wrapper after implementation. Every phase is designed as a job operation with status, cancellation, resume cursor, snapshot id, and exportable artifacts.

## Finalized Engine Schema

The implementation schema version is `aida_chain_document_v2`. It is generic and family-neutral.

```json
{
  "schema": "aida_chain_document_v2",
  "chain_id": "stable_user_or_tool_id",
  "title": "short human label",
  "target": {
    "architecture": "x86_64|x86|arm64|arm|mips|ppc|unknown",
    "platform": "windows|linux|uefi|firmware|baremetal|protocol|mixed|unknown",
    "endianness": "little|big|mixed|unknown",
    "pointer_width_bits": 64,
    "environment": {}
  },
  "corpus": [],
  "entry": {},
  "objects": [],
  "inputs": [],
  "events": [],
  "links": [],
  "objectives": [],
  "policies": {}
}
```

### Corpus Schema

`corpus[]` records code and data domains.

Required fields:

- `corpus_id`: stable identifier referenced by facts.
- `kind`: `binary`, `firmware_region`, `protocol_spec`, `memory_snapshot`, `external_contract`, `recorded_trace`.
- `identity`: hashes, path, image base, min/max, processor, bitness, file type, symbol set digest, PDB/build id if present.
- `availability`: `loaded`, `peer_loaded`, `missing`, `partial`, `recorded_only`.
- `loader_model`: image sections, segments, overlays, import/export/entry facts, MMIO ranges, protocol grammar sources, or raw address map.
- `trust`: `ida_extracted`, `recorded_dynamic`, `user_declared`, `imported_contract`.

Acceptance rule: any chain-critical corpus with `availability != loaded|peer_loaded|recorded_only` prevents `confirmed`.

### Address And Location Schema

Every address-bearing fact uses:

```json
{
  "location": {
    "corpus_id": "mod1",
    "ea": "0x...",
    "rva": "0x...",
    "segment": ".text",
    "function_id": "mod1:rva:size:hash",
    "instruction_id": "mod1:rva",
    "layer": "raw|ctree|microcode|type|xref|dynamic|declared",
    "confidence": "exact|symbolic_exact|weak_name|ambiguous|unresolved"
  }
}
```

Names are labels. They are never unique identities unless joined with corpus digest and RVA or an explicit export/import ordinal record.

### Fact Schema

All facts share:

- `fact_id`: deterministic hash of kind, subject, predicate, value, producer, and evidence.
- `kind`: one of the kinds below.
- `subject`: address, register, field, object, message, callback slot, event, edge, thread, process, privilege, allocator bin, or objective.
- `predicate`: normalized operation.
- `value`: typed value.
- `phase`: production phase or link id.
- `producer`: link id, extraction layer, solver query, dynamic trace, or user declaration.
- `evidence`: one or more citations.
- `proof_state`: `proven`, `refuted`, `conditional`, `unknown`, `unsupported`, `timeout`.
- `criticality`: `chain_critical`, `objective_critical`, `collateral`, `diagnostic`.

Fact kinds:

1. `value_fact`: equality, inequality, range, bitmask, arithmetic relation, type width, signedness, endian relation.
2. `content_fact`: controlled bytes, zero bytes, constant bytes, copied bytes, decoded bytes, transformed bytes, checksum-constrained bytes, encrypted/compressed unknown, symbolic bytes.
3. `address_fact`: concrete address, module RVA, symbolic address, field path, offset expression, address-known phase.
4. `register_fact`: register value, flags, ABI argument/return, volatile/nonvolatile preservation.
5. `stack_fact`: stack pointer delta, return address, shadow space, saved register, local slot, caller/callee frame.
6. `memory_fact`: read/write/store/load over region, field, width, content, alignment, permissions, initialization, bounds.
7. `alias_fact`: must-alias, may-alias, no-alias, points-to set, field identity, self-reference.
8. `lifetime_fact`: allocated, initialized, published, borrowed, freed, destructed, reclaimed, reused, dangling, address discovered, use window.
9. `allocator_fact`: allocator family, arena, size class, bin, slab/cache, reuse ordering, quarantine, zeroing behavior, metadata write.
10. `call_fact`: direct call, import/export call, indirect call, virtual call, thunk, tailcall, helper call, ABI transfer, return/clobber.
11. `branch_fact`: predicate, required direction, feasible direction, forced direction, opposite feasibility, guard semantics.
12. `event_fact`: event source, dispatch route, callback registration, callback invocation, interrupt, timer, signal, finalizer, protocol transition, GUI/message pump trigger.
13. `protocol_fact`: message grammar, field range, endian, length relation, state-machine state, parser cursor, canonicalization, decoder transform, checksum/hash condition.
14. `firmware_fact`: MMIO read/write, port IO, interrupt vector, boot/runtime service call, SMI/NMI/IRQ route, memory map descriptor, privilege mode.
15. `concurrency_fact`: lock state, atomic op, race window, happens-before, thread identity, IRQL/priority/mode, preemption assumptions.
16. `objective_fact`: final required capability or invariant, such as arbitrary read, arbitrary write, control-flow hijack, auth bypass, sandbox escape, data exfiltration path, privilege transition, firmware persistent mutation, protocol invariant break.
17. `poison_fact`: fastfail, bugcheck, invalid dereference, assertion, fatal exception, required object corruption, unsupported path, impossible state.

### Value Lattice

`chain_value`:

- `unknown(reason)`: no proof.
- `unsupported(reason)`: extractor or model cannot represent this value.
- `concrete(bits, value)`: exact.
- `bytes(kind, length, source)`: content-aware byte range.
- `symbolic(expr, width, variables)`: solver-backed expression.
- `interval(min,max,width)`.
- `bitmask(known_zero,known_one,width)`.
- `pointer(region, offset, address_known_phase)`.
- `points_to(set, must_or_may)`.
- `aggregate(fields)`.
- `poison(reason)`.

Controlledness:

- `attacker_controlled_exact`
- `attacker_controlled_partial`
- `derived_from_attacker`
- `constant_zero`
- `constant_nonzero`
- `copied_from_memory`
- `environment_derived`
- `target_derived`
- `cryptographically_constrained`
- `unknown`

Unknown controlledness never satisfies a controlled precondition.

### State Schema

`trace_state` is immutable per search node:

- `pc`: canonical corpus/RVA/function/block/instruction.
- `event_stack`: nested trigger/event/callback/protocol states.
- `call_stack`: frames with ABI, return site, caller facts, callee facts, and clobber facts.
- `thread_process`: thread id model, process/session, CPU mode, privilege, IRQL/priority, interrupt state when known.
- `registers`: symbolic/concrete register and flag store.
- `stack`: stack regions, frame slots, return addresses.
- `memory`: region graph, object graph, field graph, aliases, permissions, initialization.
- `allocator`: active arenas/bins/size classes, address-discovery facts, reuse order, zeroing/metadata policy.
- `messages`: protocol message buffers, cursors, decoded fields, transformed fields, parser state.
- `callbacks`: registration slots, target expressions, lifetime, dispatch roots, invocation evidence.
- `constraints`: SMT expressions plus non-SMT obligations.
- `side_effects`: complete effect ledger.
- `obligations`: facts required by future links or objectives but not yet proven.
- `proof_ledger`: decisions, solver query ids, extraction chunk ids, negative-evidence scope.
- `resource_counters`: depth, nodes, elapsed, memory, solver calls, peer calls.

### Link Schema

Each link is a transition:

```json
{
  "link_id": "L1",
  "role": "trigger|transform|allocation|lifetime|dispatch|call|write|read|branch|callback|protocol|firmware|objective_step",
  "entry": {
    "event": {},
    "location": {},
    "state_preconditions": []
  },
  "path": {
    "mode": "exact_corridor|target_search|bounded_reachable_set|external_contract",
    "roots": [],
    "targets": [],
    "forbidden": []
  },
  "transition": {
    "claimed_effects": [],
    "required_branches": [],
    "required_calls": [],
    "required_absences": []
  },
  "exit": {
    "postconditions": [],
    "side_effect_policy": []
  }
}
```

`required_absences` is only accepted with complete negative evidence. Example: "no validator clears this field before sink" must state the bounded reachable set and unresolved edges.

### Objective Schema

Objectives define final proof targets without assuming exploit family:

- `objective_id`
- `kind`: `arbitrary_read`, `arbitrary_write`, `controlled_call`, `controlled_return`, `auth_state_bypass`, `parser_state_violation`, `object_lifetime_violation`, `privilege_transition`, `firmware_persistent_write`, `protocol_confusion`, `data_exfiltration_path`, `custom_invariant`.
- `requires`: facts that must hold at the objective point.
- `forbids`: poison facts and collateral facts that invalidate success.
- `demonstration`: operation sequence the engine simulates after chain setup.

The final objective is not confirmed by proving an intermediate primitive. It is confirmed only when the requested final invariant is true under the complete trace state.

## Proof, Refutation, Confidence, And Acceptance Rules

### Verdicts

The report-level verdict remains compatible with existing `verification_engine.hpp`:

- `confirmed`
- `refuted`
- `inconclusive`
- `timeout`
- `unsupported`

The report adds `acceptance`:

- `accepted`: only valid when `verdict == confirmed`.
- `not_accepted`: every other verdict.

The report also adds `confidence`, but confidence never changes acceptance.

### Proof Levels

Proof levels are cumulative:

1. `P0_structural`: schema valid, corpus bound, addresses/symbols resolved or explicitly scoped.
2. `P1_reachability`: entry reaches target behavior through a complete path corridor or complete reachable-set proof.
3. `P2_state`: register, stack, memory, content, alias, lifetime, event, and protocol preconditions are satisfied at every required point.
4. `P3_solver`: symbolic branches, aliases, and arithmetic are SAT for required directions and UNSAT for forbidden contradictions when solver proof is needed.
5. `P4_transition`: link postconditions satisfy the next link preconditions, including content provenance and temporal ordering.
6. `P5_objective`: final objective operation sequence is simulated and proven, with collateral effects safe or irrelevant by data-flow proof.

`confirmed` requires P0 through P5 for every chain-critical fact and every objective-critical fact.

### Refutation Levels

Refutation levels are independent and terminal when critical:

1. `R0_invalid_spec`: schema contradiction or invalid required field.
2. `R1_missing_corpus`: required binary, region, handler, protocol spec, or trace evidence absent.
3. `R2_unreachable`: complete negative reachability proves the target behavior cannot be reached.
4. `R3_branch_contradiction`: required branch direction is UNSAT or forced opposite.
5. `R4_content_mismatch`: producer content cannot satisfy consumer content, such as zero bytes versus controlled pointers.
6. `R5_alias_contradiction`: required field update, self-reference, or no-alias relation is false.
7. `R6_lifetime_temporal_contradiction`: object is unavailable, address is discovered too late, callback is unregistered, or use happens outside the valid window.
8. `R7_call_target_contradiction`: indirect/direct target is not the claimed target under current state.
9. `R8_protocol_contradiction`: length, checksum, state, endian, decoder, or grammar relation makes the claimed field value impossible.
10. `R9_firmware_hardware_contradiction`: MMIO/interrupt/service transition cannot reach the claimed effect under modeled state.
11. `R10_poison`: required execution hits fastfail, bugcheck, fatal exception, assertion, invalid dereference, or destroys future required state.
12. `R11_objective_contradiction`: final primitive or invariant does not actually follow from the intermediate mechanism.

Any critical refutation sets report verdict to `refuted`.

### Unknown And Conditional Policy

1. Unknown never confirms.
2. Timeout never confirms.
3. Unsupported never confirms.
4. Missing binary never confirms.
5. Missing trigger target never confirms.
6. Unresolved indirect call never confirms.
7. May-alias cannot satisfy a must-alias precondition.
8. Unknown controlledness cannot satisfy controlled content.
9. Unknown address-knowledge phase cannot satisfy "address known before construction".
10. User-declared facts create `conditional` facts. They allow a conditional diagnostic path but not accepted verification unless the fact is independently proven by extracted or recorded evidence.
11. A positive confidence label cannot mask an assumption gap. Reports must list every unproven chain-critical fact at top level.

### Confidence Labels

Confidence is diagnostic:

- `exact`: all critical facts proven from exact extracted or recorded evidence.
- `strong`: all critical facts proven; noncritical facts use conservative summaries.
- `bounded`: proof holds within explicit depth/node/time/corpus boundaries.
- `conditional`: one or more user/external contracts are required.
- `heuristic`: useful search evidence, not proof.

Only `confirmed` plus `exact|strong|bounded` can be accepted. `conditional|heuristic` cannot be accepted.

## Generic Algorithms

### Phase 1: Validate And Normalize

1. Parse `aida_chain_document_v2`.
2. Canonicalize module, firmware, trace, and protocol corpus entries.
3. Resolve every address into `corpus_id + rva/offset + segment + function`.
4. Normalize user names into weak labels unless backed by import/export/entry/PDB evidence.
5. Convert all link preconditions, transitions, postconditions, and objectives into typed facts.
6. Reject ambiguous critical bindings unless the chain explicitly permits a target set and every target is analyzed.

### Phase 2: Build Evidence Corpus

1. Query local IDA and peer IDAs for binary identity, segments, imports, exports, functions, xrefs, entries, type summaries, and analysis readiness.
2. Create immutable `binary_snapshot`, `function_snapshot`, `cfg_snapshot`, `xref_snapshot`, `type_snapshot`, `ctree_snapshot`, and `microcode_snapshot` chunks.
3. Record per-layer status: `ok`, `skipped`, `failed`, `timeout`, `unsupported`, `stale`.
4. Preserve raw instruction facts for every relevant function even when ctree or microcode fails.
5. Do not centralize raw SDK pointers. Only normalized snapshot data crosses thread or IDB boundaries.

### Phase 3: Path Corridor Construction

1. For each link root/target pair, build a corridor from raw CFG, xrefs, ctree parent paths, and microcode blocks.
2. Include all intermediate instructions, branches, calls, returns, exceptions, and memory effects before the target behavior.
3. For target-search mode, enumerate candidate corridors and rank by exact target evidence before solver cost.
4. For bounded reachable-set mode, record every visited function, edge, unresolved edge, depth limit, node limit, timeout, and missing corpus.
5. A path target absent from a complete bounded reachable set yields `R2_unreachable`.

### Phase 4: Transfer Functions

The interpreter consumes normalized operations, not decompiler text.

Required transfer coverage:

- Integer arithmetic, bit operations, shifts, casts, sign/zero extension.
- Loads/stores with width, endian, alignment, permissions, and initialization.
- Branch predicates, flags, comparisons, switch dispatch.
- Direct, indirect, virtual, import, export, thunk, helper, tail, and callback calls.
- ABI argument, return, clobber, stack, shadow-space, and saved-register transitions.
- Common memory helpers: copy, move, set, compare, string ops, allocator/free/realloc/constructor/destructor forms.
- Atomic/interlocked operations and memory-order-relevant side effects.
- Protocol parser cursor movement, decode transforms, length/checksum/grammar relations.
- Firmware/low-level operations: MMIO, port IO, service table calls, interrupt vector dispatch, memory map transitions.

Unknown mutating operations produce `unsupported` or `unknown` facts and block confirmation when relevant.

### Phase 5: Branch And Solver Evaluation

1. Substitute concrete facts first.
2. Use interval and bitmask reasoning before SMT.
3. Query SMT for required direction.
4. Query opposite direction when the chain requires a forced direction.
5. Record SAT model, UNSAT reason where available, query id, timeout, and formula hash.
6. A branch is proven only when the required direction is satisfiable and every fact needed by later links is either forced or explicitly carried as a disjunction.

### Phase 6: Cross-Domain Transitions

A transition can cross:

- Binary to binary through import/export/thunk/syscall/IOCTL/RPC/callback/protocol dispatch.
- User-mode to kernel-mode.
- Firmware service to runtime handler.
- Parser to allocator.
- Allocator to object lifecycle.
- Event registration to event invocation.
- Dynamic trace to static corpus.

Algorithm:

1. Resolve edge by exact corpus identity first.
2. Apply ABI, message, firmware, or callback state transfer.
3. Require target identity proof for indirect edges.
4. Request target snapshot from owning IDA instance or resource.
5. Continue the same trace state through callee and return effects.
6. Mark missing or stale peer evidence as `peer_data_missing` and prevent confirmation.

### Phase 7: Boundary Unification

For adjacent links:

1. Convert producer postconditions and consumer preconditions into normalized facts.
2. Match by subject, field path, width, alias class, lifetime phase, temporal order, and content provenance.
3. Classify each consumer requirement:
   - `satisfied_exact`
   - `satisfied_by_must_alias`
   - `satisfied_by_solver`
   - `satisfied_by_recorded_dynamic_evidence`
   - `conditional_external`
   - `unproven`
   - `contradicted`
4. Refute on contradiction.
5. Block confirmation on unproven or conditional critical facts.
6. Emit a boundary matrix with producer evidence, consumer requirement, result, and minimal explanation.

### Phase 8: Trigger/Event Verification

Generic trigger verification:

1. Normalize the trigger into event source, dispatch root, target behavior, required state, and allowed event order.
2. Search xrefs, dispatch tables, callback registrations, protocol state transitions, interrupt vectors, timers, message handlers, and destructor/finalizer paths.
3. Confirm target behavior only if at least one complete path reaches it under satisfiable state.
4. Refute when the complete reachable set excludes it.
5. Return inconclusive when missing corpus, unresolved edges, unsupported callback semantics, or timeout prevents completeness.

### Phase 9: Lifetime And Allocator Verification

1. Build object timeline: allocate, initialize, publish, use, free, destruct, reuse, reclaim, use-after-free, final objective.
2. Record allocator family, arena/bin/cache, requested size, rounded size, metadata writes, zeroing/quarantine behavior, reuse policy, and address discovery.
3. Verify temporal order with happens-before facts.
4. Verify construction content is written before use.
5. Verify address-dependent fake structures have address knowledge before construction.
6. Verify allocator metadata and zeroing do not destroy needed content.

### Phase 10: Protocol And Content Provenance Verification

1. Model raw input bytes with field offsets, endian, variable-length encodings, transforms, decompression/decryption, canonicalization, and checksum/hash constraints.
2. Track copied, zeroed, derived, truncated, saturated, sanitized, escaped, decoded, and re-encoded content.
3. Verify parser cursor and state-machine transitions.
4. Compare produced content facts against downstream preconditions.
5. Refute protocol chains when a length/checksum/state/content relation makes the claimed downstream bytes impossible.

### Phase 11: Objective Simulation

1. Load objective facts and operation sequence.
2. Simulate final actions from the trace state after all links.
3. Verify that writes update the intended object/field, reads source the intended data, control-flow transfers target the intended code, or protocol invariant is actually violated.
4. Verify collateral effects cannot invalidate the objective before first success.
5. Emit `R11_objective_contradiction` when the mechanism is mechanically present but logically wrong.

### Phase 12: Minimal Failure Explanation

For any non-confirmed result, compute the smallest actionable evidence slice:

- First contradictory fact.
- Producer fact and evidence.
- Consumer precondition and evidence.
- Path branch/call context.
- Missing corpus or unsupported operation.
- Solver query id and status.
- Exact acceptance rule that blocked confirmation.

## Solver, Cache, And Budget Model

### Budget Tiers

1. `schema`: parse, normalize, bind corpus. Default wall budget 2 seconds.
2. `structural`: module/function/xref/type identity and cheap boundary checks. Default wall budget 15 seconds.
3. `focused`: path corridors, trigger reachability, boundary unification, limited SMT. Default wall budget 120 seconds.
4. `deep`: broader call expansion, disjunction preservation, allocator/protocol modeling, additional solver calls. Default wall budget 10 minutes.
5. `exhaustive`: explicit user-selected mode with larger peer, memory, and solver budgets.

The default MCP submit operation starts at `focused` unless the caller selects another tier.

### Solver Policy

1. Query keys include solver schema version, module hash, function hash, path predicate hash, memory model version, alias model version, objective version, and solver version.
2. SAT and UNSAT results can be cached when all dependencies are generation-pinned.
3. UNKNOWN and timeout results are cached only as diagnostic attempts with short TTL and never as proof.
4. Solver contexts are pooled and bounded. Any context that times out, throws, or returns corrupt output is discarded.
5. Per-query defaults:
   - Branch query: 250 ms structural, 2000 ms focused, 10000 ms deep.
   - Alias query: 1000 ms focused, 15000 ms deep.
   - Objective query: 5000 ms focused, 30000 ms deep.
6. Per-job solver concurrency defaults to one per IDB and at most four process-wide unless settings lower the cap.
7. SMT formulas are exported with redacted raw byte payloads only when they are not secrets. The report stores formula hashes and optional full formulas under explicit export policy.

### Cache Keys

All cache keys include:

- engine schema version
- extractor schema version
- corpus id and digest
- IDB generation
- Hex-Rays generation
- analysis generation
- signature database revision
- function start/end RVA and byte hash
- type digest for referenced types
- requested extraction layers and microcode maturities
- architecture, endian, pointer width, ABI
- chain document hash
- proof policy hash

Missing any relevant key component is a correctness bug.

### Snapshot Retention

1. Hot memory cache stores recent snapshot chunks by content id.
2. Netnode cache stores compact IDB-local summaries and ledgers using `$ aida.chain.*` nodes.
3. Large reports and traces are chunked by content id and paginated.
4. A stale snapshot can be read for historical reports but cannot be used for a new accepted verdict unless pinned by the report that produced it.

### Backpressure

1. Every job reserves estimated memory before deep phases.
2. Admission failure returns `resource_exhausted`.
3. Large functions degrade by tier: metadata, CFG, path-window microcode, full microcode.
4. Tool responses return previews plus resource URIs for large artifacts.
5. No phase builds unbounded JSON.

## MCP-First Engine Operations

The engine exposes a compact MCP surface with operation-specific payloads. This follows the `sessions_manage` pattern where `action` and `payload` are accepted, while also accepting `operation` as an alias for AI clients.

### Tool 1: `chain_verify_manage`

Category: `vuln_chain`.

Read-only hint: false, because some operations create jobs, write ledgers, warm caches, or cancel requests.

Top-level params:

- `operation`: required string.
- `payload`: optional object.
- `chain_id`: optional string.
- `job_id`: optional string.
- `phase`: optional string.
- `tier`: optional string.
- `instance_id`: existing MCP routing key.
- `pid`: existing MCP routing key.

Operations:

- `submit`: validate chain, create job, optionally start immediately.
- `start_phase`: start a named phase for an existing job.
- `pause`: stop scheduling new work and persist resumable state.
- `resume`: resume from saved cursor and generation checks.
- `cancel`: request cancellation and return sealed partial status.
- `build_index`: warm corpus/function/path snapshots under budget.
- `persist`: save/load/compact ledger records.
- `delete_job`: remove a local job record and releasable chunks.

Every operation returns:

- `job_id`
- `chain_id`
- `operation`
- `accepted`: boolean for the operation request, not the proof verdict
- `status_uri`
- `report_uri` when available
- `next_operations`
- `phase_cursor`

### Tool 2: `chain_verify_query`

Category: `vuln_chain`.

Read-only hint: true.

Operations:

- `schema`: return current chain document and report JSON schemas.
- `corpus`: return current local and peer corpus snapshot summary.
- `status`: return job state, phase, progress, budgets, cancellation state, stale-generation state.
- `list`: list jobs with filters.
- `phase`: inspect phase details and partial artifacts.
- `facts`: query normalized facts by kind, location, link, object, or evidence id.
- `trace`: return paginated trace preview.
- `boundary`: return boundary matrix.
- `explain`: return minimal failure slice.
- `report`: return compact report payload.
- `resources`: return resource manifest for a job.
- `proof_policy`: return acceptance rules and current budget settings.

### Tool 3: `chain_extract_query`

Category: `vuln_chain_extract`.

Read-only hint: true.

Purpose: fact extraction without chain conclusions.

Operations:

- `module_overview`
- `function_facts`
- `function_batch`
- `path_window`
- `xref_reachable_set`
- `type_facts`
- `microcode_facts`
- `cache_status`

This tool is separate from `chain_verify_query` so AI clients can gather evidence without creating a verification job, while still avoiding dozens of extraction tools.

### Resource Templates

MCP resources are first-class, not a secondary export.

Templates:

- `ida://chain/jobs`
- `ida://chain/jobs/{job_id}/status.json`
- `ida://chain/jobs/{job_id}/report.json`
- `ida://chain/jobs/{job_id}/report.md`
- `ida://chain/jobs/{job_id}/trace/{page}.json`
- `ida://chain/jobs/{job_id}/facts/{chunk_id}.json`
- `ida://chain/jobs/{job_id}/boundary/{link_id}.json`
- `ida://chain/jobs/{job_id}/solver/{query_id}.smt2`
- `ida://chain/jobs/{job_id}/evidence/{evidence_id}.json`
- `ida://chain/corpus/{corpus_id}/summary.json`
- `ida://chain/corpus/{corpus_id}/function/{function_id}.json`
- `ida://chain/schema/chain_document_v2.json`
- `ida://chain/schema/report_v2.json`

Each resource includes content id, generation id, corpus digest, byte size, page count, and stale status.

### MCP Phase Requirements

Every engine phase must be:

- invokable: `chain_verify_manage` `start_phase`
- inspectable: `chain_verify_query` `phase`, `facts`, `trace`, `boundary`
- cancellable: `chain_verify_manage` `cancel`
- resumable: `chain_verify_manage` `resume`
- exportable: resource templates plus `chain_verify_query` `resources`

No phase may require a modal IDA UI interaction.

## Report Model

`chain_verification_report_v2` top-level fields:

- `schema`
- `report_id`
- `chain_id`
- `job_id`
- `verdict`
- `acceptance`
- `confidence`
- `proof_level_reached`
- `refutation_level`
- `summary`
- `first_failure`
- `unproven_critical_facts`
- `corpus`
- `phase_status`
- `links`
- `boundaries`
- `objectives`
- `trace_manifest`
- `fact_manifest`
- `solver_manifest`
- `resource_manifest`
- `generation_manifest`
- `budget_manifest`
- `diagnostics`

Per-link report:

- `link_id`
- `role`
- `verdict`
- `proof_level`
- `entry_state_summary`
- `path_corridors`
- `branches`
- `calls`
- `effects`
- `side_effects`
- `postconditions`
- `unproven_facts`
- `refutations`

Boundary report:

- `producer_link`
- `consumer_link`
- `requirements`
- `matches`
- `mismatches`
- `unproven`
- `content_provenance_matrix`
- `lifetime_temporal_matrix`
- `alias_matrix`

Objective report:

- `objective_id`
- `kind`
- `operation_sequence`
- `required_facts`
- `proven_facts`
- `contradictions`
- `collateral_safety`
- `verdict`

Every evidence item:

- `evidence_id`
- `corpus_id`
- `function_id`
- `ea`
- `rva`
- `layer`
- `lineage`: raw instruction, ctree node, microcode instruction, xref edge, type record, dynamic record, or user declaration
- `snippet`: bounded text, never required for machine proof
- `snapshot_id`

## Failure Taxonomy

Machine-readable failure codes:

- `invalid_chain_schema`
- `ambiguous_corpus_binding`
- `missing_corpus`
- `stale_generation`
- `analysis_unsettled`
- `extractor_layer_failed`
- `hexrays_unavailable`
- `microcode_unavailable`
- `unsupported_instruction`
- `unsupported_helper`
- `path_target_unreachable`
- `reachable_set_incomplete`
- `branch_required_direction_unsat`
- `branch_required_direction_unknown`
- `indirect_target_unproven`
- `call_target_mismatch`
- `abi_state_mismatch`
- `register_clobber_unproven`
- `postcondition_precondition_mismatch`
- `content_provenance_mismatch`
- `controlledness_unproven`
- `alias_must_not_proven`
- `self_reference_unproven`
- `lifetime_order_unproven`
- `address_knowledge_gap`
- `allocator_reuse_unproven`
- `callback_registration_unproven`
- `trigger_path_not_reached`
- `protocol_state_mismatch`
- `protocol_length_mismatch`
- `protocol_checksum_mismatch`
- `firmware_dispatch_unproven`
- `collateral_damage_unproven`
- `fatal_side_effect`
- `solver_timeout`
- `solver_unknown`
- `peer_unavailable`
- `resource_exhausted`
- `objective_not_achieved`

Each failure includes `acceptance_blocker: true|false`. Any chain-critical blocker prevents confirmation.

## Universal Regression Suites

The regression suites must not depend on `driver/PROGRESS.md` as the only proof source.

### Suite A: Synthetic Chain Fixtures

1. Three-function controlled copy chain confirms when copied bytes satisfy the final field precondition.
2. Three-function zero-fill chain refutes when zero bytes are consumed as controlled pointers.
3. Hidden branch fixture refutes when a branch before the target requires a self-reference not produced.
4. Self-reference positive fixture confirms only when the pointer slot points to itself before the write-through operation.
5. Register clobber fixture refutes when a volatile register carrying the target is overwritten across a call.

### Suite B: User-Mode Binary Chains

1. EXE input parser to DLL helper to callback sink.
2. COM/vtable indirect call where target is confirmed only from state-proven vtable contents.
3. Auth-state chain where a parser sets a session flag and a later branch consumes it.
4. Heap object UAF in a CRT/custom heap fixture with generic lifetime facts.
5. SEH or signal-handler trigger path with callback dispatch evidence.

### Suite C: Indirect Callback/Event Chains

1. Register callback in module A, store function pointer in object, event loop in module B invokes it.
2. Timer/deferred-work style callback where cancellation removes the callback before invocation.
3. GUI/message-dispatch chain where message ID controls handler target.
4. Destructor/finalizer chain where object cleanup must reach a claimed write.
5. Negative case where registration exists but event root cannot reach invocation.

### Suite D: Allocator-Reuse Chains

1. Address-known-before-fill positive case.
2. Address-discovered-after-fill refutation.
3. Allocator zeroing destroys controlled content.
4. Quarantine prevents immediate reuse.
5. Metadata overwrite corrupts a required field before objective.
6. Custom arena/slab size-class mismatch.

### Suite E: Protocol Parsing Chains

1. Length field controls copy and later parser consumes copied bytes.
2. Endian mismatch refutes claimed value.
3. Checksum requirement blocks arbitrary field value.
4. Decompression transform produces zeros or repeated bytes rather than controlled bytes.
5. State-machine transition missing required prior message.
6. Truncation/saturation refutes oversized write.

### Suite F: Firmware And Low-Level Chains

1. Firmware service table pointer update with exact MMIO/memory-map evidence.
2. Interrupt vector dispatch where handler target is unresolved and cannot confirm.
3. Boot service to runtime service transition with memory descriptor preconditions.
4. MMIO write objective that requires privilege/mode state.
5. Negative case where address range is data but not writable or not mapped.

### Suite G: Missing-Binary And Peer Failure

1. Import target module missing.
2. Callback owner binary missing.
3. Protocol grammar absent.
4. Peer IDA closes mid-job.
5. Stale generation invalidates an otherwise positive partial proof.

Expected result: never confirmed; report must list exact missing evidence and resume path.

### Suite H: Timeout And Unknown

1. Solver timeout on a branch-critical predicate.
2. Alias query unknown on an objective-critical field.
3. Bounded reachable set cut off by depth.
4. Unsupported instruction in a required transfer.
5. Oversized function path window skipped under budget.

Expected result: timeout or inconclusive, not confirmed.

### Suite I: PROGRESS.md Regression Evidence

1. NTFS to ETW bad chain refutes for zero-filled overflow content and missing trigger path.
2. AFD to `_setjmp` bad chain reports hidden `LIST_ENTRY` self-reference and address-knowledge gap.
3. Corrected AFD address-discovery chain can proceed through the hidden check only when address discovery precedes spray/fill.
4. Bad `pvScan0 = gpHandleManager` refutes as objective contradiction.
5. Correct self-referential `pvScan0` confirms pointer redirection only when all preceding facts are proven.

These tests are regression cases, not special-case engine rules.

## Acceptance Criteria

Core acceptance:

1. The engine accepts `aida_chain_document_v2` chain specs for arbitrary binaries and arbitrary link roles without requiring kernel/LPE-specific fields.
2. It verifies chains as one continuous trace with no unowned gap between links.
3. It records branch, call, register, stack, memory, alias, content, lifetime, event, protocol, firmware, and objective facts in one schema.
4. It never reports `confirmed` when any chain-critical fact is unknown, unsupported, timed out, missing, conditional, stale, or unresolved.
5. It reports `refuted` when a critical contradiction is proven.
6. It reports `inconclusive`, `timeout`, or `unsupported` when proof cannot be completed without contradiction.
7. It proves trigger paths generically across API, syscall, IOCTL, callback, event, interrupt, protocol, destructor, and state-machine dispatch.
8. It proves content provenance, not just write size or reachability.
9. It proves final objectives logically, not just intermediate mechanisms.
10. It produces deterministic JSON and resource-backed reports with cited corpus/RVA/evidence ids.

MCP acceptance:

1. `chain_verify_manage`, `chain_verify_query`, and `chain_extract_query` cover all required operations without tool-count explosion.
2. Every phase is invokable, inspectable, cancellable, resumable, and exportable through MCP.
3. Large facts, traces, solver formulas, and reports are exposed through resources with pagination.
4. Cross-IDB jobs use existing `instance_id`/`pid` routing and peer summaries.
5. A disconnected peer yields `peer_unavailable` and a resumable state, not a hung local IDA.

Stability acceptance:

1. IDA remains responsive during deep jobs.
2. No chain verifier progress path uses modal wait boxes, modal warnings, blocking file dialogs, or unbounded `auto_wait()`.
3. Every IDA SDK call occurs in bounded main-thread slices.
4. Raw SDK pointers never escape a slice.
5. IDB and Hex-Rays generation changes prevent stale verdict publication.
6. Cancellation seals partial results and returns the strongest already-proven non-stale result.
7. Worker, solver, extraction, peer, and resource failures affect only the current job or phase.

Regression acceptance:

1. All universal suites A through H pass.
2. PROGRESS suite I passes without hardcoded names, RVAs, structures, or exploit-family logic.
3. Existing tools in `src/vuln/verification_tools.cpp` continue to work unchanged unless explicitly wrapped by the new chain layer.

## Verification Plan

Static verification:

1. Search new verifier files for modal APIs: `show_wait_box`, `hide_wait_box`, `warning(`, `info(`, modal form helpers, and blocking file dialogs. Pass condition: none in verifier execution paths.
2. Search worker code for raw SDK pointer types: `func_t*`, `cfunc_t*`, `mba_t*`, `mblock_t*`, `minsn_t*`, `mop_t*`, `segment_t*`, `TWidget*`, `lvar_t*`. Pass condition: pointer use is confined to IDA slice functions and serialized before return.
3. Audit every IDA SDK call for slice wrapper use and exception containment.
4. Audit cache keys for all generation components.
5. Audit verdict logic so only the P0-P5 complete path can produce `confirmed`.

Schema verification:

1. Valid minimal chain with one corpus, one link, one objective.
2. Invalid missing corpus id.
3. Ambiguous module name with two hashes.
4. Conditional external fact in critical path.
5. Unknown content consumed as controlled.
6. Missing objective.

Engine verification:

1. Unit tests for value lattice joins, disjunction preservation, poison propagation, controlledness, and content provenance.
2. Unit tests for alias facts, self-reference, points-to, must/may/no alias.
3. Unit tests for lifetime and allocator timeline ordering.
4. Unit tests for protocol length/endian/checksum relations.
5. Unit tests for report acceptance rules.

Integration verification:

1. Run extraction query operations against a small user-mode IDB.
2. Run extraction query operations against a driver or large Windows binary IDB.
3. Run a cross-IDB chain with two loaded binaries and exact import/export binding.
4. Cancel during extraction, path search, solver query, peer wait, and report generation.
5. Resume after cancellation with generation unchanged.
6. Trigger stale generation and confirm the job refuses to publish accepted verdict from stale snapshots.
7. Close a peer IDA and confirm resumable `peer_unavailable`.

Regression verification:

1. Run suites A through I.
2. Inspect every non-confirmed report for minimal failure slice and exact acceptance blocker.
3. Inspect every confirmed report for P0-P5 proof completeness and no unproven critical facts.

Build verification:

The implementer host, not a planning subagent, runs the canonical AiDA build wrapper after implementation and verifies zero errors and zero new warnings.

## Exact Implementation Work Packages

### Package A: Universal Schema And Validator

Files:

- `src/vuln/chain_schema.hpp`
- `src/vuln/chain_schema.cpp`
- `src/vuln/chain_facts.hpp`
- `src/vuln/chain_facts.cpp`
- `src/vuln/chain_json.hpp`
- `src/vuln/chain_json.cpp`

Deliverables:

- `aida_chain_document_v2` parser.
- Typed corpus, address, fact, link, event, object, input, objective, and policy models.
- Deterministic ids for facts, links, evidence, snapshots, jobs, and reports.
- Strict validation with stable error codes.
- Conditional fact handling that cannot produce accepted confirmation.
- JSON schema export through `chain_verify_query operation=schema`.

Definition of done:

- Invalid specs fail with exact path and error code.
- Ambiguous corpus bindings fail unless explicitly target-set scoped.
- Unknown/conditional critical facts are represented and block acceptance.

### Package B: IDA Fact Extraction Service

Files:

- `src/vuln/chain_extract.hpp`
- `src/vuln/chain_extract.cpp`
- `src/vuln/chain_snapshots.hpp`
- `src/vuln/chain_snapshots.cpp`
- Updates to `src/vuln/microcode_engine.hpp/.cpp` only for serialized fact export.
- Updates to `src/vuln/cfg_engine.cpp` only for path-window CFG snapshots.

Deliverables:

- Bounded `MFF_READ` extraction slices.
- Module, segment, import/export/entry, function, raw instruction, xref, type, ctree, and microcode snapshots.
- Per-layer status and failure reasons.
- No mutation APIs in extraction.
- `chain_extract_query` tool.

Definition of done:

- Raw extraction works when Hex-Rays is unavailable.
- Hex-Rays failure affects only that function/layer.
- No raw SDK pointer appears in persisted or worker-owned data.

### Package C: Chain State And Transfer Engine

Files:

- `src/vuln/chain_state.hpp`
- `src/vuln/chain_state.cpp`
- `src/vuln/chain_transfer.hpp`
- `src/vuln/chain_transfer.cpp`
- `src/vuln/chain_alias.hpp`
- `src/vuln/chain_alias.cpp`
- `src/vuln/chain_lifetime.hpp`
- `src/vuln/chain_lifetime.cpp`
- `src/vuln/chain_protocol.hpp`
- `src/vuln/chain_protocol.cpp`

Deliverables:

- Immutable `trace_state`.
- Transfer functions for generic operations.
- Content provenance model.
- Alias/self-reference model.
- Allocator/lifetime timeline model.
- Protocol state/content model.
- Poison/fatal side-effect model.

Definition of done:

- Synthetic content, self-reference, clobber, allocator, and protocol tests pass without named case-study logic.

### Package D: Path, Trigger, And Cross-Domain Engine

Files:

- `src/vuln/chain_path.hpp`
- `src/vuln/chain_path.cpp`
- `src/vuln/chain_trigger.hpp`
- `src/vuln/chain_trigger.cpp`
- `src/vuln/chain_cross_domain.hpp`
- `src/vuln/chain_cross_domain.cpp`

Deliverables:

- Path corridor construction.
- Complete bounded reachable-set evidence.
- Generic trigger/event/callback/dispatch verification.
- Cross-binary/cross-domain ABI and message transfer.
- Indirect target proof policy.

Definition of done:

- Trigger absence can be refuted only with complete negative evidence.
- Unresolved indirect target blocks confirmation.
- Cross-IDB missing peer produces resumable gap.

### Package E: Solver And Boundary Engine

Files:

- `src/vuln/chain_solver.hpp`
- `src/vuln/chain_solver.cpp`
- `src/vuln/chain_boundary.hpp`
- `src/vuln/chain_boundary.cpp`
- Reuse `src/vuln/smt_solver.hpp/.cpp` without breaking existing APIs.

Deliverables:

- SMT query builder for branch, alias, value, protocol, and objective facts.
- Query cache with complete generation keys.
- Boundary unification matrix.
- Minimal contradiction extraction.

Definition of done:

- UNKNOWN and timeout never map to confirmed.
- Boundary reports cite producer and consumer facts.
- Solver results are reproducible by query id and formula hash.

### Package F: Job Manager, Cache, And Recovery

Files:

- `src/vuln/chain_job_manager.hpp`
- `src/vuln/chain_job_manager.cpp`
- `src/vuln/chain_cache.hpp`
- `src/vuln/chain_cache.cpp`
- `src/vuln/chain_recovery.hpp`
- `src/vuln/chain_recovery.cpp`
- Updates to `src/aida.hpp/.cpp` for per-IDB verifier context and generation hooks.

Deliverables:

- Per-IDB job registry.
- Bounded queues for IDA slices, CPU work, solver work, and I/O.
- Cancellation, pause, resume, and stale-generation guards.
- Netnode-backed compact ledger.
- Resource-exhaustion behavior.

Definition of done:

- Cancel works in every phase.
- Stale generation prevents accepted verdict publication.
- Interrupted jobs are recoverable or marked sealed with exact reason.

### Package G: MCP Tools And Resources

Files:

- `src/vuln/chain_mcp_tools.hpp`
- `src/vuln/chain_mcp_tools.cpp`
- Updates to `src/agent_tools.cpp/.hpp` for registration and output schemas.
- Updates to `src/mcp_server.cpp` only if dynamic resource templates require server support beyond existing static resources/templates.

Deliverables:

- `chain_verify_manage`
- `chain_verify_query`
- `chain_extract_query`
- Resource templates and paginated resource reads.
- Operation aliases: `action` and `operation`.
- Payload flattening compatible with `sessions_manage`.

Definition of done:

- AI clients can submit, poll, inspect, cancel, resume, and export without learning dozens of tools.
- Every phase has MCP access.
- Large outputs are resource-backed.

### Package H: Report Writer And Optional UI

Files:

- `src/vuln/chain_report.hpp`
- `src/vuln/chain_report.cpp`
- `src/vuln/chain_report_view.hpp`
- `src/vuln/chain_report_view.cpp`

Deliverables:

- `chain_verification_report_v2` JSON writer.
- Markdown summary writer.
- Minimal failure slice.
- Optional modeless report view that reads completed ledgers and jumps to evidence addresses.

Definition of done:

- UI never starts heavy verification synchronously.
- Report view is optional and modeless.
- MCP report output is sufficient without UI.

### Package I: Regression Fixtures And Tests

Files:

- `src/vuln/tests/chain_schema_tests.cpp`
- `src/vuln/tests/chain_state_tests.cpp`
- `src/vuln/tests/chain_solver_tests.cpp`
- `src/vuln/tests/chain_regression_specs/*.json`
- Test fixture sources or recorded snapshots under an approved test fixture directory.

Deliverables:

- Suites A through I encoded as specs and fixtures.
- Deterministic expected verdicts and failure codes.
- Recorded snapshots for tests that cannot depend on live IDA in unit mode.
- IDA integration tests for extraction and MCP behavior where available.

Definition of done:

- PROGRESS regressions pass as ordinary specs.
- Universal suites pass without case-name special handling.
- Timeout/unknown tests prove non-confirmation.

## Implementation Order

1. Package A.
2. Package B raw/module/xref extraction.
3. Package F minimal job registry and cache scaffolding.
4. Package G query-only schema/corpus/status operations.
5. Package C value/content/alias/lifetime state.
6. Package D path corridors and trigger verification.
7. Package E boundary and solver integration.
8. Package G full manage/query/resource operations.
9. Package H reports.
10. Package I regression fixtures.
11. Integrate optional modeless UI after MCP and report behavior are stable.

Each package lands with source-level tests or recorded-fixture tests for its contract. No package may weaken existing `src/vuln/verification_tools.cpp` behavior.

## Non-Goals And Boundaries

1. No first implementation package touches `server/`, `driver/`, `mapper/`, `tools/protector/`, encrypted generated headers, or standalone UI code.
2. The chain verifier does not run exploits, install drivers, deploy server files, or mutate target binaries.
3. The verifier does not treat public exploit-family names as proof.
4. The verifier does not hide assumptions behind friendly wording.
5. The verifier does not convert dynamic or user-declared evidence into accepted proof unless the policy explicitly allows recorded evidence and all recorded evidence is bound to corpus identity and state.

## Final Rule Set

1. Universal facts, not exploit-family branches.
2. Continuous trace, not isolated links.
3. Proven content, not write-size guesses.
4. Proven trigger reachability, not lifecycle assumptions.
5. Proven target state, not mechanical mechanism presence.
6. Proven temporal order, not plausible ordering.
7. Proven exact or bounded negative evidence, not absence of text.
8. Unknown never confirms.
9. Conditional never accepts.
10. Every accepted chain cites every critical fact.
