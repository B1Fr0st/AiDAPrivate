# Existing Plugin Audit And Work Breakdown: Multi-Binary Chain Verification

Date: 2026-07-03

This plan is an investigation deliverable only. It does not change plugin behavior, does not build AiDA, and does not deploy anything. The implementation target is a production-grade IDA Pro plugin capability that verifies complete multi-binary vulnerability chains rather than scoring isolated primitives.

## Mandatory Evidence From driver/PROGRESS.md

The critical section begins at `driver/PROGRESS.md:2229` under `Chain Verification Failures - Case Studies for Automated Verification Plugin`. The section explains why per-link analysis is insufficient:

- Case 1, `driver/PROGRESS.md:2260-2311`: NTFS compression overflow to ETW LIST_ENTRY looked plausible link-by-link, but the overflow produced zeros rather than controlled bytes, and the assumed ETW stop trigger did not call `RemoveEntryList`. The verifier must compare postcondition data content against the next link precondition and must confirm the trigger path actually reaches the claimed mutator.
- Case 2, `driver/PROGRESS.md:2312-2379`: AFD UAF to `_setjmp` missed a `LIST_ENTRY` self-reference check in `AfdCloseConnection` before the indirect call. The verifier must trace the whole path from entry to indirect call and surface hidden branch requirements, not only validate the terminal gadget.
- Case 3, `driver/PROGRESS.md:2381-2427`: setting `pvScan0 = gpHandleManager` was logically wrong because `SetBitmapBits` writes to `[pvScan0]`, so it writes to `gpHandleManager` and does not modify `pvScan0`. The verifier must prove logical data flow, including self-referential state, not just mechanical "uses pvScan0" facts.

The required plugin properties are explicit at `driver/PROGRESS.md:2440-2468`: end-to-end execution path tracing across binaries, branch satisfiability across the whole path, cross-link postcondition/precondition matching, intermediate side-effect detection, register state tracking across calls, logical data-flow verification, and trigger path confirmation. The required input/output shape is documented at `driver/PROGRESS.md:2470-2493`.

## Current-State Findings

### Build Boundary

The IDA plugin is the `AiDA` shared library, not the standalone IDE. `CMakeLists.txt:573` enables `BUILD_AIDA_PLUGIN` by default. `CMakeLists.txt:2588-2612` declares the plugin source set, including `src/actions.cpp`, `src/agent_tools.cpp`, `src/aida.cpp`, `src/aida_ipc.cpp`, `src/graphrag.cpp`, `src/ida_utils.cpp`, `src/instance_registry.cpp`, `src/license.cpp`, `src/mcp_server.cpp`, `src/settings.cpp`, `src/driver_loader.cpp`, the `src/vuln/*` engines, and `driver/comm.cpp`. `CMakeLists.txt:2667` builds `add_library(AiDA SHARED ...)`; `CMakeLists.txt:2678` sets output name `AiDA`; `CMakeLists.txt:2706-2720` includes the IDA SDK and defines `__EA64__`; `CMakeLists.txt:2749-2752` links the IDA import library plus Zydis, Unicorn, Triton, and Z3.

New chain verification code should live under `src/vuln/` and integrate through existing tool registration. It should not require changes to `server/`, the driver stack, or the standalone IDE for the first production iteration.

### Plugin Lifecycle And UI Surface

`src/aida.hpp:27-49` defines `aida_plugin_t : public plugmod_t` with MCP, action, and operational lifecycle methods. `src/aida.cpp:616-633` shows a modal EULA path using `ask_yn`. `src/aida.cpp:637-680` hooks `ui_finish_populating_widget_popup` and attaches actions into IDA popups. `src/aida.cpp:772-928` is the operational startup path: it verifies the standalone runtime, loads settings, handles EULA, initializes anti-re state, starts watchdog and tamper monitors, loads `AnalysisDB`, registers agent tools, forces MCP enabled, starts MCP, installs Hex-Rays fixups, hooks UI, registers the self-watchdog timer, and starts GraphRAG work. `src/aida.cpp:968-1000` tears those systems down.

Existing visible actions are narrow: `src/aida.cpp:1051-1094` registers/unregisters actions, and `src/actions.cpp:144-312` implements copy context, save database context, and fix analysis. `src/actions.cpp:173-300` exports database context with `ask_file`, `show_wait_box`, a full function loop, and `hide_wait_box`.

### MCP And Tool Surface

`src/mcp_server.hpp:14-36` exposes `mcp_server_t` with start/stop, port discovery, client config writing, a server thread, and registry reference. `src/mcp_server.cpp:1166-1216` dispatches each tool through `execute_tool_in_main_thread`, selecting `MFF_READ` or `MFF_WRITE` from the tool metadata before calling `execute_sync`. `src/mcp_server.cpp:1322-1342` has parallel batch execution for read-only calls and displays a wait box. `src/mcp_server.cpp:1928-1966` handles MCP `tools/call`. `src/mcp_server.cpp:2528-2530` uses `std::async` for async tool calls, but each task still routes into `execute_tool_in_main_thread`. `src/mcp_server.cpp:4252` writes client config files.

`src/agent_tools.hpp:66-103` defines `tool_definition_t`. `src/agent_tools.cpp:82-128` validates metadata, including read-only/destructive consistency. `src/agent_tools.cpp:240-287` executes registered handlers and enforces the self-target guard. `src/agent_tools.cpp:12525-12553` registers the full tool catalog, including base vuln tools, advanced vuln workflows, verification tools, batch tools, meta tools, and extension tools.

The chain verifier should be exposed primarily as MCP tools and resources. It should avoid modal UI and should not depend on `execute_python` (`src/agent_tools.cpp:3517-3600`) for core analysis.

### Analysis And Session Persistence

`src/analysis_db.hpp:107-310` provides an in-process JSON database with dirty tracking. It stores RLHF, chat, analysis entries, binary fingerprints, and capability flags. `src/analysis_db.hpp:318-396` saves and loads under the user IDA directory. `src/settings.cpp:606-611` persists settings. `src/graphrag.cpp` and `src/ida_utils.cpp` use IDA netnodes and `aida_db` files for graph, vector, RAG, and IDB-local cache state.

Chain verification should add a separate durable chain ledger under `src/vuln/` rather than mixing large chain proof artifacts into the generic chat/analysis DB. The ledger should store compact chain specs, binary identities, job state, verdicts, branch obligations, link-boundary mismatches, trigger evidence, and report references.

### Existing Vulnerability Engines

The current vulnerability layer is substantial but local. `src/vuln/verification_engine.hpp:144-190` exposes taint path verification, exploit input solving, path satisfiability, sink triage, verified ledger operations, wire path extraction, and payload synthesis. Implementations are in `src/vuln/verification_engine.cpp:618-1589`; MCP handlers and registrations are in `src/vuln/verification_tools.cpp:184-825`.

Advanced workflows already enumerate attack surfaces and explain source-to-sink chains inside the current IDB: `src/vuln/surface_engine.cpp:2142-2464` implements IPC endpoint enumeration, pre-auth handler discovery, reachable sink enumeration, indirect call target resolution, `explain_vulnerability_chain_v2`, remote RCE hunting, and attack-surface ranking. These tools are registered at `src/vuln/surface_engine.cpp:4798-4897`.

The gap is multi-binary chain correctness. Existing tools can verify a path or rank candidates inside one database, but they do not model a chain spec across several binaries, prove that each link's postcondition satisfies the next link's precondition, track call-boundary state across binaries, prove trigger reachability, or refute logical data-flow contradictions like the `pvScan0` self-reference case.

## Risk Map

| Risk Area | Current Evidence | Production Requirement |
|---|---|---|
| Modal startup/UI blocking | `src/aida.cpp:616-633` uses `ask_yn`; `src/actions.cpp:173-300` uses `ask_file` and wait box export. | Chain verification must be MCP/job-driven and non-modal. Any optional UI must be a report viewer or chooser after results exist. |
| Wait-box imbalance and disabled UI | `src/actions.cpp:190-300`, `src/mcp_server.cpp:563`, and `src/mcp_server.cpp:1342` use wait boxes around long operations. | Long chain verification must not depend on wait boxes. If UI progress is later added, every wait-box path must be RAII-balanced and cancellable. |
| Main-thread contention | `src/mcp_server.cpp:1207`, `1489`, `1496`, `1966`, `2147`, `2215`, `2248`, and `3055` call `execute_sync`. | Snapshot IDA state on the main thread, then solve/analyze off-thread. Keep `execute_sync` windows small and bounded. |
| Async illusion | `src/mcp_server.cpp:2528-2530` uses `std::async`, but the handler still enters `execute_tool_in_main_thread`. | Async chain jobs must separate IDA snapshot collection from worker-side SMT/state evaluation. |
| Decompiler/microcode failures | Current engines depend on Hex-Rays microcode and decompilation. | Every path proof must record microcode maturity, failure reason, and fallback evidence rather than silently degrading to a pass. |
| Multi-binary identity | Existing engines assume the active IDB address space. | Every chain address must resolve through a binary identity: module name, hash, image base, RVA, IDB path, function identity, and confidence. |
| False positive chain verdicts | PROGRESS case studies show per-link passes that are globally false. | Verdicts must be `verified`, `refuted`, or `inconclusive` with explicit blocking evidence. Unknown cannot satisfy a link boundary. |
| Security boundary | MCP tools include mutating and Python execution surfaces. | Chain verification tools must validate input schema, cap costs, honor cancellation, avoid arbitrary code execution, and preserve fail-closed license/anti-tamper behavior. |

## IDA SDK API Evidence And Recommendations

All SDK evidence below is from `ida-sdk/src/include`, which is the API source of truth for this repository.

### E1: Main-Thread Execution

`ida-sdk/src/include/kernwin.hpp:4437-4456`:

```cpp
#define MFF_FAST   0x0000       ///< Execute code as soon as possible.
#define MFF_READ   0x0001       ///< Execute code only when ida is idle and it is safe
                                ///< to query the database.
#define MFF_WRITE  0x0002       ///< Execute code only when ida is idle and it is safe
                                ///< to modify the database.
                                ///< #MFF_WRITE implies #MFF_READ
#define MFF_NOWAIT 0x0004       ///< Do not wait for the request to be executed.
```

`ida-sdk/src/include/kernwin.hpp:4468-4486`:

```cpp
/// Execute code in the main thread - to be used with execute_sync().
struct exec_request_t
{
  /// Callback to be executed.
  /// If this function raises an exception, execute_sync() never returns.
  virtual ssize_t idaapi execute() = 0;
```

`ida-sdk/src/include/kernwin.hpp:5080-5086`:

```cpp
/// Execute code in the main thread.
/// \param req   request specifying the code to execute
/// \param reqf  \ref MFF_
THREAD_SAFE inline ssize_t execute_sync(exec_request_t &req, int reqf) { return callui(ui_execute_sync, &req, reqf).ssize; }
```

Recommendation: collect IDA database facts with bounded `MFF_READ` snapshots, reserve `MFF_WRITE` only for explicit user-approved mutations, and catch all exceptions inside `exec_request_t::execute()` handlers because the SDK warns that an exception can make `execute_sync()` never return.

### E2: Actions And Popups

`ida-sdk/src/include/kernwin.hpp:5208-5222`:

```cpp
/// Create a new action (::ui_register_action).
/// After an action has been created, it is possible to attach it
/// to menu items (attach_action_to_menu()), or to popup menus
/// (attach_action_to_popup()).
inline bool register_action(const action_desc_t &desc)
```

`ida-sdk/src/include/kernwin.hpp:5314-5335`:

```cpp
/// Attach a previously-registered action to the menu (::ui_attach_action_to_menu).
inline bool attach_action_to_menu(
        const char *menupath,
        const char *name,
        int flags=0)
```

`ida-sdk/src/include/kernwin.hpp:5635-5656`:

```cpp
/// Insert a previously-registered action into the widget's popup menu (::ui_attach_action_to_popup).
inline bool attach_action_to_popup(
        TWidget *widget,
        TPopupMenu *popup_handle,
        const char *name,
```

Recommendation: if a chain UI is added, register one action that opens a non-modal report surface after a completed MCP job. Do not start heavyweight verification from popup activation.

### E3: Modal Dialogs And File Prompts

`ida-sdk/src/include/kernwin.hpp:7836-7848`:

```cpp
/// Display a dialog box and get choice from "Yes", "No", "Cancel".
/// \return the selected button (one of \ref ASKBTN_). Esc key returns #ASKBTN_CANCEL.
AS_PRINTF(2, 3) inline int ask_yn(int deflt, const char *format, ...)
```

`ida-sdk/src/include/kernwin.hpp:8060-8100`:

```cpp
/// Display a dialog box and wait for the user to input a file name (::ui_ask_file).
/// \return nullptr     the user cancelled the dialog.
/// Otherwise the user entered a valid file name.
AS_PRINTF(3, 4) inline char *ask_file(
        bool for_saving,
```

Recommendation: chain verification tools must not call `ask_yn`, `ask_file`, or equivalent blocking prompt APIs. MCP requests should provide all paths and options in structured JSON.

### E4: Wait Boxes

`ida-sdk/src/include/kernwin.hpp:6996-7006`:

```cpp
/// Plugins must call hide_wait_box() to close the dialog box, otherwise
/// the user interface will remain disabled.
/// This implies that a plugin should call hide_wait_box() exactly as many
/// times as it called show_wait_box(), or the wait dialog might remain
/// visible and block the UI.
```

`ida-sdk/src/include/kernwin.hpp:7010-7024`:

```cpp
THREAD_SAFE AS_PRINTF(1, 2) inline void show_wait_box(const char *format, ...)
THREAD_SAFE inline void hide_wait_box()
```

Recommendation: chain verification progress should be exposed through MCP job state and resources. Any future visual progress must use a strict scoped guard around `show_wait_box` and must not cover solver or cross-binary worker time.

### E5: Non-Modal Choosers

`ida-sdk/src/include/kernwin.hpp:2978-2979`:

```cpp
/// Modal chooser
#define CH_MODAL          0x00000001
```

`ida-sdk/src/include/kernwin.hpp:3486-3518`:

```cpp
/// The chooser object without multi-selection.
struct chooser_t : public chooser_base_t
{
  /// Display a generic list chooser and allow the user to select an item.
  inline ssize_t choose(ssize_t deflt = 0);
```

Recommendation: a result browser should avoid `CH_MODAL` and should not own the verification run. It may render completed chain verdicts and jump to evidence addresses.

### E6: IDA Threads, Semaphores, And Locks

`ida-sdk/src/include/pro.h:5475-5539`:

```cpp
idaman THREAD_SAFE qthread_t ida_export qthread_create(qthread_cb_t *thread_cb, void *ud);
idaman THREAD_SAFE bool ida_export qthread_join(qthread_t q);
idaman THREAD_SAFE qsemaphore_t ida_export qsem_create(const char *name, int init_count);
idaman THREAD_SAFE bool ida_export qsem_wait(qsemaphore_t sem, int timeout_ms);
idaman THREAD_SAFE qmutex_t ida_export qmutex_create(void);
```

Recommendation: long-running analysis should use explicit job objects with cancellation and bounded joins. Off-thread work must consume immutable snapshots and must not call IDA database APIs directly unless routed through bounded `execute_sync`.

### E7: Function, Instruction, Call, And Return Enumeration

`ida-sdk/src/include/funcs.hpp:289-327`:

```cpp
/// \param ea  any address in a function
/// \return ptr to a function or nullptr.
idaman func_t *ida_export get_func(ea_t ea);
idaman size_t ida_export get_func_qty(void);
```

`ida-sdk/src/include/ua.hpp:1505-1509`:

```cpp
/// \param out  the resulting instruction
/// \param ea  linear address
/// \return the length of the (possible) instruction or 0
idaman int ida_export decode_insn(insn_t *out, ea_t ea);
```

`ida-sdk/src/include/idp.hpp:144-159`:

```cpp
/// Is the instruction a "call"?
idaman bool ida_export is_call_insn(const insn_t &insn);
/// Is the instruction a "return"?
idaman bool ida_export is_ret_insn(const insn_t &insn, uchar flags=IRI_STRICT);
```

Recommendation: path tracing must anchor every link to a real `func_t`, decode control-transfer instructions, and classify calls/returns through the processor module helpers rather than string matching disassembly.

### E8: CFG And Xrefs

`ida-sdk/src/include/gdl.hpp:441-461`:

```cpp
/// A flow chart for a function, or a set of address ranges
class qflow_chart_t : public cancellable_graph_t
{
  qstring title;
  range_t bounds;
  func_t *pfn = nullptr;
  blocks_t blocks;
  void idaapi create(const char *_title, func_t *_pfn, ea_t _ea1, ea_t _ea2, int _flags)
```

`ida-sdk/src/include/xref.hpp:170-194`:

```cpp
/// Structure to enumerate all xrefs.
/// This structure provides a way to access cross-references from a given address.
/// You may not modify the contents of a xrefblk_t structure! It is read only.
```

`ida-sdk/src/include/xref.hpp:228-241`:

```cpp
bool first_from(ea_t _from, int flags=XREF_FLOW)
bool next_from()
bool first_to(ea_t _to, int flags=XREF_FLOW)
bool next_to()
```

Recommendation: intraprocedural paths should use `qflow_chart_t`; call graph and trigger discovery should use read-only `xrefblk_t` enumeration. Results must record the exact block, xref, and edge evidence used.

### E9: Hex-Rays Microcode And Side Effects

`ida-sdk/src/include/hexrays.hpp:4903-4907`:

```cpp
/// Array of micro blocks representing microcode for a decompiled function.
/// The first micro block is the entry point, the last one is the exit point.
class mba_t
```

`ida-sdk/src/include/hexrays.hpp:7767-7771`:

```cpp
mba_t *hexapi gen_microcode(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        const mlist_t *retlist=nullptr,
```

`ida-sdk/src/include/hexrays.hpp:3867-3931`:

```cpp
/// Does the instruction have a side effect?
bool hexapi has_side_effects(bool include_ldx_and_divs=false) const;
/// Does the instruction modify its 'd' operand?
bool hexapi modifies_d() const;
/// Is it possible for the instruction to use aliased memory?
bool hexapi may_use_aliased_memory() const;
```

`ida-sdk/src/include/hexrays.hpp:4469-4487`:

```cpp
/// Build use-list of an instruction.
mlist_t hexapi build_use_list(const minsn_t &ins, maymust_t maymust) const;
/// Build def-list of an instruction.
mlist_t hexapi build_def_list(const minsn_t &ins, maymust_t maymust) const;
```

`ida-sdk/src/include/hexrays.hpp:4539-4587`:

```cpp
/// Find the first insn that redefines any part of the list in the insn range.
const minsn_t *hexapi find_redefinition(...);
/// \return the instruction that accesses the operand.
minsn_t *hexapi find_access(...);
```

Recommendation: side-effect detection, data-content proof, register state tracking, and hidden intermediate checks should use microcode where available. The verifier must treat microcode generation failure as explicit evidence, not as a successful proof.

### E10: IDB-Local Persistence

`ida-sdk/src/include/netnode.hpp:285-293`:

```cpp
/// Create a named netnode.
/// \param _name   name of netnode to create.
///                names of user-defined netnodes must have the "$ " prefix
bool create(const char *_name, size_t namlen=0)
```

`ida-sdk/src/include/netnode.hpp:942-1018`:

```cpp
/// Get blob from a netnode.
void *getblob(...)
/// Store a blob in a netnode.
bool setblob(
        const void *buf,
        size_t size,
```

Recommendation: use netnodes only for IDB-local anchors and lightweight per-IDB state. Store complete multi-binary chain ledgers in a versioned JSON file under AiDA's `aida_db` directory so the ledger can reference several IDBs at once.

## Target Capability

The chain verifier must accept a structured chain spec with:

- Chain identity: name, author, created time, threat model, target OS/build, expected privilege transition, and evidence policy.
- Binary corpus: one or more binaries with module name, image hash, IDB path, image base, pointer size, PDB/type provenance, and exported/imported symbol map.
- Links: binary/function/RVA entry, claimed source event, entry preconditions, branch obligations, register/memory/object state, claimed behavior, exit postconditions, side-effect exclusions, and trigger assumptions.
- Link-pair contracts: exact matching rules between a previous postcondition and the next precondition, including data content, address identity, alias identity, lifetime, control authority, and timing.
- Full-chain objective: final primitive or exploit state, required trigger path, forbidden side effects, and confidence policy.

The output must include:

- Per-link verdict with path evidence, branch constraints, side effects, register facts, memory facts, unresolved assumptions, and proof cost.
- Per-boundary verdict showing exact postcondition/precondition matches or mismatches.
- Full-chain verdict with a minimal refutation when broken, or a complete evidence path when verified.
- Machine-readable proof ledger and human-readable report.

Verdict semantics:

- `verified`: all required paths, branches, side effects, and link contracts are proven with current evidence.
- `refuted`: evidence proves a required contract or trigger is impossible or contradicted.
- `inconclusive`: evidence is missing, analysis failed, or cost limits were reached. This state never satisfies a downstream link.

## Proposed Architecture

All new implementation files should live under `src/vuln/` unless explicitly called out.

| Module | New Files | Responsibility |
|---|---|---|
| Chain model | `src/vuln/chain_model.hpp`, `src/vuln/chain_model.cpp` | Versioned JSON schema, typed chain spec, facts, contracts, verdicts, diagnostics, and stable serialization. |
| Chain store | `src/vuln/chain_store.hpp`, `src/vuln/chain_store.cpp` | Durable ledger under `aida_db`, atomic save/load, compact job/result indexing, schema migration, IDB netnode anchors when needed. |
| Binary corpus | `src/vuln/chain_binary_corpus.hpp`, `src/vuln/chain_binary_corpus.cpp` | Multi-binary identity, RVA/EA mapping, module hash validation, import/export/symbol correlation, active-IDB inventory snapshots. |
| Path tracing | `src/vuln/chain_path_trace.hpp`, `src/vuln/chain_path_trace.cpp` | Entry-to-target path enumeration, call-boundary summaries, CFG evidence, xref evidence, branch obligation extraction, microcode failure reporting. |
| State contracts | `src/vuln/chain_state_contracts.hpp`, `src/vuln/chain_state_contracts.cpp` | Pre/postcondition language, memory/register/object fact lattice, alias identity, data-content matching, SAT integration, logical self-reference checks. |
| Side effects | `src/vuln/chain_side_effects.hpp`, `src/vuln/chain_side_effects.cpp` | Intermediate checks, writes, calls, aliasing hazards, hidden branch requirements, object lifetime effects, forbidden clobbers. |
| Trigger tracing | `src/vuln/chain_trigger_trace.hpp`, `src/vuln/chain_trigger_trace.cpp` | Confirmation that claimed external/internal triggers reach the required mutator or call site. |
| Orchestrator | `src/vuln/chain_verification_engine.hpp`, `src/vuln/chain_verification_engine.cpp` | Job lifecycle, cancellation, progress, phase scheduling, result aggregation, bounded main-thread snapshots, worker-side solving. |
| MCP tools | `src/vuln/chain_verification_tools.hpp`, `src/vuln/chain_verification_tools.cpp` | Tool schemas and handlers for submit/get/list/cancel/export, plus report resources. |
| Optional report UI | `src/vuln/chain_report_view.hpp`, `src/vuln/chain_report_view.cpp` | Non-modal completed-result browser and evidence jumps. This is deferred until MCP verification is stable. |

Integration files:

- `src/agent_tools.cpp`: add a single registration call in `initialize_all_tools`.
- `src/vuln/vuln_tools.hpp`: expose only the registration declaration if needed.
- `CMakeLists.txt`: add new source/header files to the `AiDA` plugin target.

No first-pass changes should be made to `server/`, `driver/`, `mapper/`, `tools/protector/`, or `src/standalone/`.

## Implementation Phases

### Phase 1: Chain Schema, Corpus Inventory, And Ledger

Implement `chain_model`, `chain_store`, and `chain_binary_corpus`. Add JSON validation with strict required fields and deterministic error envelopes. Add binary identity snapshots for the active IDB: module path, input file path when available, image base, image size, pointer size, function count, hash/fingerprint reuse from existing binary tools where possible, imports, exports, and selected symbol names.

Acceptance:

- Invalid chain specs fail closed with precise schema errors.
- A chain spec can reference several binaries even when only one IDB is active; inactive binaries are reported as missing evidence, not ignored.
- Ledger save/load round-trips chain specs and empty result records without data loss.
- No modal dialogs or user prompts are introduced.

### Phase 2: Per-Link Path Snapshot And Branch Obligations

Implement `chain_path_trace` using existing `cfg_engine`, `symbolic_engine`, microcode helpers, `qflow_chart_t`, xrefs, `decode_insn`, and call/return helpers. Produce immutable path snapshots for a link: entry, target, basic blocks, branch EAs, branch predicates, calls, returns, xrefs, and unresolved indirect calls.

Acceptance:

- A link path report identifies every branch between entry and target or states exactly why enumeration stopped.
- Hidden checks like the AFD `LIST_ENTRY` self-reference gate are surfaced as branch obligations, not omitted.
- `execute_sync` is used only to collect IDA facts; solver/path ranking runs off-thread.
- Microcode and decompiler failures are preserved in diagnostics.

### Phase 3: State Fact Lattice And Side-Effect Extraction

Implement `chain_state_contracts` and `chain_side_effects`. Use microcode use/def lists, side-effect flags, alias indicators, stack/register summaries, and known call effects to extract writes, reads, clobbers, object lifetime changes, and branch preconditions along a path.

Acceptance:

- The engine distinguishes controlled bytes, zero-filled bytes, copied bytes, unknown bytes, pointer identity, and self-referential pointer facts.
- The NTFS case can represent "overflow writes zeros" and reject a next-link precondition requiring controlled `Flink/Blink`.
- The AFD case can represent a required self-referencing `LIST_ENTRY` fact before `_setjmp`.
- The `pvScan0` case can prove that `pvScan0 = gpHandleManager` does not update `pvScan0` through `SetBitmapBits`.

### Phase 4: Cross-Link Contract Checker

Implement link-pair verification inside `chain_state_contracts` and orchestrate it from `chain_verification_engine`. Compare each link's postconditions against the next link's preconditions by identity, value, content, alias set, object lifetime, timing, and required control.

Acceptance:

- Each boundary produces `matched`, `mismatched`, or `missing_evidence` entries.
- A mismatch points to the exact fact names and evidence addresses.
- Unknown facts cannot be coerced into matches.
- The minimal refutation path is stable and deterministic.

### Phase 5: Multi-Binary Resolution

Extend `chain_binary_corpus` and `chain_path_trace` so a chain can bind functions and facts across modules by binary identity, RVA, symbol, import/export, and user-supplied alias relationships. The active IDB provides local evidence; inactive binaries remain explicit dependencies.

Acceptance:

- A chain referencing `afd.sys`, `ntoskrnl.exe`, `win32kbase.sys`, and related modules can be loaded as a single chain spec.
- The verifier resolves active-IDB RVAs to EAs and records image-base assumptions.
- Cross-binary calls are represented as contracts when the callee IDB is not active and as path obligations when evidence is available.
- Binary hash or image mismatch invalidates affected evidence.

### Phase 6: Trigger Path Confirmation

Implement `chain_trigger_trace`. Trace claimed triggers from named APIs, IOCTL handlers, callbacks, dispatch tables, ETW/session lifecycle paths, or xref roots to the claimed mutator/call site.

Acceptance:

- A trigger assumption must become either a confirmed path, a refuted path, or an inconclusive dependency.
- The NTFS/ETW case refutes "ETW stop calls RemoveEntryList" if no path reaches that mutator.
- Trigger traces include xref roots, call chain, unresolved indirect edges, and branch blockers.

### Phase 7: Job Orchestration, MCP Tools, And Reports

Implement `chain_verification_engine` and `chain_verification_tools`. Register MCP tools:

- `chain_verify_submit`: validate spec, create job, optionally start analysis.
- `chain_verify_get`: get job status, phase progress, and partial results.
- `chain_verify_list`: list ledger jobs/results with filters.
- `chain_verify_cancel`: request cancellation and return final cancellation state.
- `chain_verify_export`: return machine-readable ledger or human-readable report.
- `chain_corpus_snapshot`: return active IDB binary identity and available evidence.

Acceptance:

- All tools have strict JSON schemas, bounded inputs, and deterministic errors.
- Long work is cancellable and progress is persisted.
- No tool starts a modal dialog or long UI wait.
- Re-running the same completed job reuses stable ledger records unless input evidence changed.

### Phase 8: Optional Non-Modal Report UI

Add `chain_report_view` only after MCP and ledger behavior are stable. The UI should list completed jobs, verdicts, link failures, and evidence addresses. It can jump to addresses in the active IDB but must not start verification.

Acceptance:

- The report view is non-modal.
- It never blocks on solver work.
- It handles missing/inactive binaries explicitly.

### Phase 9: Regression Fixtures And Evidence Tests

Create focused test specs for the three PROGRESS case studies and minimal synthetic chains. Tests should exercise model validation, contract matching, trigger confirmation, and deterministic report generation. IDA-dependent behavior should be verified with controlled IDBs or recorded snapshots where possible.

Acceptance:

- NTFS to ETW is refuted for data-content mismatch and missing trigger.
- AFD to `_setjmp` reports the hidden LIST_ENTRY branch obligation.
- Incorrect `pvScan0 = gpHandleManager` is refuted; self-referencing `pvScan0` is accepted only when the required pointer identity fact is proven.
- A successful simple chain produces per-link, boundary, and full-chain evidence.

## Disjoint Subagent Work Packages

All implementer subagents must not build. The host AI builds only after implementation review.

### Package A: Model And Store

Owned files:

- `src/vuln/chain_model.hpp`
- `src/vuln/chain_model.cpp`
- `src/vuln/chain_store.hpp`
- `src/vuln/chain_store.cpp`

Read-only context:

- `src/analysis_db.hpp`
- `src/settings.cpp`
- `src/ida_utils.cpp`
- `src/graphrag.cpp`
- `ida-sdk/src/include/netnode.hpp`

Deliverable: complete chain schema, typed facts/contracts/verdicts, strict JSON parsing, deterministic serialization, ledger persistence, and schema migration behavior.

### Package B: Binary Corpus Resolver

Owned files:

- `src/vuln/chain_binary_corpus.hpp`
- `src/vuln/chain_binary_corpus.cpp`

Read-only context:

- `src/agent_tools.cpp` binary/import/export tools
- `src/ida_utils.cpp`
- `src/vuln/vuln_common.hpp`
- `ida-sdk/src/include/funcs.hpp`
- `ida-sdk/src/include/xref.hpp`

Deliverable: active-IDB snapshot, module/RVA/EA mapping, import/export/symbol correlation, binary identity matching, and missing-evidence diagnostics.

### Package C: Path Trace Engine

Owned files:

- `src/vuln/chain_path_trace.hpp`
- `src/vuln/chain_path_trace.cpp`

Read-only context:

- `src/vuln/cfg_engine.cpp`
- `src/vuln/symbolic_engine.cpp`
- `src/vuln/microcode_engine.cpp`
- `ida-sdk/src/include/gdl.hpp`
- `ida-sdk/src/include/ua.hpp`
- `ida-sdk/src/include/idp.hpp`
- `ida-sdk/src/include/hexrays.hpp`

Deliverable: per-link path snapshots, CFG edges, branch obligations, call/return summaries, xref roots, unresolved indirect-call diagnostics, and bounded IDA main-thread fact capture.

### Package D: State Contracts And Side Effects

Owned files:

- `src/vuln/chain_state_contracts.hpp`
- `src/vuln/chain_state_contracts.cpp`
- `src/vuln/chain_side_effects.hpp`
- `src/vuln/chain_side_effects.cpp`

Read-only context:

- `src/vuln/taint_engine.cpp`
- `src/vuln/smt_solver.cpp`
- `src/vuln/symbolic_engine.cpp`
- `src/vuln/verification_engine.cpp`
- `ida-sdk/src/include/hexrays.hpp`

Deliverable: fact lattice, data-content proof, alias identity, register/memory/object state summaries, side-effect extraction, hidden-check detection, link-boundary matcher, and deterministic refutation reasons.

### Package E: Trigger Trace Engine

Owned files:

- `src/vuln/chain_trigger_trace.hpp`
- `src/vuln/chain_trigger_trace.cpp`

Read-only context:

- `src/vuln/surface_engine.cpp`
- `src/vuln/cfg_engine.cpp`
- `src/vuln/vuln_callsites.cpp`
- `ida-sdk/src/include/xref.hpp`
- `ida-sdk/src/include/gdl.hpp`

Deliverable: trigger-root discovery, trigger-to-mutator path tracing, branch blockers, unresolved indirect edge reporting, and trigger-specific verdicts.

### Package F: Orchestrator, MCP Tools, And Build Integration

Owned files:

- `src/vuln/chain_verification_engine.hpp`
- `src/vuln/chain_verification_engine.cpp`
- `src/vuln/chain_verification_tools.hpp`
- `src/vuln/chain_verification_tools.cpp`
- `src/agent_tools.cpp`
- `src/vuln/vuln_tools.hpp`
- `CMakeLists.txt`

Read-only context:

- `src/mcp_server.cpp`
- `src/agent_tools.hpp`
- `src/vuln/verification_tools.cpp`
- `src/vuln/verification_engine.hpp`
- `ida-sdk/src/include/kernwin.hpp`
- `ida-sdk/src/include/pro.h`

Deliverable: job lifecycle, cancellation, progress, MCP schemas/handlers, tool registration, source/header integration into the AiDA target, and bounded main-thread snapshot scheduling.

### Package G: Optional Report UI

Owned files:

- `src/vuln/chain_report_view.hpp`
- `src/vuln/chain_report_view.cpp`
- `src/aida.cpp`
- `src/aida.hpp`

Read-only context:

- `src/actions.cpp`
- `src/vuln/chain_verification_tools.hpp`
- `ida-sdk/src/include/kernwin.hpp`

Deliverable: non-modal completed-result browser and evidence address jumps. This package must wait until Packages A-F are complete and reviewed.

## Integration Order

1. Package A lands first so every other package can share stable types and ledger serialization.
2. Package B lands next to make all chain references binary-qualified.
3. Package C lands with per-link path snapshots but does not make full-chain claims.
4. Package D lands and enables link-pair contract verdicts.
5. Package E lands and adds trigger-specific verdicts.
6. Package F lands after A-E APIs are stable and wires MCP/build integration.
7. Package G lands only after MCP tools and reports are reliable.

No package should edit another package's owned files. If an API change is required, the owning package updates its header and all dependent packages adapt after that change is reviewed.

## Acceptance Criteria For The Full Feature

- The plugin accepts the PROGRESS chain input model: binary/function/RVA, preconditions, claimed behavior, postconditions, assumptions, and trigger assumptions.
- It emits per-link, per-boundary, and full-chain verdicts with evidence.
- It refutes NTFS to ETW because zero-filled overflow output cannot satisfy controlled LIST_ENTRY input and because the claimed trigger path is not proven.
- It surfaces the AFD LIST_ENTRY self-reference check as an intermediate branch obligation before the `_setjmp` call.
- It refutes `pvScan0 = gpHandleManager` and accepts self-referencing `pvScan0` only when pointer identity and write-through semantics are proven.
- It never treats missing evidence, unresolved indirect calls, inactive IDBs, microcode failure, or solver timeout as a pass.
- It avoids modal prompts and long UI-thread execution during MCP verification.
- It persists chain jobs and reports durably, keyed by chain ID and binary evidence identity.
- It preserves AiDA security invariants: no license bypasses, no anti-tamper weakening, no arbitrary Python dependency for core proof, no server authority changes.

## Verification, Build, And Deployment Notes

This investigation did not build by instruction. Implementer subagents must not build. After approved implementation, the host AI must run the canonical repository build wrapper from the root, `.\build-host.cmd`, and confirm success with no new warnings before reporting completion.

The first implementation sequence should not touch `server/`, so no server deployment is expected. If a future approved change touches `server/`, run the relevant server verification and deployment scripts before reporting the change live. If driver, mapper, or encrypted driver assets are touched in a future scope, follow the driver rebuild pipeline and report that a reboot is required.

Suggested post-implementation verification:

- Load representative IDBs for the relevant modules, including AFD, ntoskrnl, win32kbase, NTFS, and ETW-related binaries when available.
- Use `chain_corpus_snapshot` to confirm binary identity, image base, hash, imports, exports, and function inventory.
- Submit the three PROGRESS case-study specs through `chain_verify_submit`.
- Poll `chain_verify_get` until completion and inspect the persisted ledger.
- Confirm `aida_debug.log` and MCP request logs show bounded main-thread snapshots, cancellation points, and no modal prompt activity.
- Confirm no changes were made to server deployment state unless server files were intentionally modified in a later approved implementation.
