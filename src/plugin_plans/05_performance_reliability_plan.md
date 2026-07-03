# AiDA IDA Plugin Performance And Reliability Plan

## Objective

Design the production architecture for an IDA Pro plugin that verifies multi-binary vulnerability chains without freezing IDA, blocking a reverse engineer, or relying on isolated per-link checks. The plugin must verify end-to-end chain feasibility across binaries while keeping every IDA database responsive, recoverable, cancellable, and diagnostically transparent.

The architecture is driven by the `driver/PROGRESS.md` case studies:

- NTFS compression to ETW failed because the overflow postcondition was zeros while the next link required controlled LIST_ENTRY values, and the ETW stop trigger was assumed rather than traced.
- AFD UAF to `_setjmp` failed because an intermediate LIST_ENTRY self-reference check existed before the indirect call and required a runtime kernel address not guaranteed by prior links.
- `pvScan0` failed because the chain confused mechanical pointer use with logical data flow; writing through `pvScan0 = gpHandleManager` writes to `gpHandleManager`, not to `pvScan0`.

The plugin therefore needs continuous path ownership across binaries, but its performance model must treat IDA as a fragile interactive host: IDA SDK calls are harvested in short main-thread slices, heavy solving and graph work run over immutable snapshots outside the UI path, and every long operation has explicit cancellation, budget, checkpoint, and recovery semantics.

## Current-State Findings

1. `src/aida.cpp` already has operational gating, action registration, UI event hooks, timer watchdog, background `std::thread` workers, and diagnostic breadcrumbs through `aida_ipc::trace_breadcrumb`. This is a good lifecycle foundation, but `initialize_operational(true)` and `run()` still use modal dialogs for disabled states and EULA flow.

2. `src/mcp_server.cpp` already routes tool calls through `execute_sync(req, MFF_READ/MFF_WRITE)` and logs total, execution, and queue wait timings. It also has a qthread-backed parallel batch helper with cancellation and wall-clock timeout, but it shows an IDA wait box and waits for all worker threads before returning, so a timed-out batch can still block if a worker is stuck inside an IDA main-thread request.

3. `src/ida_utils.cpp` has a RAG context cache with LRU, TTL, persistent netnode storage, per-binary hash separation, and maximum persistent byte limits. This pattern should be retained, but the chain verifier needs generation-based invalidation tied to IDB and Hex-Rays events rather than only time.

4. `src/vuln/verification_engine.hpp` exposes timeouts, cancellation, in-flight count, ledger persistence, path satisfiability, exploit input synthesis, wire constraints, and verdict summaries. `src/vuln/verification_engine.cpp` currently uses a global cancellation flag plus `user_cancelled()`, a wait-box guard, and synchronous engine calls. This is the closest existing surface for the chain verifier, but it needs a nonmodal job runtime and immutable snapshots.

5. `src/vuln/taint_engine.cpp` has whole-program analysis capped by `kMaxFunctionsToAnalyze`, call-graph ordering, reachability indexes, and netnode-backed summary cache keyed by binary MD5 plus signature database revision. It is synchronous and stores summaries in mutable engine state guarded at the tool-handler layer, which is unsafe for concurrent, cross-binary chain verification unless isolated behind snapshot generations.

6. `src/standalone/src/core/infra/work_queue.hpp` demonstrates the strongest local queue pattern: named tasks, worker stats, active-task snapshots, exception and SEH containment, shutdown timeouts, rejected-task counters, and nonblocking stats via `try_to_lock`. The IDA plugin should implement an IDA-safe variant with smaller pools and no direct IDA SDK access from worker bodies.

7. Several current plugin paths use `show_wait_box`, `warning`, and `info`. The new verifier must not add any such flow and should migrate its own status to a dockable, nonmodal task panel plus `msg()` and file logs.

## SDK Evidence Snippets

All IDA API recommendations below are based on local headers under `ida-sdk/src/include`.

### Main-thread request policy

From `ida-sdk/src/include/kernwin.hpp:4437-4454`:

```cpp
#define MFF_FAST   0x0000       ///< Execute code as soon as possible.
                                ///< this mode is ok for calling ui related functions
                                ///< that do not query the database.

#define MFF_READ   0x0001       ///< Execute code only when ida is idle and it is safe
                                ///< to query the database.
                                ///< This mode is recommended only
                                ///< for code that does not modify the database.

#define MFF_WRITE  0x0002       ///< Execute code only when ida is idle and it is safe
                                ///< to modify the database. in particular,
                                ///< this flag will suspend execution if there is
                                ///< a modal dialog box on the screen.
                                ///< this mode can be used to call any ida api function.
```

Architecture rule: all IDB reads for snapshot harvest use `MFF_READ`. IDB mutations, cache dirtying, annotations, and action registration use `MFF_WRITE`. `MFF_FAST` is allowed only for UI-only status refreshes that do not query the database.

### Nonblocking UI scheduling

From `ida-sdk/src/include/kernwin.hpp:4494-4509`:

```cpp
/// Base class for defining UI requests.
/// Override the run() method and insert your code.
class ui_request_t
{
public:
  /// Run the UI request
  /// \retval false  remove the request from the queue
  /// \retval true   reschedule the request and run it again
  virtual bool idaapi run() = 0;
  virtual ~ui_request_t() {}
};

/// List of UI requests. The ui_request_t is allocated by the caller
/// but its ownership is transferred to the execute_ui_requests().
/// The ui_request_t instance will be deleted as soon as it is executed and
/// was not rescheduled for another run.
```

From `ida-sdk/src/include/kernwin.hpp:4862-4883`:

```cpp
/// Execute a list of UI requests (::ui_execute_ui_requests_list).
/// \return a request id: a unique number that can be used to cancel the request
THREAD_SAFE inline int execute_ui_requests(ui_requests_t *reqs)

/// Execute a variable number of UI requests (::ui_execute_ui_requests).
/// The UI requests will be dispatched in the context of the main thread.
/// \param req  pointer to the first request, use nullptr to terminate the varadic request list
/// \return a request id: a unique number that can be used to cancel the request
THREAD_SAFE inline int execute_ui_requests(ui_request_t *req, ...)
```

Architecture rule: progress repaint, task panel refresh, and small deferred harvest steps use `execute_ui_requests`. A request must return quickly, update one bounded slice, and reschedule itself only while it has remaining budget and the job generation is still current.

### Request cancellation

From `ida-sdk/src/include/kernwin.hpp:4886-4903`:

```cpp
/// Try to cancel an asynchronous exec request (::ui_cancel_exec_request).
/// \param req_id  request id
/// \retval true   successfully canceled
/// \retval false  request has already been processed.
THREAD_SAFE inline bool cancel_exec_request(int req_id)

/// Try to cancel asynchronous exec requests created by the specified thread.
/// \param tid  thread id
/// \return number of the canceled requests.
THREAD_SAFE inline int cancel_thread_exec_requests(qthread_t tid)
```

From `ida-sdk/src/include/kernwin.hpp:4907-4913`:

```cpp
/// Setting it to `esa_unavailable` will cause the existing requests for
/// this thread to be cancelled.
/// Setting it to `esa_release` will clear the status for this thread, and
/// should be issued right before a call to `qthread_free` is issued.
```

Architecture rule: each job records every `execute_ui_requests` and `execute_sync | MFF_NOWAIT` request id plus the producing worker thread id. Cancellation first sets the job token, then cancels pending UI requests, then marks the generation abandoned so late completions cannot publish stale results.

### Thread primitives

From `ida-sdk/src/include/pro.h:5475-5498`:

```cpp
/// Create a thread and return a thread handle
idaman THREAD_SAFE qthread_t ida_export qthread_create(qthread_cb_t *thread_cb, void *ud);

/// Free a thread resource (does not kill the thread)
idaman THREAD_SAFE void ida_export qthread_free(qthread_t q);

/// Wait a thread until it terminates
idaman THREAD_SAFE bool ida_export qthread_join(qthread_t q);

/// Forcefully kill a thread (calls pthread_cancel under unix)
idaman THREAD_SAFE bool ida_export qthread_kill(qthread_t q);

/// Get current thread. Must call qthread_free() to free it!
idaman THREAD_SAFE qthread_t ida_export qthread_self(void);
```

From `ida-sdk/src/include/pro.h:5526-5531`:

```cpp
idaman THREAD_SAFE qsemaphore_t ida_export qsem_create(const char *name, int init_count);
idaman THREAD_SAFE bool ida_export qsem_free(qsemaphore_t sem);
idaman THREAD_SAFE bool ida_export qsem_post(qsemaphore_t sem);
idaman THREAD_SAFE bool ida_export qsem_wait(qsemaphore_t sem, int timeout_ms);
```

Architecture rule: IDA-integrated workers use `qthread_create`, `qsem_wait` with short finite waits, `qthread_join` only during bounded shutdown, and `qthread_free` after successful join or deliberate detach. The plugin must not use `qthread_kill` for normal cancellation; jobs cooperate through cancellation tokens and publish partial evidence.

### Auto-analysis readiness

From `ida-sdk/src/include/auto.hpp:234-266`:

```cpp
/// Process everything in the queues and return true.
/// \return false if the user clicked cancel.
///         (the wait box must be displayed by the caller if desired)
idaman bool ida_export auto_wait(void);

/// Process everything in the specified range and return true.
/// \return number of autoanalysis steps made. -1 if the user clicked cancel.
///         (the wait box must be displayed by the caller if desired)
idaman ssize_t ida_export auto_wait_range(ea_t ea1, ea_t ea2);

/// Are all queues empty?
/// (i.e. has autoanalysis finished?).
idaman bool ida_export auto_is_ok(void);
```

Architecture rule: the verifier never calls whole-database `auto_wait()` on an interactive action path. It uses `auto_is_ok()` as a readiness signal, range-scoped `auto_wait_range()` only when the user explicitly starts a verification job, and records unsettled ranges as snapshot preconditions when it chooses not to wait.

### User cancellation

From `ida-sdk/src/include/kernwin.hpp:6319-6323`:

```cpp
/// Test the cancellation flag (::ui_test_cancelled).
/// \retval true   Cancelled, a message is displayed
/// \retval false  Not cancelled
THREAD_SAFE inline bool user_cancelled() { return callui(ui_test_cancelled).cnd; }
```

Architecture rule: `user_cancelled()` is sampled only in main-thread slices. Worker-side cancellation uses the job token because workers can outlive a UI cancel flag and because cross-binary verification may be driven by MCP clients rather than direct UI actions.

### Modal wait boxes and warnings

From `ida-sdk/src/include/kernwin.hpp:6987-7006`:

```cpp
/// Display a dialog box with "Please wait...".
/// The behavior of the dialog box can be configured with well-known tokens
/// Plugins must call hide_wait_box() to close the dialog box, otherwise
/// the user interface will remain disabled.
/// This implies that a plugin should call hide_wait_box() exactly as many
/// times as it called show_wait_box(), or the wait dialog might remain
/// visible and block the UI.
```

From `ida-sdk/src/include/kernwin.hpp:7158-7178`:

```cpp
/// Display warning dialog box and wait for the user to press Enter or Esc.
THREAD_SAFE AS_PRINTF(1, 0) inline ssize_t vwarning(const char *format, va_list va)
THREAD_SAFE AS_PRINTF(1, 2) inline ssize_t warning(const char *format, ...)
```

Architecture rule: the chain verifier must not call `show_wait_box`, `warning`, `info`, or any modal form for progress, errors, cancellation, or completion. Status goes to a modeless dockable task panel, IDA output through `msg()`, MCP result payloads, and `%TEMP%\AiDA\aida_ida_plugin.log`.

### Plugin lifecycle and multi-IDB support

From `ida-sdk/src/include/loader.hpp:601-605`:

```cpp
#define PLUGIN_MULTI    0x0100  ///< The plugin can work with multiple idbs in parallel.
                                ///< init() returns a pointer to a plugmod_t object
                                ///< run/term functions are not used.
                                ///< Virtual functions of plugmod_t are used instead.
```

From `ida-sdk/src/include/idp.hpp:2150-2167`:

```cpp
struct plugmod_t : public modctx_t
{
  virtual bool idaapi run(size_t arg) = 0;

  bool hook_event_listener(
        hook_type_t hook_type,
        event_listener_t *cb,
        int hkcb_flags=0)
  {
    return ::hook_event_listener(hook_type, cb, this, hkcb_flags);
  }

  virtual ~plugmod_t() {}
};
```

Architecture rule: every IDB gets a distinct verifier context owned by `aida_plugin_t` / `plugmod_t`, including job registry, cache generations, IDB event hooks, and per-IDB memory budgets. Cross-binary work coordinates contexts through the existing MCP multi-instance mesh; it does not share raw IDA pointers across databases.

### IDB change invalidation

From `ida-sdk/src/include/idp.hpp:2876-2879`:

```cpp
/// The callback function should return 0 but the kernel won't check it.
/// Use the hook_event_listener() function to install your callback.
```

From `ida-sdk/src/include/idp.hpp:2895-2902`:

```cpp
auto_empty,             ///< Info: all analysis queues are empty.
                        ///< This callback is called once when the
                        ///< initial analysis is finished.

auto_empty_finally,     ///< Info: all analysis queues are empty definitively.
                        ///< This callback is called only once.
```

From `ida-sdk/src/include/idp.hpp:2937-2945`, `2966-2974`, `3023-3109`, and `3193-3197`:

```cpp
changing_ti,            ///< An item typestring (c/c++ prototype) is to be changed.
ti_changed,             ///< An item typestring (c/c++ prototype) has been changed.
segm_added,             ///< A new segment has been created.
segm_deleted,           ///< A segment has been deleted.
func_added,             ///< The kernel has added a function.
func_updated,           ///< The kernel has updated a function.
deleting_func,          ///< The kernel is about to delete a function.
destroyed_items,        ///< Instructions/data have been destroyed in [ea1,ea2).
renamed,                ///< The kernel has renamed a byte.
byte_patched,           ///< A byte has been patched.
local_types_changed,    ///< Local types have been changed
```

Architecture rule: the verifier installs an IDB event listener per database. Events bump a monotonic `idb_generation`, enqueue range-level invalidation, and prevent stale snapshot publication. `auto_empty` triggers low-priority indexing; `closebase` cancels all local jobs and seals the recovery journal.

### Hex-Rays and microcode snapshots

From `ida-sdk/src/include/hexrays.hpp:7689-7701`:

```cpp
#define DECOMP_NO_WAIT      0x0001 ///< do not display waitbox
#define DECOMP_NO_CACHE     0x0002 ///< do not use decompilation cache (snippets are never cached)
#define DECOMP_WARNINGS     0x0008 ///< display warnings in the output window
#define DECOMP_GXREFS_NOUPD 0x0040 ///< do not update the global xrefs cache
#define DECOMP_VOID_MBA     0x0100 ///< return empty mba object (to be used with gen_microcode)
```

From `ida-sdk/src/include/hexrays.hpp:7711-7721`:

```cpp
/// Decompile a snippet or a function.
/// \param decomp_flags bitwise combination of \ref DECOMP_... bits
/// \return pointer to the decompilation result (a reference counted pointer).
///         nullptr if failed.
cfuncptr_t hexapi decompile(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        int decomp_flags=0);
```

From `ida-sdk/src/include/hexrays.hpp:7759-7772`:

```cpp
/// Generate microcode of an arbitrary code snippet
/// \param reqmat       required microcode maturity
/// \return pointer to  the microcode, nullptr if failed.
mba_t *hexapi gen_microcode(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        const mlist_t *retlist=nullptr,
        int decomp_flags=0,
        mba_maturity_t reqmat=MMAT_GLBOPT3);
```

From `ida-sdk/src/include/hexrays.hpp:7790-7796`:

```cpp
/// Flush the cached decompilation results.
/// Erases a cache entry for the specified function.
/// \param ea function to erase from the cache
/// \param close_views close pseudocode windows that show the function
/// \return if a cache entry existed.
bool hexapi mark_cfunc_dirty(ea_t ea, bool close_views=false);
```

Architecture rule: snapshot harvest uses `DECOMP_NO_WAIT` and, for background indexing, `DECOMP_GXREFS_NOUPD` unless the user explicitly requests xref cache updates. Worker jobs never retain `cfunc_t*`, `mba_t*`, `func_t*`, `mblock_t*`, or `minsn_t*`; they receive serialized microcode summaries, instruction facts, edges, reads, writes, branch predicates, callsites, and type facts.

### Hex-Rays event invalidation

From `ida-sdk/src/include/hexrays.hpp:7865-7895`:

```cpp
/// Use install_hexrays_callback() to install a handler for decompiler events.
hxe_flowchart,        ///< Flowchart has been generated.
hxe_microcode,        ///< Microcode has been generated.
                       ///< \param mba (mba_t *)
```

From `ida-sdk/src/include/hexrays.hpp:7990-8008` and `8083-8090`:

```cpp
hxe_collect_warnings, ///< Collect warning messages from plugins.
hxe_open_pseudocode=100,
hxe_switch_pseudocode,///< Existing pseudocode view has been reloaded
hxe_refresh_pseudocode,///< Existing pseudocode text has been refreshed.
hxe_cmt_changed,      ///< Comment got changed.
hxe_mba_maturity,     ///< Maturity level of an MBA was changed.
```

From `ida-sdk/src/include/hexrays.hpp:8102-8118`:

```cpp
typedef ssize_t idaapi hexrays_cb_t(void *ud, hexrays_event_t event, va_list va);
bool hexapi install_hexrays_callback(hexrays_cb_t *callback, void *ud);
int hexapi remove_hexrays_callback(hexrays_cb_t *callback, void *ud);
```

Architecture rule: Hex-Rays callbacks record cache dirty ranges and maturity availability only. They do not run analysis, solve constraints, allocate large objects, update UI, or block. Callback work is constant-time and hands off to the job scheduler.

## Job System Design

### Components

1. `verification_job_manager_t`

   Owns the per-IDB job registry, cancellation tokens, request ids, memory reservations, status snapshots, and durable recovery journal. It lives under the plugin instance, not as a process-global singleton.

2. `ida_slice_scheduler_t`

   Runs short IDA-main-thread harvest slices. It supports read slices, write slices, and UI-only slices. Every slice has:

   - `job_id`
   - `idb_generation_at_enqueue`
   - `budget_ms`
   - `max_items`
   - `cancel_token`
   - `request_id`
   - `phase`

3. `analysis_worker_pool_t`

   Runs pure CPU, graph, taint, SMT, and chain-composition work over immutable snapshots. It can use an IDA-safe qthread implementation in plugin builds and the existing standalone `work_queue` style in standalone builds. It must expose stats equivalent to `work_queue::stats_t`: alive, pending, active, oldest active age, labels, started, finished, rejected, and active TID.

4. `cross_idb_chain_coordinator_t`

   Coordinates multi-binary jobs across IDA instances by stable instance id, PID, input file hash, image base, processor, and bitness from the existing MCP mesh. It never shares raw SDK objects. Each remote IDB returns signed or hashed snapshot chunks with generation ids and evidence addresses.

5. `snapshot_store_t`

   Owns immutable fact snapshots. Snapshot chunks are plain data: functions, basic blocks, normalized instructions, decompiler/microcode summaries, reads, writes, call edges, branch predicates, switch targets, type facts, string/import/export facts, segment maps, and source provenance. Each chunk carries `idb_generation`, `hexrays_generation`, binary hash, signature database revision, source tool version, and byte size.

6. `result_ledger_t`

   Persists job state and verdicts to a netnode or existing analysis database record keyed by binary hash plus chain id. It stores only bounded summaries and content-addressed chunk references, not unbounded raw pseudocode.

### Execution Flow

1. A UI action or MCP tool creates a job with a complete chain manifest: binaries, functions/RVAs, link claims, preconditions, postconditions, trigger assumptions, memory/register assumptions, and requested proof depth.

2. The manager validates parameters on the caller path in under 25 ms. If validation is heavier, it returns a job id immediately and schedules validation as a job phase.

3. The scheduler harvests minimal IDB metadata first: binary identity, segments, function ranges, auto-analysis readiness, and Hex-Rays availability. This is a bounded `MFF_READ` slice.

4. The job expands into per-binary snapshot requests. Each request is divided by function and path window, not by whole database. The first pass harvests only the functions and callers/callees needed for the declared chain.

5. Worker phases build cross-link state models, path constraints, branch obligations, call clobber facts, and postcondition/precondition checks from snapshots.

6. If a hidden intermediate check, missing trigger edge, or logical data-flow contradiction is found, the job publishes a partial refutation immediately and stops deeper solving unless the user selected exhaustive mode.

7. SMT and symbolic phases use strict per-query and per-job budgets. They return `confirmed`, `refuted`, `inconclusive`, `timeout`, or `unsupported`, matching `verification_engine.hpp`.

8. Completion publishes a stable result record with evidence addresses, source snapshot generation, missing assumptions, branch obligations, side effects, collateral damage, and reproducible proof inputs.

### Queue Classes

1. UI queue

   Purpose: modeless progress panel updates, small status refreshes, action enablement. Uses `execute_ui_requests`. Budget: 2 ms target, 8 ms hard cap per run. If work remains, reschedule.

2. IDB read queue

   Purpose: `get_func`, xrefs, names, bytes, types, decompile/microcode generation, segment state, auto-analysis status. Uses `execute_sync` with `MFF_READ` or UI requests that run read-only slices. Budget: 10 ms target, 40 ms hard cap per slice; large functions can use one function per slice.

3. IDB write queue

   Purpose: user-requested annotations, cache dirtying, optional result comments, database settings. Uses `MFF_WRITE`. Budget: 10 ms target, 25 ms hard cap. Mutations are disabled by default during verification and require explicit user action.

4. CPU worker queue

   Purpose: graph composition, chain state propagation, path search over serialized CFG, def-use analysis over serialized facts, payload logic checks, ranking, report generation. No IDA SDK calls. Budget: cooperative checkpoints every 2,000 nodes or 20 ms, whichever comes first.

5. Solver queue

   Purpose: SMT and symbolic queries. It is isolated from general workers so solver saturation cannot starve snapshot harvest or UI refresh. Max concurrency defaults to `min(2, logical_cores / 4)` per IDB and `min(4, logical_cores / 2)` process-wide.

6. I/O queue

   Purpose: journal writes, netnode blobs, external report export, compressed snapshot chunk persistence. It must not hold IDB locks while compressing or serializing large payloads.

## Responsiveness And No-Freeze Guarantees

1. No modal UI in verifier code. No `show_wait_box`, `warning`, or `info` for verifier state. All errors become task records with severity, phase, evidence, and recovery action.

2. Every user-triggered action returns control to IDA in under 50 ms. Slow actions return a job id and update the nonmodal task panel.

3. Main-thread SDK slices are bounded by item count and elapsed time. The scheduler records `slice_started_ms`, `slice_elapsed_ms`, `items_done`, and `next_cursor`.

4. No worker can synchronously wait on the UI thread while holding a job mutex, cache mutex, or result lock. IDA API requests copy results into local temporary objects and publish after releasing scheduler locks.

5. `auto_wait()` is not used for whole-database blocking in verifier paths. If auto-analysis is not settled, the job records `analysis_unsettled=1`, waits only for required ranges when explicitly requested, and continues with degraded confidence when safe.

6. Decompiler calls use `DECOMP_NO_WAIT`. Background indexing adds `DECOMP_GXREFS_NOUPD` unless a user-visible xref refresh is explicitly requested.

7. Large function handling is incremental. A function exceeding thresholds is summarized first with instruction/xref facts; microcode and pseudocode are harvested only for path windows relevant to the chain.

8. Cross-binary coordination is asynchronous. A slow or closed peer IDA marks only that binary leg as `unavailable` or `stale_generation`; it does not freeze the local IDA.

9. Shutdown is bounded. Plugin unload sets process-wide cancellation, cancels pending UI requests, seals journals, waits briefly for harvest threads, detaches noncritical workers after logging active snapshots, and never blocks indefinitely.

10. Result publication is generation-checked. A completed phase publishes only if its input snapshot generation still matches the current job generation.

## Scheduling Budgets

Default budgets are deliberately conservative and user-configurable through settings:

- UI refresh: 250 ms cadence while jobs are active, 2 ms target work per refresh.
- IDB metadata slice: 10 ms target, 40 ms hard cap.
- Function snapshot slice: one function or 25 basic blocks per slice, whichever is smaller.
- Microcode snapshot slice: one function per slice, skipped or downgraded when function size exceeds configured thresholds.
- Worker checkpoint: 20 ms or 2,000 graph nodes.
- Solver query: 250 ms cheap pass, 5,000 ms normal pass, 30,000 ms explicit deep pass.
- Per-chain default wall time: 120 seconds with resumable partial results.
- Per-IDB memory budget: 256 MB default for snapshots and indexes.
- Process-wide verifier memory budget: 1 GB default, with backpressure before allocation.

When a budget is reached, the phase returns partial evidence with `partial=true`, `budget_exhausted=true`, cursor state, and the exact next resumable phase.

## Snapshot Architecture

Snapshots are the boundary between IDA and heavy analysis.

### Snapshot Types

1. `binary_snapshot_t`

   Binary identity, input path hash, MD5/SHA256, image base, segments, bitness, processor, compiler, IDB path, IDA instance id, generation ids.

2. `function_snapshot_t`

   Function start/end, chunks, flags, name, demangled name, frame summary, type signature, incoming and outgoing xrefs, calls, return behavior, no-return state, and size metrics.

3. `cfg_snapshot_t`

   Blocks, edges, branch instruction facts, switch targets, exceptional edges when available, dominator/postdominator summaries, loop headers, and path window ids.

4. `microcode_snapshot_t`

   Serialized facts only: mblock ids, maturity, instruction EA, opcode, rendered text, destination/source operand categories, def-use summaries, call argument facts, branch predicates, memory read/write facts, and clobber lists.

5. `dataflow_snapshot_t`

   Cross-link state facts: registers, stack slots, heap object fields, symbolic memory regions, produced bytes, zero-filled ranges, controlled ranges, unknown ranges, and assumptions.

6. `trigger_snapshot_t`

   Event-to-behavior path evidence: entry event, API/dispatch route, callbacks, cleanup path, required object lifecycle, terminal behavior, and missing edges.

### Snapshot Rules

- SDK object pointers never leave a main-thread slice.
- Snapshots are immutable after publication.
- Snapshot ids include binary hash, generation, function start, maturity, and content hash.
- Large snapshots are compressed and content-addressed.
- The job manager tracks reference counts and evicts least-recent, rehydratable chunks under memory pressure.
- A stale snapshot can be read for historical reports but cannot be used for a new verdict unless the user explicitly pins that generation.

## Incremental Indexing

1. Initial index

   On `auto_empty` or explicit user start, build only identity, segments, imports/exports, functions, names, call graph skeleton, and fast source/sink callsites.

2. Demand index

   When a chain references a function/RVA, index that function, its direct callers/callees, and the shortest connecting path windows first.

3. Deep index

   Build microcode, taint summaries, branch constraints, and alias facts only for functions in the chain frontier.

4. Whole-program index

   Available as an explicit background job with progress, cancellation, memory budget, and pause/resume. It never starts automatically just because IDA opened a large database.

5. Multi-binary index

   Each IDB independently indexes its local binary. The coordinator builds a cross-binary graph from exported snapshot summaries and ABI/call-transition facts. It does not centralize raw IDB reads.

## Cache Invalidation

### Generation Model

Each IDB context maintains:

- `idb_generation`: increments on byte, segment, function, type, rename, destroyed item, and rebase events.
- `hexrays_generation`: increments on Hex-Rays events that indicate pseudocode, maturity, local variable, comment, or microcode state changed.
- `analysis_generation`: increments when auto-analysis transitions from unsettled to settled.
- `signature_generation`: equals `SIGNATURE_DATABASE_REVISION` and tool schema revision.
- `engine_generation`: increments when verifier algorithms, source/sink signatures, normalization logic, or SMT encoding changes.

Cache keys include all relevant generations plus binary hash and architecture. A missing generation component is a correctness bug.

### Event Handling

The IDB listener handles:

- `auto_empty` and `auto_empty_finally`: mark readiness, schedule low-priority indexing, unblock jobs waiting on settled analysis.
- `func_added`, `func_updated`, `deleting_func`, function tail events: invalidate function, CFG, call graph, taint, microcode, and chain proof chunks touching the function range.
- `byte_patched`, `destroyed_items`, `make_code`, `make_data`: invalidate range facts and every function overlapping the range.
- `segm_added`, `segm_deleted`, segment move/rebase events: invalidate binary layout, address translation, cross-binary RVA mapping, and all absolute-address proof facts.
- `ti_changed`, `op_ti_changed`, `local_types_changed`: invalidate type facts, call argument facts, decompiler snapshots, and dataflow assumptions.
- `renamed`: invalidate display-name caches and evidence labels without forcing proof invalidation unless the name was used as a semantic match key.
- `closebase`: cancel local jobs, persist recoverable state, release snapshots, and mark peers unavailable.

Hex-Rays callbacks only bump `hexrays_generation`, mark affected functions dirty in AiDA caches, and update availability metrics. They never solve, decompile, or run chain verification inline.

### Cache Layers

1. Hot in-memory per-IDB LRU

   Bounded by byte size and generation. Holds recent function, CFG, microcode, and path snapshots.

2. Durable netnode cache

   Stores compact summaries and verification ledgers. It uses per-record byte caps like `ida_utils.cpp` and `taint_engine.cpp`; oversized records spill to chunked pages or are refused with a logged size reason.

3. MCP output cache

   Stores presentation results only. It must not be used as correctness cache because it is capped by count and detached from IDB generations.

4. Deterministic tool cache

   Kept for read-only repeated queries, but chain verdicts require generation-aware keys and must flush or mark stale on every mutation event, not only on destructive tool calls.

## Memory Limits And Backpressure

1. Every job declares an estimated memory reservation before deep phases start.

2. Snapshot store enforces per-IDB and process-wide byte budgets. Admission failure returns `resource_exhausted` with current stats, not a crash or UI stall.

3. Large functions are summarized in tiers:

   - Tier 0: metadata and call edges.
   - Tier 1: CFG and branch predicates.
   - Tier 2: microcode facts for path windows.
   - Tier 3: full function facts only in explicit deep mode.

4. Solver contexts are pooled and bounded. A timed-out or exception-throwing solver context is discarded, not reused.

5. Snapshot serialization uses streaming/chunking. No single JSON object may exceed configured caps in memory or in netnode storage.

6. Reports are paginated. UI and MCP responses return previews plus content ids for large payloads.

## Cancellation Semantics

1. Cancellation is cooperative and deterministic:

   - Set job token.
   - Cancel queued UI/main-thread request ids.
   - Mark generation abandoned.
   - Wake worker semaphores.
   - Seal partial result.
   - Persist cancellation record.

2. Every phase checks cancellation before and after:

   - IDA main-thread request enqueue.
   - Snapshot publication.
   - Function loop iteration.
   - CFG frontier expansion.
   - SMT query.
   - Cross-IDB RPC.
   - Journal write.

3. Cancellation returns the strongest already-proven verdict. A refutation remains valid if its source snapshots are recorded and generation-pinned. An inconclusive or timeout result is resumable.

4. User cancellation never uses `qthread_kill`, `TerminateThread`, process exit, or modal confirmation.

## Failure Containment

1. SEH and C++ exception guards wrap every worker job, every solver query, and every IDA slice callback.

2. A crashing worker marks only its job phase failed and writes a crash breadcrumb with job id, phase, binary id, function EA/RVA, generation, worker TID, exception code, elapsed time, memory counters, and queue stats.

3. A Hex-Rays failure is a function-level degradation. The verifier falls back to disassembly/CFG facts and reports `hexrays_unavailable` for the affected path window.

4. A peer IDA disconnect becomes `peer_unavailable` for that binary leg. The local job remains responsive and publishes missing-binary evidence.

5. A stale generation fails closed for new verdicts. The job either re-harvests the affected snapshot or returns `stale_generation`.

6. A memory cap failure stops deeper phases and publishes bounded partial evidence; it never disables the plugin.

7. A solver timeout is a query-level timeout, not a job crash. The path remains `inconclusive` unless another proof refutes it.

8. Repeated phase failures trip a per-feature circuit breaker. The circuit breaker pauses new deep phases for that IDB, leaves read-only status available, and logs the exact breaker reason.

## Deterministic Recovery

The job manager writes a compact recovery journal at every phase boundary:

- job id
- chain manifest hash
- IDB instance id and binary hash
- phase name
- phase cursor
- snapshot ids consumed and produced
- generation ids
- cancellation state
- last verdict
- resource counters
- error code and breadcrumb id

On plugin restart or IDB reopen:

1. Load journals for the current binary hash and IDB path.
2. Drop records whose binary hash or tool generation does not match.
3. Mark in-flight records as `interrupted`.
4. Validate snapshot chunks by content hash and generation.
5. Offer nonmodal resume, discard, or export actions in the task panel.
6. Resume from the last completed phase only after rechecking current IDB generation.

No restart path assumes partial in-memory state is valid.

## Logging And Telemetry Strategy

1. Local file log

   Use `%TEMP%\AiDA\aida_ida_plugin.log` through the existing `aida_ipc` breadcrumb style. Add a verifier tag for every line: `verifier job=<id> phase=<phase> idb_gen=<n> hex_gen=<n>`.

2. IDA output

   Use `msg()` only for concise lifecycle events: job started, job finished, job failed, recovery available. No progress spam, no secrets, no full payloads.

3. Structured event ring

   Keep an in-memory bounded ring for the task panel and MCP status. It stores recent events with severity, timestamp, TID, queue, phase, elapsed, counters, and evidence address.

4. Performance counters

   Record per phase:

   - enqueue time
   - queue wait
   - execution time
   - item count
   - bytes allocated
   - snapshot bytes produced
   - cache hits/misses
   - cancellation checks
   - IDA generation observed
   - solver timeout count

5. Failure breadcrumbs

   For crashes, hangs, and stale results, capture:

   - job id and chain id
   - binary id and IDA instance id
   - function VA/RVA
   - phase and substep
   - worker TID and main-thread request id
   - elapsed duration
   - queue stats
   - memory budget state
   - SDK API being called
   - Win32/SEH code where applicable

6. Privacy and security

   Logs may include addresses, hashes, state facts, and payload context needed for debugging. They must not include raw credentials, private keys, license keys, bearer tokens, KMS/HSM material, or signing secrets.

## Multi-Binary Reliability Architecture

1. Each binary is an independent proof domain with its own IDB generation and snapshot store.

2. Cross-binary edges are explicit facts: import/export binding, syscall/IOCTL dispatch, callback registration, object lifecycle handoff, shared structure layout, protocol message, or user-mode/kernel transition.

3. A chain edge is verified only when the producing binary's postcondition satisfies the consuming binary's precondition under the recorded ABI and memory model.

4. Missing peer data does not block local IDA. It yields a resumable `peer_data_missing` proof gap.

5. Cross-binary jobs publish a merged timeline with per-binary phase clocks so slow peers are visible.

6. The coordinator owns global wall-clock and memory budgets but delegates IDB access to each peer's local scheduler.

## Chain Verification Performance Strategy

The case studies require whole-chain ownership, but the verifier should fail early on cheap contradictions:

1. Parse the chain manifest and normalize all claims into preconditions, transitions, postconditions, trigger edges, and assumptions.

2. Run cheap structural checks first:

   - referenced binary/function exists
   - RVA maps to function/block
   - callsite/branch exists
   - stated source/sink instruction exists
   - required type/offset facts exist

3. Run boundary checks before deep solving:

   - produced bytes vs consumed bytes
   - controlled vs zero-filled vs unknown memory
   - self-reference requirements
   - required concrete address knowledge
   - register clobbers across calls
   - object lifetime and trigger reachability

4. Run path-window harvesting only for chain frontier functions and trigger paths.

5. Run SMT only after structural and boundary checks leave the chain plausible.

6. Emit early refutations with exact proof gaps, such as:

   - `postcondition_content_mismatch`
   - `trigger_path_not_reached`
   - `hidden_intermediate_check_unmet`
   - `logical_dataflow_contradiction`
   - `register_state_not_guaranteed`
   - `object_address_unknown`

## Nonmodal User Experience

1. Add an AiDA Chain Verification dockable panel with:

   - active jobs
   - progress bars
   - phase labels
   - cancel/pause/resume buttons
   - current bottleneck
   - cache/memory stats
   - newest finding
   - peer IDA status
   - recovery records

2. Every modal error becomes an inline panel event and a `msg()` line.

3. Cancellation is immediate from the panel and MCP.

4. Results are shown incrementally. The user can inspect early refutations before the full exhaustive run completes.

5. The plugin never steals focus during background verification.

## Files Likely Affected

Likely new files:

- `src/vuln/chain_verifier.hpp`
- `src/vuln/chain_verifier.cpp`
- `src/vuln/chain_job_manager.hpp`
- `src/vuln/chain_job_manager.cpp`
- `src/vuln/chain_snapshot.hpp`
- `src/vuln/chain_snapshot.cpp`
- `src/vuln/chain_cache.hpp`
- `src/vuln/chain_cache.cpp`
- `src/vuln/chain_recovery.hpp`
- `src/vuln/chain_recovery.cpp`
- `src/vuln/chain_status_view.hpp`
- `src/vuln/chain_status_view.cpp`
- `src/vuln/chain_mcp_tools.cpp`

Likely existing files to update:

- `src/aida.hpp`: add per-plugin verifier manager, IDB listener state, and status panel owner.
- `src/aida.cpp`: initialize and shut down verifier manager; hook IDB and Hex-Rays events; remove verifier-related modal flows.
- `src/mcp_server.cpp`: expose async job start/status/cancel/result tools and generation-aware large result handling.
- `src/agent_tools.cpp` / `src/agent_tools.hpp`: register chain verifier MCP tools and shared result schemas.
- `src/ida_utils.cpp` / `src/ida_utils.hpp`: add generation-aware cache invalidation helpers and snapshot-safe wrappers.
- `src/vuln/verification_engine.hpp` / `src/vuln/verification_engine.cpp`: adapt existing verdict, ledger, timeout, and cancellation concepts to async jobs.
- `src/vuln/taint_engine.hpp` / `src/vuln/taint_engine.cpp`: expose snapshot-friendly summaries and generation-aware cache loading.
- `src/vuln/microcode_engine.hpp` / `src/vuln/microcode_engine.cpp`: expose serialized microcode fact extraction with strict flags and no retained SDK pointers.
- `src/vuln/cfg_engine.cpp`: expose path-window CFG snapshots and generation-aware graph cache invalidation.
- `src/settings.hpp` / `src/settings.cpp`: add budgets, queue sizes, memory limits, and solver concurrency settings.

## Acceptance Criteria

1. IDA remains interactive during a deep multi-binary chain verification. Cursor movement, disassembly navigation, right-click menus, and existing AiDA actions remain usable.

2. No verifier code path calls `show_wait_box`, `warning`, `info`, or any modal dialog for progress, failure, cancellation, or completion.

3. Starting a verification job returns to the caller in under 50 ms for local UI and MCP.

4. Every long-running job can be cancelled from UI and MCP, and cancellation returns a partial result without waiting for the full wall-clock budget.

5. Every IDA SDK access occurs in a bounded main-thread slice with `MFF_READ`, `MFF_WRITE`, or `execute_ui_requests` according to the SDK rules cited above.

6. Worker phases never retain raw IDA SDK pointers outside the slice that created them.

7. IDB and Hex-Rays events invalidate exactly the affected generations and prevent stale verdict publication.

8. Memory budgets are enforced with explicit `resource_exhausted` results and logs; no unbounded JSON, pseudocode, microcode, or solver payload accumulation is allowed.

9. A crashing worker, Hex-Rays failure, solver timeout, peer disconnect, or stale generation affects only the current job or phase and leaves the plugin operational.

10. Recovery after IDA restart or plugin reload deterministically marks interrupted jobs, validates snapshots by generation and content hash, and supports nonmodal resume or discard.

11. The three case-study failure modes are represented as first-class verifier outcomes and are detectable before exhaustive SMT solving when the evidence is present.

12. Logs include enough timing, queue, memory, generation, function, phase, and request-id evidence to diagnose freezes or incorrect stale results from one reproduction.

## Verification Plan

1. Static source audit

   Search new verifier files for forbidden modal APIs: `show_wait_box`, `hide_wait_box`, `warning(`, `info(`, modal form helpers, blocking file dialogs, and unbounded `auto_wait()`.

2. SDK-threading audit

   Verify every IDA SDK access is inside an IDA slice wrapper. Audit worker code for forbidden raw SDK types crossing thread boundaries: `func_t*`, `cfunc_t*`, `mba_t*`, `mblock_t*`, `minsn_t*`, `TWidget*`, `segment_t*`, and raw `lvar_t*`.

3. Responsiveness test

   Run a deep verification on a large IDB while repeatedly navigating, opening context menus, switching pseudocode/disassembly, and issuing lightweight MCP reads. Pass condition: no visible freeze, no hung window, and UI slice logs stay within hard caps except explicitly logged outliers.

4. Cancellation test

   Start a multi-binary deep job, cancel from the task panel, then cancel from MCP. Pass condition: pending UI requests are canceled, workers publish partial results, no worker blocks plugin unload, and the job reaches terminal `cancelled` state.

5. Generation invalidation test

   Patch a byte, rename a function, change a type, add/delete a function, and trigger Hex-Rays refresh while jobs are queued and running. Pass condition: stale phases cannot publish final verdicts, affected snapshots are re-harvested, and unaffected snapshots remain cached.

6. Memory pressure test

   Lower per-IDB and process-wide budgets, run whole-program indexing, and verify backpressure. Pass condition: jobs degrade to partial evidence with `resource_exhausted`, no process memory spike beyond configured caps, and UI remains responsive.

7. Peer failure test

   Start a cross-binary job across multiple IDA instances, then close one peer IDA. Pass condition: local IDA remains responsive, the job reports `peer_unavailable`, and recovery can resume when the peer returns with matching binary hash.

8. Crash containment test

   Inject a controlled exception in a worker phase and a controlled Hex-Rays failure return. Pass condition: only that phase fails, breadcrumbs contain job/phase/function/generation/TID/elapsed data, and subsequent jobs still run.

9. Recovery test

   Interrupt IDA during a long job, reopen the IDB, and inspect the task panel. Pass condition: interrupted jobs are listed with last completed phase, stale records are rejected, valid records can resume, and discarded records release snapshots.

10. Case-study regression suite

   Encode the three `driver/PROGRESS.md` case studies as manifests:

   - NTFS to ETW must flag data-content mismatch and missing trigger path.
   - AFD to `_setjmp` must flag the hidden LIST_ENTRY self-reference precondition and required address knowledge.
   - `pvScan0` must flag logical data-flow contradiction unless `pvScan0` points to itself.

   Pass condition: each failure is reported with concrete addresses, path evidence, and postcondition/precondition mismatch, without requiring a full exhaustive whole-program scan.

11. Build and warning gate for implementers

   After implementation, the host AI must run the canonical AiDA build wrapper and verify zero errors and zero new warnings. Planning subagents do not build.

