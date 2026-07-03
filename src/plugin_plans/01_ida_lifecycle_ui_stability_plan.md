# AiDA IDA Lifecycle, UI, and Stability Plan for Multi-Binary Chain Verification

Scope: IDA plugin lifecycle, UI integration, non-modal UX, background execution, cancellation, exception containment, and IDA-main-thread safety for production-grade multi-binary vulnerability-chain verification.

Mandatory driver context read: `C:\Users\ruar1337\AiDAPrivate\driver\PROGRESS.md`, especially the final chain-verification case studies.

## Objective

Build the IDA-side host shell for a verifier that proves a vulnerability chain as one continuous cross-binary execution trace. The UI and lifecycle layer must let the verifier check register state, memory state, branch conditions, side effects, trigger reachability, and postcondition/precondition compatibility across all involved binaries without ever halting, freezing, or crashing a reverse engineer's IDA session.

The plugin must treat the three documented failure classes as first-class product requirements:

- NTFS -> ETW: postcondition content mismatch, where the overflow wrote zeros while the next link required controlled LIST_ENTRY pointers.
- AFD -> _setjmp: hidden intermediate branch/check before the claimed call target, where the path required a self-referencing LIST_ENTRY.
- pvScan0: logical data-flow contradiction, where writing through `pvScan0 = gpHandleManager` did not mutate `pvScan0` itself.

This plan is limited to the IDA host architecture that makes that analysis safe and usable. The semantic verifier can be powerful only if its IDA integration is non-blocking, cancellable, and failure-contained.

## Current-State Findings

1. AiDA is already a `PLUGIN_MULTI` plugin with a per-IDB `aida_plugin_t` object.
   Evidence: `src\aida.cpp` exports `plugin_t PLUGIN` with `PLUGIN_MULTI`, and `src\aida.hpp` declares `class aida_plugin_t : public plugmod_t`.

2. Existing lifecycle hardening is valuable and must be preserved.
   Evidence: `src\aida.cpp` pins `AiDA.dll`, owns `public_ip_thread` and `graphrag_load_thread`, unregisters `self_watchdog_timer`, unhooks `HT_UI`, stops MCP, saves GraphRAG/analysis DB, and unregisters actions in `aida_plugin_t::~aida_plugin_t`.

3. Current plugin startup still contains modal UI and interactive blockers that are incompatible with the chain verifier requirement.
   Evidence: `src\aida.cpp` uses `ask_yn()` in `show_eula_dialog()`, calls `warning()` when disabled, and uses `info()` from `aida_plugin_t::run()`.

4. Current action handlers include modal file selection and wait-box progress.
   Evidence: `src\actions.cpp` calls `ask_file()` in `handle_save_database_context()` and uses `show_wait_box()`, `replace_wait_box()`, `user_cancelled()`, and `hide_wait_box()` while looping all functions.

5. Current MCP tool execution uses the correct broad concept, `exec_request_t` + `execute_sync()`, to get IDA work onto the main thread.
   Evidence: `src\mcp_server.cpp` defines MCP request types derived from `exec_request_t` and calls `execute_sync(req, MFF_READ)` or `execute_sync(req, MFF_WRITE)`.

6. Current MCP execution still permits long main-thread bodies and wait boxes.
   Evidence: `src\mcp_server.cpp` executes `ToolRegistry::instance().execute_tool()` inside `mcp_tool_exec_request_t::execute()` and `mcp_batch_exec_request_t::execute()`, and the batch path shows wait boxes for multi-tool calls.

7. Existing parallel MCP read-only batches use `qthread_create()` and `qsemaphore_t`, but they still depend on `user_cancelled()` and `show_wait_box()`.
   Evidence: `src\mcp_server.cpp` `run_batch_parallel()` spawns qthreads and waits on a semaphore, while displaying `show_wait_box()` and polling `user_cancelled()`.

8. Existing vulnerability verification has useful cancellation and in-flight accounting, but it is not the right UI model for the new chain verifier.
   Evidence: `src\vuln\verification_engine.cpp` has `g_verify_cancel`, `g_verify_in_flight`, and `VerificationEngine::cancel()`, but also has `wait_box_guard_t` and `should_cancel()` tied to `user_cancelled()`.

9. Existing microcode and symbolic engines already expose useful building blocks, but their IDA object lifetime must be contained.
   Evidence: `src\vuln\microcode_engine.hpp` exposes `generate()`, `mba_handle_t`, `dump_mba()`, visitors, def-use helpers, and call-target helpers; `src\vuln\symbolic_engine.hpp` exposes path constraints, symbolic values, alias proofs, and simplification results.

10. The chain-verifier UI should not reuse the existing synchronous "save database context" pattern.
    That pattern performs decompilation, disassembly generation, xref scanning, and file writes in one foreground action. The new verifier must snapshot bounded pieces on the IDA main thread and do expensive solving/tracing on background workers.

## SDK Evidence Snippets

All IDA API guidance below is grounded in `C:\Users\ruar1337\AiDAPrivate\ida-sdk\src\include`.

### SDK-01: PLUGIN_MULTI and plugmod lifecycle

`ida-sdk\src\include\loader.hpp`

```cpp
#define PLUGIN_MULTI    0x0100  ///< The plugin can work with multiple idbs in parallel.
                                ///< init() returns a pointer to a plugmod_t object
                                ///< run/term functions are not used.
                                ///< Virtual functions of plugmod_t are used instead.
```

`ida-sdk\src\include\idp.hpp`

```cpp
struct plugmod_t : public modctx_t
{
  virtual bool idaapi run(size_t arg) = 0;
  bool hook_event_listener(hook_type_t hook_type, event_listener_t *cb, int hkcb_flags=0)
  {
    return ::hook_event_listener(hook_type, cb, this, hkcb_flags);
  }
  virtual ~plugmod_t() {}
};
```

### SDK-02: UI hook ownership and automatic listener removal

`ida-sdk\src\include\idp.hpp`

```cpp
idaman bool ida_export hook_event_listener(
        hook_type_t hook_type,
        event_listener_t *cb,
        const void *owner,
        int hkcb_flags=0);
...
/// A listener is uninstalled automatically when the owner module is unloaded
/// or when the listener object is being destroyed
idaman bool ida_export unhook_event_listener(
        hook_type_t hook_type,
        event_listener_t *cb);
...
virtual ~event_listener_t() { remove_event_listener(this); }
```

### SDK-03: UI readiness, database initialization, and popup population events

`ida-sdk\src\include\kernwin.hpp`

```cpp
ui_database_inited,   ///< cb: database initialization has completed.
...
ui_ready_to_run,      ///< cb: all UI elements have been initialized.
                      ///< Automatic plugins may hook to this event to
                      ///< perform their tasks.
...
ui_finish_populating_widget_popup,
                      ///< cb: IDA is about to be done populating the
                      ///< context menu for a widget.
                      ///< This is your chance to attach_action_to_popup().
```

### SDK-04: Actions must use heap/owned handlers and cheap update callbacks

`ida-sdk\src\include\kernwin.hpp`

```cpp
/// Because the actions will need to call the handler's activate() and
/// update() methods at any time, you shouldn't build your action handler
/// on the stack.
inline bool register_action(const action_desc_t &desc)
```

```cpp
/// Update an action.
/// This is called when the context of the UI changed...
/// Note: This callback is not meant to change anything in the
/// application's state, except by calling one (or many) of
/// the "update_action_*()" functions on this very action.
virtual action_state_t idaapi update(action_update_ctx_t *ctx) = 0;
```

```cpp
#define ADF_OWN_HANDLER   0x01  ///< handler is owned by the action; it'll be
                                ///< destroyed when the action is unregistered.
#define ACTION_DESC_LITERAL_PLUGMOD(name, label, handler, plgmod, shortcut, tooltip, icon) \
  { sizeof(action_desc_t), name, label, handler, plgmod, shortcut, tooltip, icon, ADF_OT_PLUGMOD }
```

### SDK-05: Menu and popup actions are non-modal integration points

`ida-sdk\src\include\kernwin.hpp`

```cpp
/// After an action has been created, it is possible to attach it
/// to menu items (attach_action_to_menu()), or to popup menus
/// (attach_action_to_popup()).
inline bool register_action(const action_desc_t &desc)
```

```cpp
/// Insert a previously-registered action into the widget's popup menu
/// This function has two "modes": 'single-shot', and 'permanent'.
inline bool attach_action_to_popup(
        TWidget *widget,
        TPopupMenu *popup_handle,
        const char *name,
        const char *popuppath = nullptr,
        int flags=0)
```

### SDK-06: Dockable/non-modal widgets

`ida-sdk\src\include\kernwin.hpp`

```cpp
/// Create an empty widget, serving as a container for custom
/// user widgets
inline TWidget *create_empty_widget(const char *title, int icon = -1)
```

```cpp
/// Display a widget, dock it if not done before
inline void display_widget(TWidget *widget, uint32 options, const char *dest_ctrl=nullptr)
```

```cpp
#define WOPN_PERSIST           0x00000040u ///< widget will remain available when starting or stopping debugger sessions
#define WOPN_NOT_CLOSED_BY_ESC 0x00000100u ///< override idagui.cfg:CLOSED_BY_ESC: esc will not close
#define WOPN_DP_TAB            (DP_TAB << WOPN_DP_SHIFT)
```

### SDK-07: Wait boxes block the UI and must be balanced

`ida-sdk\src\include\kernwin.hpp`

```cpp
/// Display a dialog box with "Please wait...".
///   "HIDECANCEL\n": the cancel button won't be added to the dialog box
///                   and user_cancelled() will always return false
/// Plugins must call hide_wait_box() to close the dialog box, otherwise
/// the user interface will remain disabled.
...
THREAD_SAFE AS_PRINTF(1, 2) inline void show_wait_box(const char *format, ...)
```

### SDK-08: Modal dialogs wait for user input

`ida-sdk\src\include\kernwin.hpp`

```cpp
/// Display warning dialog box and wait for the user to press Enter or Esc.
THREAD_SAFE AS_PRINTF(1, 2) inline ssize_t warning(const char *format, ...)
```

```cpp
/// Display info dialog box and wait for the user to press Enter or Esc.
THREAD_SAFE AS_PRINTF(1, 2) inline ssize_t info(const char *format, ...)
```

```cpp
/// Display a dialog box and get choice from "Yes", "No", "Cancel".
AS_PRINTF(2, 3) inline int ask_yn(int deflt, const char *format, ...)
```

```cpp
/// Display a dialog box and wait for the user to input a text string
AS_PRINTF(3, 4) inline bool ask_str(qstring *str, int hist, const char *format, ...)
```

```cpp
/// Display a dialog box and wait for the user to input a file name
AS_PRINTF(3, 4) inline char *ask_file(
        bool for_saving,
        const char *defval,
        const char *format,
        ...)
```

### SDK-09: IDA global cancellation flag is UI/global, not a per-job cancellation model

`ida-sdk\src\include\kernwin.hpp`

```cpp
/// Test the cancellation flag (::ui_test_cancelled).
/// \retval true   Cancelled, a message is displayed
/// \retval false  Not cancelled
THREAD_SAFE inline bool user_cancelled() { return callui(ui_test_cancelled).cnd; }
```

### SDK-10: execute_sync flags and exception contract

`ida-sdk\src\include\kernwin.hpp`

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

```cpp
#define MFF_NOWAIT 0x0004       ///< Do not wait for the request to be executed.
                                ///< the caller should ensure that the request is not
                                ///< destroyed until the execution completes.
                                ///< the request must be created using the 'new' operator
```

```cpp
/// Callback to be executed.
/// If this function raises an exception, execute_sync() never returns.
virtual ssize_t idaapi execute() = 0;
...
THREAD_SAFE inline ssize_t execute_sync(exec_request_t &req, int reqf)
```

### SDK-11: UI requests and request cancellation

`ida-sdk\src\include\kernwin.hpp`

```cpp
/// The UI requests will be dispatched in the context of the main thread.
THREAD_SAFE inline int execute_ui_requests(ui_request_t *req, ...)
```

```cpp
/// Try to cancel an asynchronous exec request
THREAD_SAFE inline bool cancel_exec_request(int req_id)
```

```cpp
/// Try to cancel asynchronous exec requests created by the specified thread.
THREAD_SAFE inline int cancel_thread_exec_requests(qthread_t tid)
```

### SDK-12: Timers run on the main thread

`ida-sdk\src\include\kernwin.hpp`

```cpp
/// Register a timer (::ui_register_timer).
/// Timer functions are thread-safe and the callback is executed
/// in the context of the main thread.
THREAD_SAFE inline qtimer_t register_timer(
        int interval_ms,
        int (idaapi *callback)(void *ud),
        void *ud)
```

### SDK-13: IDA threads, semaphores, and main-thread checks

`ida-sdk\src\include\pro.h`

```cpp
idaman THREAD_SAFE qthread_t ida_export qthread_create(qthread_cb_t *thread_cb, void *ud);
idaman THREAD_SAFE bool ida_export qthread_join(qthread_t q);
idaman THREAD_SAFE qthread_t ida_export qthread_self(void);
idaman THREAD_SAFE bool ida_export is_main_thread(void);
...
idaman THREAD_SAFE qsemaphore_t ida_export qsem_create(const char *name, int init_count);
idaman THREAD_SAFE bool ida_export qsem_post(qsemaphore_t sem);
idaman THREAD_SAFE bool ida_export qsem_wait(qsemaphore_t sem, int timeout_ms);
```

### SDK-14: Active modal widget does not detect wait boxes

`ida-sdk\src\include\kernwin.hpp`

```cpp
/// Get the current, active modal TWidget instance.
/// Note that in this context, the "wait dialog" is not considered:
/// this function will return nullptr even if it is currently shown.
inline TWidget *get_active_modal_widget()
```

### SDK-15: Hex-Rays decompile and microcode generation support no-wait operation

`ida-sdk\src\include\hexrays.hpp`

```cpp
#define DECOMP_NO_WAIT      0x0001 ///< do not display waitbox
...
cfuncptr_t hexapi decompile(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        int decomp_flags=0);
...
mba_t *hexapi gen_microcode(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        const mlist_t *retlist=nullptr,
        int decomp_flags=0,
        mba_maturity_t reqmat=MMAT_GLBOPT3);
```

### SDK-16: Hex-Rays microcode object is a decompiler-owned data structure

`ida-sdk\src\include\hexrays.hpp`

```cpp
/// Array of micro blocks representing microcode for a decompiled function.
/// The first micro block is the entry point, the last one is the exit point.
class mba_t
```

```cpp
inline int mba_t::for_all_insns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mba_t_for_all_insns, this, &mv);
}
```

## Risk Register

1. Modal UI risk.
   Existing `ask_yn()`, `ask_file()`, `ask_str()`, `warning()`, `info()`, and `show_wait_box()` paths can halt a reverse engineer's session. SDK-07 and SDK-08 make this explicit. The new verifier must not call them.

2. Main-thread monopolization risk.
   Long decompilation, graph traversal, SMT setup, whole-database scans, JSON parsing, and file I/O inside `action_handler_t::activate()`, UI events, timers, or one `execute_sync()` body can freeze IDA. SDK-04, SDK-10, and SDK-12 require cheap UI callbacks and carefully scoped main-thread requests.

3. Exception bridge risk.
   SDK-10 states that if `exec_request_t::execute()` raises an exception, `execute_sync()` never returns. Every main-thread request body must catch C++ exceptions and Windows SEH faults and convert them to structured failure results.

4. IDA object lifetime risk.
   `func_t*`, `cfuncptr_t`, `mba_t*`, `minsn_t*`, `mop_t*`, `TWidget*`, and chooser/widget internals are not safe to hand to arbitrary background workers as long-lived objects. The worker boundary must use immutable copied snapshots, not live SDK objects. SDK-10, SDK-15, and SDK-16 support an extract-then-release model.

5. Cancellation illusion risk.
   `user_cancelled()` is a UI/global cancellation flag and can display a message. SDK-09 makes it unsuitable as the verifier's primary cancellation token. Chain verification needs per-job cancellation, deadlines, and request cancellation.

6. Unload deadlock risk.
   Joining plugin workers in `~aida_plugin_t()` is necessary to avoid executing unloaded code, but unbounded joins can hang IDA shutdown. Existing owned threads are good; new verifier threads need cooperative cancellation, request cancellation, and shared lifetime state so teardown never waits on a stuck solver while holding IDA resources.

7. Multi-IDB ownership risk.
   `PLUGIN_MULTI` means each IDB has its own `plugmod_t`. Cross-binary verification must preserve per-IDB ownership and route IDA API calls to the correct instance. SDK-01 requires this to be designed as multi-instance coordination, not a single global mutable database view.

8. Widget lifetime race risk.
   Non-modal views can be closed while jobs continue. Background workers must publish state into service-owned models, and UI timers must tolerate a null/closed widget. SDK-06 and SDK-12 support a model/view separation.

9. Hidden modal risk.
   `get_active_modal_widget()` does not report wait boxes. SDK-14 means a "no modal active" check is not enough; wait boxes must be banned directly.

10. Hex-Rays wait/progress risk.
    Decompiler APIs can display wait UI unless `DECOMP_NO_WAIT` is used. SDK-15 supports no-wait decompile/microcode generation; the verifier must always use `DECOMP_NO_WAIT` and its own non-modal progress stream.

## Production Implementation Plan

### Phase 1: Establish a chain-verification service owned by `aida_plugin_t`

Recommended change: add a `chain_verifier_service_t` member owned by `aida_plugin_t`, initialized lazily after `ui_ready_to_run` and stopped before existing MCP/server teardown.

IDA API basis: use `PLUGIN_MULTI` and `plugmod_t` ownership from SDK-01; hook UI events through the plugmod owner as in SDK-02 and SDK-03.

Implementation requirements:

- Service lifetime is per IDB, not global.
- A global coordinator may exist only as a registry of weak service handles keyed by binary identity and instance ID.
- The service starts in "idle / ready" state without launching heavy analysis.
- No verification work begins during plugin construction, `init()`, `ui_database_inited`, or `ui_ready_to_run`; those callbacks only register actions, restore persisted UI state, and enqueue cheap status refresh.
- Startup failures are shown in the non-modal Chain Verify panel and `msg()` output only, never with `warning()` or `info()`.
- Existing security checks, standalone auth, ARC verification, anti-re initialization, module pinning, timer ownership, and watchdog shutdown remain intact.

### Phase 2: Replace modal verifier UX with a persistent non-modal dock

Recommended change: create `AiDA Chain Verify` as a persistent docked widget with a job list, input editor/path field, status timeline, result tree, branch-condition table, side-effect table, and Cancel button.

IDA API basis: use `create_empty_widget()` and `display_widget()` with `WOPN_PERSIST`, `WOPN_NOT_CLOSED_BY_ESC`, and `WOPN_DP_TAB` from SDK-06. Use menu/popup actions from SDK-05.

Implementation requirements:

- Actions:
  - `aida:chain_verify_open_panel`
  - `aida:chain_verify_current_function_as_link`
  - `aida:chain_verify_start`
  - `aida:chain_verify_cancel`
  - `aida:chain_verify_copy_result_json`
- Action `update()` callbacks are O(1), context-only, and state-read-only, per SDK-04.
- Popup actions are attached only in `ui_finish_populating_widget_popup`, with no analysis, file I/O, network I/O, decompilation, or logging loops in the popup callback, per SDK-03 and SDK-05.
- Inputs are accepted through the docked panel text editor, explicit path text field, recent chain list, or MCP tool payload. File browsing via `ask_file()` is not used.
- Legal/EULA or disabled-state acceptance is not shown as `ask_yn()`. If acceptance is still required inside IDA, it is a non-modal panel state with explicit Accept/Decline actions; disabled plugin actions open the panel and explain status without blocking.
- Progress is rendered in the dock and streamed to MCP clients. The Output window receives concise lifecycle breadcrumbs through `msg()` only.

### Phase 3: Add a strict IDA main-thread gateway

Recommended change: introduce a single `ida_gateway_t` for all new verifier calls into IDA SDK APIs.

IDA API basis: use `execute_sync()` flags and exception contract from SDK-10, request cancellation from SDK-11, main-thread checks from SDK-13, and modal-awareness nuance from SDK-14.

Implementation requirements:

- All database, Hex-Rays, widget, action, netnode, xref, function, segment, type, and UI API calls made by the verifier go through the gateway unless `is_main_thread()` proves the caller is already in a sanctioned main-thread slice.
- Worker threads never call IDA database APIs directly.
- Gateway request types catch:
  - `vd_failure_t`
  - `std::bad_alloc`
  - `std::exception`
  - all other C++ exceptions
  - Windows SEH faults on Windows builds
- No exception crosses `exec_request_t::execute()`, because SDK-10 says `execute_sync()` never returns if it does.
- `MFF_READ` is used for read-only extraction and decompilation snapshot capture.
- `MFF_WRITE` is used only for explicit user-requested database mutations such as optional annotations, and never for default verification.
- `MFF_FAST` is used only for UI-only calls that do not query the database, matching SDK-10.
- `MFF_NOWAIT` is used only for heap-allocated requests whose lifetime is owned by a tracked request object until completion or cancellation, matching SDK-10.
- If `get_active_modal_widget()` returns non-null, non-urgent requests are deferred. This check is not a substitute for the direct wait-box ban because SDK-14 excludes wait boxes.
- Each request has a phase name, binary ID, function EA, deadline, start tick, end tick, and result status.
- Main-thread slice target:
  - p95 under 25 ms for UI refresh slices.
  - p95 under 75 ms for function metadata extraction.
  - p95 under 250 ms for one Hex-Rays microcode/decompile extraction, with larger functions split or marked "deferred".
  - no single gateway request performs whole-database traversal.

### Phase 4: Snapshot IDA/Hex-Rays state into immutable verifier facts

Recommended change: move the verifier boundary from "workers operate on IDA objects" to "main thread snapshots facts; workers solve over facts".

IDA API basis: use Hex-Rays `DECOMP_NO_WAIT`, `decompile()`, and `gen_microcode()` from SDK-15; treat `mba_t` as a decompiler-owned microcode structure per SDK-16; execute extraction through SDK-10.

Implementation requirements:

- Per-binary snapshot includes:
  - image identity: input path, loader name, processor, bitness, image base, MD5, segments, imports, exports.
  - function identity: start/end EA, flags, name, demangled name, thunk/external/tail status.
  - call graph facts: direct calls, indirect call sites, imports, known helper calls.
  - CFG facts: blocks, edges, conditional branch EAs, branch predicate text, fallthrough/taken destinations.
  - microcode facts: normalized instruction facts, register reads/writes, memory reads/writes, constants, call arguments, spoiled registers, stack deltas.
  - decompiler facts: pseudocode line mapping and ctree summary only if needed for human evidence.
- Workers receive only copied POD/JSON/string/vector data. They do not receive `mba_t*`, `mblock_t*`, `minsn_t*`, `mop_t*`, `func_t*`, `cfunc_t*`, or `TWidget*`.
- Every Hex-Rays call uses `DECOMP_NO_WAIT`.
- Missing or failing decompilation is a per-function evidence failure, not a plugin failure. The result records `unsupported` or `inconclusive` with exact phase and EA.
- Very large functions are processed in extraction chunks with checkpointed progress, not in one main-thread request.

### Phase 5: Implement cancellable background job execution

Recommended change: add a verifier job manager with worker threads, a bounded queue, per-job cancellation tokens, and immutable progress/result state.

IDA API basis: use `qthread_create()`, `qthread_join()`, `qsemaphore_t`, and `is_main_thread()` from SDK-13; use request cancellation from SDK-11.

Implementation requirements:

- Job model fields:
  - `job_id`
  - `generation`
  - `state`: queued, extracting, solving, finalizing, cancelled, failed, complete
  - `cancel_requested`
  - `deadline_ms`
  - `started_ms`
  - `last_progress_ms`
  - `active_binary`
  - `active_function`
  - `active_phase`
  - `pending_execute_request_ids`
  - `worker_thread_ids`
- Cancellation sources:
  - docked panel Cancel button
  - MCP `chain_verify_cancel`
  - IDB closing/unload
  - plugin shutdown
  - deadline expiration
  - memory-pressure or failure-budget trip
- Cancellation behavior:
  - set the per-job token first.
  - cancel pending `MFF_NOWAIT` request IDs with `cancel_exec_request()`.
  - cancel worker-thread pending requests with `cancel_thread_exec_requests()` where qthread identity is available.
  - wake semaphores/condition variables.
  - return a structured partial result with completed links, last proven state, and cancellation phase.
- Background work never polls `user_cancelled()` as the primary mechanism. SDK-09 allows it to display a message and it is global, so it is unsuitable for per-job verifier cancellation.
- Worker threads use qthreads when they may schedule IDA requests. Pure solver workers may use standard C++ threads only if their lifetime is owned by the service and they never call IDA APIs.
- The job manager limits concurrency:
  - one active extraction per IDB.
  - bounded parallel solving off main thread.
  - configurable CPU budget with a conservative default.
  - no unbounded `std::async` fan-out.

### Phase 6: Make progress and UI refresh timer-driven

Recommended change: use a main-thread timer to drain a small progress queue into the non-modal panel.

IDA API basis: timers execute on the main thread per SDK-12; docked widgets come from SDK-06; UI requests can be dispatched on the main thread per SDK-11.

Implementation requirements:

- Timer callback runs every 100-250 ms while the panel is visible or jobs are active.
- Timer callback does bounded work:
  - drain at most N progress events.
  - coalesce repeated events by job/phase.
  - update model/view state.
  - return quickly with next interval.
- Timer callback does not decompile, scan, read files, query network, run SMT, or call into ToolRegistry.
- UI-only cross-thread requests may use `execute_ui_requests()` for one-shot open/activate operations; high-frequency progress uses the timer to avoid queue pressure.
- If the widget is closed, workers continue; progress is retained in service state and the timer backs off.
- If IDA is shutting down, the timer unregisters itself and stops scheduling UI work.

### Phase 7: Integrate multi-binary coordination without global mutable IDA state

Recommended change: introduce a chain session coordinator that can route extraction to the correct IDB instance and merge immutable facts into one trace model.

IDA API basis: `PLUGIN_MULTI` per-IDB ownership from SDK-01 and owned event hooks from SDK-02.

Implementation requirements:

- Each binary in the chain is represented by a `binary_descriptor`:
  - logical name from chain input
  - expected module/file name
  - expected image base or relocation policy
  - expected IDB MD5/input MD5 when available
  - owning AiDA instance ID
- Coordinator resolves descriptors to loaded IDBs through existing instance registry/MCP mechanisms. Missing binaries are non-modal "missing evidence" diagnostics, not popups.
- Each IDB service performs only its own IDA extraction.
- Cross-binary edge facts are merged off main thread:
  - call/return ABI handoff
  - register state transfer
  - memory object identity
  - side-effect compatibility
  - trigger event reachability
- Per-link "verified" is never final. The final verdict requires link-boundary compatibility and complete path reachability across all binaries.

### Phase 8: Define chain-verification job outputs for the UI

Recommended change: every result is structured, navigable, and evidence-backed.

Implementation requirements:

- Full chain result:
  - verdict: confirmed, refuted, inconclusive, unsupported, cancelled, timeout
  - continuous path trace across binaries
  - branch condition table with required direction, actual/satisfiable direction, and witness state
  - register state timeline
  - memory state timeline
  - call-boundary ABI state
  - side-effect ledger
  - postcondition/precondition compatibility matrix
  - trigger confirmation status
  - logical data-flow contradiction findings
  - collateral damage summary
  - assumption gaps
- Every finding has:
  - binary
  - function
  - EA/RVA
  - phase
  - source fact IDs
  - reason
  - confidence/verdict
- The UI can jump to relevant EAs without modal dialogs.
- Large results are virtualized/paged in the UI. Rendering never builds one enormous text blob on the main thread.

### Phase 9: Replace or fence existing modal paths before enabling the verifier by default

Recommended change: remove modal calls from plugin operational paths that can be reached during verifier use.

IDA API basis: SDK-07 and SDK-08 show wait boxes and `ask_*`/`warning()`/`info()` block. SDK-14 shows wait boxes are not covered by active-modal detection.

Implementation requirements:

- Ban these APIs from the chain verifier and default plugin UX:
  - `show_wait_box`
  - `replace_wait_box`
  - `hide_wait_box` as part of verifier progress
  - `warning`
  - `info`
  - `ask_yn`
  - `ask_buttons`
  - `ask_file`
  - `ask_str`
  - Win32 `MessageBox*`
  - `error`
- Existing settings/API-key prompts must become non-modal panel state or standalone-side configuration state.
- Existing database export should be migrated to a background job or left outside the verifier menu until non-modal.
- Any remaining legacy modal call must be behind an explicit compatibility setting that defaults off and is not reachable from chain verification.
- Code review gate: new code under `src\vuln`, `src\actions.*`, `src\aida.*`, and `src\mcp_server.*` cannot introduce those APIs.

### Phase 10: Preserve shutdown safety

Recommended change: verifier teardown must be explicit and ordered.

IDA API basis: qthread join/cancel facilities from SDK-13 and execute request cancellation from SDK-11.

Implementation requirements:

- Teardown order:
  1. mark service stopping.
  2. unregister UI timer.
  3. disable actions or make them open read-only shutdown status.
  4. set cancellation on all active jobs.
  5. cancel pending execute requests.
  6. wake worker queues.
  7. join cooperative workers with bounded waits outside IDA main-thread request bodies.
  8. retain shared state until late workers have observed cancellation and exited.
  9. close/detach widget if still live.
  10. unregister actions after no action handler can access freed service state.
- Worker code never captures raw `this` unless the owner lifetime is proven. Use shared service state or intrusive lifetime token.
- If a worker exceeds shutdown budget, the plugin records a fatal non-modal/output diagnostic and leaves shared state pinned until process exit rather than freeing memory still reachable by the worker.
- No destructor path calls modal UI, wait boxes, network auth, full GraphRAG save, or solver shutdown while holding UI locks.

## No-Popup and No-Freeze Rules

1. No modal dialogs in verifier code.
   `ask_yn()`, `ask_buttons()`, `ask_file()`, `ask_str()`, `warning()`, `info()`, `error()`, and `MessageBox*` are forbidden because SDK-08 shows they wait for user input.

2. No wait boxes in verifier code.
   `show_wait_box()` and `replace_wait_box()` are forbidden because SDK-07 says the UI remains disabled until balanced by `hide_wait_box()`. `HIDECANCEL` is also forbidden because SDK-07 says it makes `user_cancelled()` always return false.

3. No long work in action update/activation.
   Action `update()` only checks widget type, service state, and cached availability. SDK-04 says update callbacks are not meant to change application state.

4. No long work in UI hooks.
   `ui_ready_to_run`, `ui_database_inited`, and popup events from SDK-03 only register, attach, or enqueue. They never decompile, solve, scan, or block.

5. No direct IDA database API from background workers.
   Workers request snapshots through the gateway using SDK-10. Workers only process immutable copied facts.

6. No whole-database foreground loops.
   Whole database work is chunked into cancellable extraction requests and background processing.

7. No global cancellation dependence.
   The verifier uses per-job tokens. `user_cancelled()` from SDK-09 is not used for job cancellation.

8. No uncaught exceptions across IDA callbacks.
   Every action activation, UI event, timer, qthread entry, MCP handler, and `exec_request_t::execute()` body catches failures and records a structured error.

9. No UI rendering from worker threads.
   Workers publish state; the SDK-12 timer or SDK-11 UI requests update UI on the main thread.

10. No unbounded memory growth.
    Progress, trace events, path candidates, solver witnesses, and logs have bounded retention with explicit truncation markers in the result.

## Threading and Cancellation Model

### Components

- `chain_verifier_service_t`: per-IDB owner in `aida_plugin_t`.
- `chain_job_manager_t`: owns job queue, workers, active jobs, cancellation tokens, result cache.
- `ida_gateway_t`: only path from verifier to IDA SDK database/UI APIs.
- `chain_verify_view_model_t`: thread-safe immutable/current UI state.
- `chain_verify_widget_t`: non-modal view; no ownership of workers.
- `chain_session_coordinator_t`: optional cross-IDB coordinator using instance IDs.

### Main-thread work

Allowed on main thread:

- action registration/unregistration.
- popup action attachment.
- non-modal widget create/display/activate.
- timer progress drain.
- bounded IDA database extraction through `execute_sync(MFF_READ)`.
- explicit user-requested annotations through `execute_sync(MFF_WRITE)`.

Forbidden on main thread:

- SMT solving.
- complete cross-binary path search.
- whole-database scans in one callback.
- network calls.
- blocking file import/export.
- waiting on worker completion.
- modal UI.

### Worker work

Allowed on workers:

- parse chain JSON.
- validate chain schema.
- schedule bounded IDA snapshots through the gateway.
- build cross-binary trace graph from immutable facts.
- run branch satisfiability and postcondition/precondition matching.
- run register/memory symbolic propagation.
- run solver queries.
- write result artifacts to service-owned storage after cancellation checks.

Forbidden on workers:

- direct IDA SDK database calls.
- direct widget calls.
- holding live Hex-Rays objects.
- blocking shutdown without observing cancellation.

### Cancellation checkpoints

Every phase checks cancellation:

- before scheduling IDA extraction.
- after each `execute_sync()` completion.
- before and after each function snapshot.
- before every solver call.
- at path-search node expansion boundaries.
- before result publish.
- during UI export/copy operations.

Cancellation must complete visibly:

- UI state changes to `cancelled` or `cancelling` within 250 ms.
- IDA main-thread extraction stops scheduling new requests immediately.
- solver cancellation returns partial proof state or timeout state.
- final result lists what was proven before cancellation.

## Failure Containment Strategy

1. Main-thread request containment.
   Every gateway request wraps its entire `execute()` body. No exception crosses `execute_sync()` because SDK-10 says that prevents return to the caller.

2. Worker containment.
   Every worker entry has a top-level C++ catch-all and Windows SEH guard. The job fails, not IDA.

3. UI containment.
   Action handlers, UI event listeners, timers, and widget callbacks catch all exceptions and publish non-modal errors.

4. Hex-Rays containment.
   `vd_failure_t`, null `cfuncptr_t`, null `mba_t*`, and malformed microcode are normal unsupported evidence outcomes. They do not disable the plugin.

5. Per-function quarantine.
   A function that repeatedly crashes or times out extraction is quarantined for the current job with exact EA, binary, and phase. The chain result becomes inconclusive or unsupported if that function is required.

6. Failure budget.
   Jobs have a configurable failure budget. Exhaustion stops the job cleanly and reports the exact limiting failures.

7. Result durability.
   Partial results are published incrementally so a crash or cancellation window does not lose all evidence.

8. Logging.
   Breadcrumbs include job ID, binary ID, phase, function EA/RVA, request ID, worker ID, elapsed time, cancellation state, exception code, and verdict. Logs never require a popup to diagnose failures.

9. Memory pressure.
   Large traces page to disk-backed/cache-backed result storage. UI renders summaries and pages details on demand.

10. Fail-closed semantics.
    Unknown, missing, crashed, timed-out, or unsupported evidence never upgrades a link to verified. It yields inconclusive/unsupported and keeps the chain unconfirmed.

## Files Likely Affected During Implementation

- `src\aida.hpp`
  Add service owner fields and lifecycle declarations.

- `src\aida.cpp`
  Initialize/stop the verifier service, register actions, remove modal disabled/run behavior from verifier paths, preserve plugin pinning and shutdown ordering.

- `src\actions.hpp`
  Add chain verifier action handlers and keep updates cheap.

- `src\actions.cpp`
  Add non-modal chain actions; migrate verifier-adjacent modal action behavior.

- `src\mcp_server.cpp`
  Add safe gateway use for chain-verifier MCP tools, remove wait-box progress from verifier execution, expose job start/status/cancel/result streaming.

- `src\mcp_server.hpp`
  Expose any service registry hooks needed by MCP without leaking UI/widget ownership.

- `src\vuln\verification_engine.hpp`
  Extend or separate job-safe verifier interfaces from the current per-function SMT helpers.

- `src\vuln\verification_engine.cpp`
  Remove wait-box/user-cancel dependency from new verifier paths; keep old helpers only behind non-modal wrappers or migrate them.

- `src\vuln\verification_tools.hpp`
  Register chain verifier MCP tools.

- `src\vuln\verification_tools.cpp`
  Add chain job start/status/cancel/result tools with structured schemas.

- `src\vuln\microcode_engine.hpp`
  Add snapshot-friendly fact structs if existing JSON dump is insufficient.

- `src\vuln\microcode_engine.cpp`
  Ensure Hex-Rays extraction always uses `DECOMP_NO_WAIT`, catches failures, and returns copied facts.

- `src\vuln\symbolic_engine.hpp`
  Add cross-function/cross-binary state structures or move them to new chain files.

- `src\vuln\symbolic_engine.cpp`
  Reuse existing symbolic primitives without carrying live IDA objects into workers.

- `src\vuln\chain_verifier.hpp`
  New production interface for chain sessions, links, facts, verdicts, and results.

- `src\vuln\chain_verifier.cpp`
  New cross-binary trace engine over immutable snapshots.

- `src\vuln\chain_job_manager.hpp`
  New job/cancel/progress/result ownership.

- `src\vuln\chain_job_manager.cpp`
  New queue, workers, deadlines, cancellation, and failure containment.

- `src\vuln\ida_gateway.hpp`
  New safe main-thread gateway abstraction.

- `src\vuln\ida_gateway.cpp`
  New `execute_sync()` request wrappers, request IDs, cancellation, and exception containment.

- `src\vuln\chain_verify_ui.hpp`
  New non-modal panel interface and view model.

- `src\vuln\chain_verify_ui.cpp`
  New docked widget, timer refresh, input editor, job table, result tree, and cancel command.

- `src\settings.hpp`
  Persist non-modal verifier UI preferences and recent chain files/paths without modal prompts.

- `src\settings.cpp`
  Load/save verifier settings silently with output/log diagnostics only.

- `src\instance_registry.hpp`
  Add chain-verifier instance lookup helpers if current registry is insufficient.

- `src\instance_registry.cpp`
  Route multi-IDB binary descriptor resolution without global mutable IDA state.

- `CMakeLists.txt` or relevant source list
  Add new source files after implementation.

## Acceptance Criteria

1. Plugin load/unload stability.
   Loading the plugin, opening the panel, starting no jobs, closing the IDB, and exiting IDA produces no crash, no hang, no orphan worker, and no modal UI.

2. No modal UI.
   Chain verification and all plugin paths reachable from it do not call `ask_yn`, `ask_buttons`, `ask_file`, `ask_str`, `warning`, `info`, `error`, `MessageBox*`, `show_wait_box`, or `replace_wait_box`.

3. IDA responsiveness.
   While a multi-binary chain job is running, the reverse engineer can scroll disassembly, open context menus, switch tabs, rename a local symbol, and close/reopen the Chain Verify panel without visible stalls.

4. Main-thread budget.
   Instrumented gateway slices report p95 under the targets defined in Phase 3 and no unbounded whole-database request.

5. Cancellation.
   Cancel from UI and MCP updates visible status within 250 ms and reaches terminal cancelled state within 2 seconds for normal extraction/solver phases, with partial evidence preserved.

6. Exception containment.
   Fault injection in action handlers, timers, worker threads, Hex-Rays extraction, JSON parsing, and solver calls produces structured job errors without crashing IDA.

7. No live IDA object leakage.
   Code review and tests prove workers do not store `func_t*`, `cfunc_t*`, `mba_t*`, `mblock_t*`, `minsn_t*`, `mop_t*`, or `TWidget*` outside sanctioned main-thread scopes.

8. Multi-IDB correctness.
   A chain spanning at least three loaded binaries routes extraction to the correct IDB instances and reports missing binaries non-modally.

9. Case-study regressions.
   The verifier reports:
   - NTFS -> ETW zeros-vs-controlled-data mismatch and missing ETW trigger path.
   - AFD -> _setjmp hidden LIST_ENTRY self-reference precondition.
   - pvScan0 self-reference logical data-flow contradiction.

10. Fail-closed verdicts.
    Missing evidence, timeout, unsupported decompilation, cancelled jobs, and extraction failures never produce a confirmed chain.

11. Build and warning policy.
    After implementation, the host AI runs the canonical project build and verifies zero errors and zero new warnings. This planning subagent does not build.

12. MCP compatibility.
    MCP clients can start, cancel, poll, and fetch verifier results without causing IDA popups or blocking the IDA UI thread.

## Verification Plan

1. Static modal-ban scan.
   Run targeted source scans for banned APIs in verifier-reachable files:
   `show_wait_box`, `replace_wait_box`, `warning(`, `info(`, `ask_yn`, `ask_buttons`, `ask_file`, `ask_str`, `MessageBox`, `error(`, and verifier use of `user_cancelled`.

2. Static main-thread-gateway scan.
   Review new verifier files for direct IDA SDK calls outside `ida_gateway.*`, UI files, and action registration. Any direct database/Hex-Rays API in a worker file fails review.

3. Exception bridge test.
   Inject controlled exceptions inside representative `exec_request_t::execute()` bodies and verify callers receive structured error results and `execute_sync()` returns.

4. Worker crash containment test.
   Inject controlled C++ and SEH faults in background job phases. IDA remains alive; job transitions to failed with phase evidence.

5. Cancellation tests.
   Start jobs in extraction, solving, and finalization phases; cancel from UI and MCP; verify request cancellation, worker wakeup, partial result publication, and bounded completion.

6. UI responsiveness smoke.
   While a chain job runs on large functions, continuously scroll disassembly, open pseudocode, open context menus, switch tabs, edit names, and close/reopen the Chain Verify panel.

7. Multi-IDB routing test.
   Open IDBs for `afd.sys`, `ntoskrnl.exe`, and `win32kbase.sys`; submit a chain that references all three; verify extraction occurs in the owning instance and result facts carry the correct binary identity.

8. Missing-binary test.
   Submit the same chain with one IDB missing. The panel shows missing evidence, MCP returns structured unsupported/inconclusive status, and no popup appears.

9. Hex-Rays failure test.
   Run on thunks, externs, huge functions, malformed ranges, and functions that fail decompilation. Each becomes unsupported/inconclusive evidence, not a plugin failure.

10. Case-study regression suite.
    Encode the three `driver\PROGRESS.md` case studies as chain descriptions and assert the exact expected break classifications:
    - postcondition/precondition mismatch.
    - trigger not confirmed.
    - hidden intermediate check.
    - logical data-flow contradiction.

11. Shutdown test.
    Start long verification, close the panel, close IDB, and exit IDA. Verify timers unregister, workers cancel, pending requests are cancelled, no freed service state is accessed, and no shutdown modal appears.

12. Performance test.
    Record gateway slice histograms, worker CPU use, memory growth, progress queue depth, result size, and UI timer duration for small, medium, and large chain jobs.

13. Host build verification after implementation.
    The host AI runs `.\build-host.cmd` from repo root after code changes and validates the build summary and logs. This plan creation step does not run build tooling.

## Implementation Invariants

- The plugin owns the complete path evidence, not isolated links.
- The UI never blocks the reverse engineer.
- IDA SDK calls stay on the IDA main thread through bounded, exception-contained requests.
- Background workers operate only on copied immutable facts.
- Cancellation is per job, fast, and observable.
- Failures are structured evidence, not popups.
- Unknown evidence never becomes a confirmed chain.
- Teardown cancels first, releases later, and never frees state still reachable by workers.
