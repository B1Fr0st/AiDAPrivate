# AiDA IDA Lifecycle, UI, and Stability Plan Verification

Verification date: 2026-07-03

Assigned scope: IDA plugin lifecycle, UI integration, non-modal UX, background execution, cancellation, exception containment, IDA-main-thread safety, and IDA plugin source needed to verify this plan.

Verification result: NO. The source code does not prove 100% implementation of this plan. The plan must remain open.

This verification used source evidence only. No git commands were used. No build commands were run. No source code was modified.

## Current Implemented Evidence

1. The plugin remains a `PLUGIN_MULTI` plugmod design with a per-IDB `aida_plugin_t`.
   Evidence: `src\aida.hpp` declares `class aida_plugin_t : public plugmod_t`; `src\aida.cpp` constructs an `aida_plugin_t` from `init()`.

2. Existing plugin lifecycle hardening is still present.
   Evidence: `src\aida.cpp` registers actions during construction, verifies standalone runtime before operational initialization, registers `self_watchdog_timer`, stops MCP in the destructor, unhooks `HT_UI`, joins owned startup threads, saves analysis state, and unregisters actions.

3. The chain-verification engine and MCP manage surface exist.
   Evidence:
   - `CMakeLists.txt` includes `src/vuln/chain_binary_corpus.cpp`, `chain_model.cpp`, `chain_report.cpp`, `chain_schema.cpp`, `chain_state.cpp`, `chain_store.cpp`, `chain_budget.cpp`, `chain_extraction.cpp`, `chain_path_trace.cpp`, `chain_side_effects.cpp`, `chain_solver.cpp`, `chain_state_contracts.cpp`, `chain_trigger_trace.cpp`, and `chain_verification_engine.cpp`.
   - `src\agent_tools.cpp` calls `aida::vuln::chain_mcp::register_manage_tools()`.
   - `src\vuln\chain_verification_tools.hpp` registers `ida_chain_manage`, `ida_project_manage`, `ida_extract_manage`, `ida_report_manage`, and `ida_job_manage`.
   - `src\vuln\chain_verification_tools.hpp` defines `ida_chain_manage` operations including `validate_spec`, `submit`, `start`, `status`, `cancel`, `resume`, `export`, `verify_link`, `boundary_match`, `trigger_confirm`, `get_report`, `list`, `evidence_fetch`, `explain_failure`, and `diagnostics`.

4. Some source-level extraction safety exists inside the chain engine.
   Evidence:
   - `src\vuln\chain_extraction.cpp` wraps `extract_module_snapshot()` and `extract_function_snapshot()` in local `exec_request_t` types and calls `execute_sync(req, MFF_READ)`.
   - Those request bodies catch C++ exceptions and convert failures into failed snapshots.
   - `src\vuln\chain_extraction.cpp` uses `DECOMP_NO_WAIT | DECOMP_WARNINGS` for ctree extraction.
   - `src\vuln\microcode_engine.cpp` uses `DECOMP_NO_WAIT | DECOMP_WARNINGS` in microcode generation.

5. Basic chain cancellation primitives exist in the engine layer.
   Evidence:
   - `src\vuln\chain_budget.cpp` defines `cancellation_token_t` and deadline/budget checks.
   - `src\vuln\chain_verification_engine.cpp` has `ChainVerificationEngine::cancel()` and checks cancellation during verification.

## Blocking Gaps

The following required plan features are missing, partial, or not proven by source evidence.

### 1. No per-IDB chain verifier service owned by `aida_plugin_t`

Required: `chain_verifier_service_t` owned by `aida_plugin_t`, lazily initialized after UI readiness and stopped before MCP/server teardown.

Current source state:
- `src\aida.hpp` fields are `actions_list`, `ui_listener`, `mcp_server`, `features_initialized`, `ui_listener_hooked`, `actions_registered`, `self_watchdog_timer`, and `disabled_detail`.
- There is no `chain_verifier_service_t` field and no lifecycle method for a chain verifier service.
- Searches for `chain_verifier_service_t`, `chain_job_manager_t`, `ida_gateway_t`, `chain_verify_view_model_t`, `chain_verify_widget_t`, and `chain_session_coordinator_t` find only this plan file.

Remaining work:
- Add a per-IDB service owner to `aida_plugin_t`.
- Initialize it only after UI readiness with no analysis work at construction/init time.
- Stop it before MCP teardown and before action handlers can access freed state.

### 2. No persistent non-modal Chain Verify dock or required IDA actions

Required actions:
- `aida:chain_verify_open_panel`
- `aida:chain_verify_current_function_as_link`
- `aida:chain_verify_start`
- `aida:chain_verify_cancel`
- `aida:chain_verify_copy_result_json`

Current source state:
- `src\aida.cpp` registers only:
  - `ai_assistant:copy_context`
  - `ai_assistant:save_database_context`
  - `ai_assistant:fix_analysis`
- `src\aida.cpp` popup attachment uses only those three legacy actions.
- Searches in `src\aida.cpp`, `src\actions.cpp`, and `src\vuln` find no `create_empty_widget`, `display_widget`, `WOPN_PERSIST`, `WOPN_NOT_CLOSED_BY_ESC`, `WOPN_DP_TAB`, `AiDA Chain Verify`, or chain verify widget implementation.

Remaining work:
- Implement a persistent docked `AiDA Chain Verify` panel.
- Add the required actions and keep `update()` callbacks O(1) and state-read-only.
- Attach chain actions in `ui_finish_populating_widget_popup` without analysis, file I/O, network I/O, decompilation, or logging loops.

### 3. Modal and wait-box calls remain in verifier-reachable/default plugin paths

Required: no verifier/default plugin UX path can call modal dialogs or wait boxes.

Current source state:
- `src\aida.cpp` still uses `ask_yn()` in `show_eula_dialog()`.
- `src\aida.cpp` still uses `warning()` in disabled-state paths and `info()` in `aida_plugin_t::run()`.
- `src\actions.cpp` still uses `ask_file()`, `warning()`, `show_wait_box()`, `replace_wait_box()`, `user_cancelled()`, and `hide_wait_box()` in `handle_save_database_context()`.
- `src\mcp_server.cpp` still uses `show_wait_box()`, `replace_wait_box()`, `hide_wait_box()`, and `user_cancelled()` in batch execution paths.
- `src\vuln\verification_engine.cpp` still uses `user_cancelled()` and `show_wait_box()` / `hide_wait_box()`.
- `src\vuln\symbolic_engine.cpp` still calls `user_cancelled()`.

Remaining work:
- Convert EULA/disabled/API-key/settings status to non-modal panel or standalone-side state.
- Remove or fence legacy modal actions behind an explicit compatibility setting that defaults off and is not reachable from chain verification.
- Remove wait-box progress and global `user_cancelled()` dependency from verifier-reachable execution paths.

### 4. No single strict `ida_gateway_t` abstraction

Required: all verifier database, Hex-Rays, widget, netnode, xref, function, segment, type, and UI calls go through `ida_gateway_t`, with request IDs, phase metadata, deadlines, timing, request cancellation, modal deferral, and exception containment.

Current source state:
- `src\vuln\chain_extraction.cpp` has local `exec_request_t` wrappers for module and function snapshots.
- There is no `src\vuln\ida_gateway.hpp`, no `src\vuln\ida_gateway.cpp`, and no `ida_gateway_t` type.
- The existing wrappers do not provide the full planned gateway contract: tracked request IDs, `cancel_exec_request()`, `cancel_thread_exec_requests()`, `MFF_NOWAIT` ownership, active modal deferral, phase/binary/function metadata, deadline enforcement, p95 slice telemetry, or a single enforced path for all verifier SDK access.

Remaining work:
- Add `ida_gateway_t` and migrate chain extraction/UI/action/database access through it.
- Add request metadata, timing, cancellation, exception containment, and modal deferral.
- Enforce that workers never call IDA SDK APIs directly outside gateway-approved main-thread slices.

### 5. Snapshot extraction is partial relative to the full immutable fact contract

Required: immutable facts covering image identity, functions, call graph, CFG, branch predicates, microcode reads/writes, memory/register effects, constants, call arguments, spoiled registers, stack deltas, ctree summaries, large-function chunking, and per-function unsupported evidence.

Current source state:
- `src\vuln\chain_extraction.cpp` captures useful module/function/ctree/microcode facts and serializes them.
- It does not prove the full required fact contract is complete for cross-binary chain verification.
- It does not prove large functions are split across multiple gateway requests with checkpointed progress.

Remaining work:
- Audit and complete fact coverage against the Phase 4 list.
- Add explicit chunking/deferred behavior for very large functions.
- Ensure worker-facing data remains copied POD/JSON/string/vector facts only.

### 6. No cancellable background job manager for chain verification

Required: `chain_job_manager_t` with workers, bounded queue, per-job cancellation tokens, pending execute request IDs, worker thread IDs, deadlines, partial results, and bounded shutdown.

Current source state:
- `src\vuln\chain_verification_tools.hpp` implements an in-memory job/report map for MCP responses.
- `ida_chain_manage.submit` / `start` creates a job, calls `build_chain_report(ctx, job_id)` synchronously, stores the report, marks the job completed, and returns the report in the same handler.
- `ida_chain_manage.cancel` calls `verify::engine().cancel()` and marks a stored job `cancelled`, but it does not prove cancellation of pending `execute_sync` requests, worker queues, semaphores, or solver threads.
- There is no `chain_job_manager_t`, no worker queue, no qthread worker ownership for chain jobs, and no bounded shutdown model.

Remaining work:
- Implement a real asynchronous job manager.
- Ensure UI and MCP cancellation transition to `cancelling` or `cancelled` quickly and preserve partial evidence.
- Track and cancel pending IDA requests and wake worker queues.

### 7. No timer-driven non-modal progress UI

Required: timer-driven progress drain every 100-250 ms while the panel is visible or jobs are active.

Current source state:
- `src\aida.cpp` registers only `self_watchdog_timer`.
- Searches find no chain UI timer, chain progress queue drain, or Chain Verify panel model/view state.

Remaining work:
- Add a main-thread timer for chain progress UI.
- Bound drained events per tick, coalesce progress, and back off when the widget is closed.

### 8. Multi-IDB coordination is not proven

Required: binary descriptors resolved to loaded IDBs through existing instance registry/MCP mechanisms, each IDB extracting only its own facts, missing binaries reported non-modally, and final verdict requiring link-boundary compatibility across binaries.

Current source state:
- Chain model/corpus structures exist, and the MCP manage surface has project/extract/report operations.
- There is no `chain_session_coordinator_t` or source-proven cross-IDB routing service.
- Searches do not find a `binary_descriptor` implementation matching the plan.

Remaining work:
- Implement explicit multi-IDB descriptor resolution and routing.
- Tie descriptors to owning AiDA instance IDs.
- Merge cross-binary facts off the main thread and keep per-link verified states non-final until boundary compatibility is proven.

### 9. UI output contract is not implemented

Required: structured navigable UI with continuous path trace, branch table, register/memory timeline, ABI state, side-effect ledger, compatibility matrix, trigger status, contradiction findings, collateral damage, assumption gaps, EA jumping, and virtualized large result rendering.

Current source state:
- Chain reports and MCP export/report operations exist.
- No Chain Verify UI exists in source.
- Therefore no source proves UI navigation, EA jumping, paging/virtualization, or non-blocking large result rendering.

Remaining work:
- Build the docked UI on top of service-owned state.
- Add paged/virtualized result views and non-modal EA navigation.

### 10. Shutdown safety for chain jobs is not implemented

Required: mark stopping, unregister timer, disable actions, cancel active jobs, cancel pending execute requests, wake queues, bounded worker joins, retain shared state for late workers, detach widget, then unregister actions.

Current source state:
- Existing plugin destructor handles legacy actions, timers, MCP, GraphRAG, DB save, and startup threads.
- There is no chain service, chain UI timer, chain worker queue, chain pending request tracking, or chain-specific shutdown sequence.

Remaining work:
- Implement ordered chain service teardown before freeing service/UI/job state.
- Leave shared state pinned on shutdown-budget breach instead of freeing memory reachable by late workers.

## Acceptance Criteria Status

1. Plugin load/unload stability: not proven for Chain Verify because no Chain Verify service/UI/jobs exist.
2. No modal UI: failed by source evidence in `src\aida.cpp`, `src\actions.cpp`, `src\mcp_server.cpp`, `src\vuln\verification_engine.cpp`, and `src\vuln\symbolic_engine.cpp`.
3. IDA responsiveness during chain jobs: not proven; current chain submit/start path is synchronous in the MCP handler.
4. Main-thread budget: not proven; no gateway telemetry or p95 slice accounting exists.
5. Cancellation: partial engine token exists, but UI/MCP request cancellation and bounded terminal state are not proven.
6. Exception containment: partial extraction wrappers exist, but full action/timer/worker/MCP/SEH containment is not proven.
7. No live IDA object leakage: partially aligned in extraction serialization, but not proven across workers because the worker architecture does not exist.
8. Multi-IDB correctness: not proven.
9. Case-study regressions: synthetic examples exist in chain engine source, but no source-proven regression suite for the three driver case studies is wired to the IDA host UI/lifecycle plan.
10. Fail-closed verdicts: partially represented in chain state/report code, but not proven for missing evidence, cancellation, timeout, and extraction failures through the planned UI/job lifecycle.
11. Build and warning policy: not performed by this verification subagent by instruction.
12. MCP compatibility: chain manage tools exist, but non-blocking start/cancel/poll/result semantics are not proven because submit/start currently completes synchronously.

## Remaining Implementation Work

1. Add `chain_verifier_service_t`, `chain_job_manager_t`, `ida_gateway_t`, `chain_verify_view_model_t`, `chain_verify_widget_t`, and `chain_session_coordinator_t`.
2. Wire `chain_verifier_service_t` into `aida_plugin_t` lifecycle with per-IDB ownership and ordered shutdown.
3. Add the five required Chain Verify actions and a persistent non-modal dock.
4. Remove or fence modal/wait-box legacy paths from verifier/default plugin UX.
5. Migrate verifier IDA SDK access through a single gateway with timing, deadlines, cancellation, modal deferral, and full exception containment.
6. Convert chain jobs to asynchronous background execution with bounded queues, per-job tokens, pending request tracking, progress publication, and partial results.
7. Add timer-driven UI progress draining and virtualized/paged result views.
8. Implement explicit multi-IDB binary descriptor resolution and cross-binary fact merging.
9. Complete immutable fact coverage and large-function chunking.
10. Add source-backed regression coverage for NTFS -> ETW, AFD -> `_setjmp`, and `pvScan0`.
11. After implementation, the host AI must run the canonical build wrapper and verify zero errors and zero new warnings.
