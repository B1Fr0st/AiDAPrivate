# Camoufox, Network, And Test Lab GUI Performance Plan

## Scope And Constraints

This plan covers GUI responsiveness costs from Camoufox, Burp/network views, reverse-MCP/browser lifecycle, and Test Lab paths that can consume CPU, GPU, worker threads, or the Camoufox service queue. It is based on the current worktree and only proposes changes. Camoufox remains mandatory; no Chrome, Edge, Firefox, system-browser, Playwright-stock-browser, or fileless launch fallback is acceptable.

No build or source edit was performed for this planning pass.

## Current Hot Paths

| Area | Exact files and symbols | Current possible idle/background cost |
| --- | --- | --- |
| Network startup | `src/standalone/src/main.cpp` line area 4476-4494, `seh_network_view_initialize`, `seh_mitm_proxy_pre_initialize`; `src/standalone/src/core/network/network_view.cpp` `network_view::initialize` lines 885-959 | Authorized startup eagerly calls `network_view::initialize`, which initializes `work_queue`, starts connection, capture, DNS, bandwidth, and fuzzer workers, then calls `aida::burp::initialize`. Startup also pre-initializes the MITM proxy. |
| Network polling workers | `network_view.cpp` `connection_poll_thread` lines 490-538, `capture_poll_thread` lines 541-604, `dns_poll_thread` lines 607-672, `bandwidth_poll_thread` lines 675-745, `start_*_worker` lines 751-880, `post_network_task` lines 229-255 | Long-lived workers are posted to the shared `work_queue`. Connection polling wakes every 1000 ms and checks driver readiness when the view was rendered recently. Capture, DNS, and bandwidth workers block on CVs, but still occupy shared worker slots once started. |
| Network render arming | `network_view.cpp` `network_view::render` lines 5884-6059; `network_view.hpp` `state_t` lines 151-300 | `last_render_tick_ms` is updated whenever the Network view renders, not only when the Connections tab is active. This can arm connection refresh due to any Network tab visibility. |
| Fuzzer | `network_view.cpp` `run_fuzzer_thread` lines 4105-4372, `render_fuzzer` lines 4605-4677 | Fuzzing can run up to 32 threads and push result updates while the GUI is active. Cancellation is cooperative through `fuzz_running`, but the worker fanout and UI buffers can still compete with rendering. |
| Burp eager module init | `src/standalone/src/core/network/burp/burp_module.cpp` `initialize` lines 94-150 | `network_view::initialize` eagerly initializes scope, stores, scanners, crawler, content discovery, subdomain enum, auth/JWT labs, WebSocket editor, logger, browser, CSP, technology detection, upstream proxy, Camoufox install, and headless view. This is too broad for startup and idle GUI. |
| MITM proxy pre-init | `src/standalone/src/core/network/mitm_proxy.cpp` `pre_initialize` lines 2197-2229, `listener_thread_func` lines 1996-2038, `shutdown` lines 2232-2245 | Pre-init posts a listener and worker pool jobs to the shared `work_queue` before the proxy is explicitly used. Listener uses 1 s `select` loops, and shutdown busy-waits until workers drain. |
| Browser tab lifecycle | `src/standalone/src/core/network/burp/browser_view.cpp` `render` lines 118-347; `src/standalone/src/core/network/burp/browser_launch.cpp` `launch` lines 428-543, `kill` lines 546-593, `kill_all` lines 596-627, `list_running` lines 660-728 | The Browser view calls Camoufox status/list operations from render and calls `launch` or `kill_all` synchronously on button clicks. `launch` calls `start_bridge`, optional `navigate(..., 30000)`, and status refreshes. `kill_all` calls `stop_bridge` and status refreshes. These can stall the UI thread. |
| Headless Camoufox polling | `src/standalone/src/core/network/burp/headless_view.cpp` constants lines 39-43, `schedule_status_poll` lines 208-266, `schedule_install_probe` lines 269-286, `run_start_bridge` lines 355-370, `run_stop_bridge` lines 373-387, `run_navigate` lines 390-405, `initialize` lines 1286-1292, `render` lines 1309-1324 | Headless view schedules status polling every 750 ms while visible. A ready bridge poll can call `get_status`, `get_console_logs`, `list_network_requests`, and `get_page_info`. These use bridge RPC deadlines up to 30 s and can keep the Camoufox service queue busy. Install probing is also posted through the shared `work_queue`. |
| Camoufox service queue and prewarm | `src/standalone/src/core/network/burp/camoufox_bridge.cpp` `post_bridge_task` lines 185-192, `prewarm_default_disabled` lines 296-304, `call_with_deadline` lines 4017-4648, `start_bridge` line area 6299-7130, `stop_bridge` line area 7611-7735, `force_cleanup` line area 7736-7831, `ensure_ready` lines 7970-8158, `prewarm_default_async` lines 8160-8228 | Bridge RPCs are isolated through `post_service`, but status/detail polls can still serialize with lifecycle work. Prewarm is disabled by default unless `AIDA_CAMOUFOX_PREWARM` is enabled; if enabled, it posts `ensure_ready` through the shared `work_queue` after render authorization. |
| Camoufox status invalidation | `camoufox_bridge.cpp` `get_status` lines 9412-9646 | Frequent status calls can invalidate bridge readiness if child/browser/page/privacy/visible-window state is not proven and logs every call. Per-frame or high-frequency status use creates CPU/log churn and can trigger cleanup behavior. |
| Browser MCP capture publishing | `src/standalone/src/core/network/burp/camoufox_bridge_mcp.cpp` `wait_for_ready_status` lines 412-426, `camoufox_timeout_ms` lines 1795-1811, `tool_launch_browser` lines 2007-2029, `tool_close_browser` lines 2032-2059, `tool_camoufox_passthrough` lines 2062-2385 | MCP browser navigation defaults to `publish_to_burp=true`; that makes capture active and defaults body capture to true. After navigation, it can call `list_network_requests` with a 30 s timeout and publish exchanges to Burp. This is valid behavior, but it is heavy if used as the default path for tests or UI refresh. |
| Test Lab Camoufox and Network phases | `src/standalone/src/core/testlab/test_all_features.cpp` `cleanup_camoufox_for_full_test_start` lines 566-632, `start_tests_impl` lines 3413-3523, `queue_start_tests_impl` lines 3526-3616, `cancel_tests_impl` lines 3618-3630, `run_all` lines 3040-3302 | Full Test startup performs Camoufox cleanup before queuing the worker. Cancel calls `camoufox::force_cleanup("testlab.cancel.inline")` synchronously. Both can affect the GUI if reached from UI-triggered paths. |
| Test Lab bounded tasks | `src/standalone/src/core/testlab/test_lab_bounded_runner.hpp` `bounded_runner_t` lines 52-108; `src/standalone/src/core/testlab/test_all_network.cpp` `run_bounded_bool` lines 92-175 | Bounded runners time out from the caller perspective, but the underlying posted task can continue running. Network helper tasks use shared queues and lack a common cooperative cancellation token. |
| Test Lab Burp/Camoufox tests | `src/standalone/src/core/testlab/test_all_burp.cpp` `bounded_burp_camoufox_probe` lines 178-203, `ensure_burp_camoufox_dependencies` lines 205-226, loopback fixture line areas 399-441 and 509, scanner fixture lines 1426-1477, crawler fixture lines 1489-1494, WebSocket fixture lines 1619-1625, content discovery lines 1662-1667, `phase_burp_tests` line area 4860-5244 | Burp tests already bound several modules, but loopback fixtures, WebSocket paths, scanner/crawler/content-discovery tasks, and Camoufox probes can still compete with GUI workers or leave timed-out work active. |
| Test Lab MCP browser tests | `src/standalone/src/core/testlab/test_all_mcp.cpp` constants lines 151-168, `scoped_camoufox_testlab_launch_t` lines 276-283, `bounded_camoufox_probe` lines 327-352, `camoufox_dependencies_ready_for_test` lines 365-394, `mcp_tool_requires_live_camoufox_bridge` lines 1147-1161, `camoufox_live_bridge_status` lines 1190-1199, `phase_mcp_tests` line area 28259 onward | MCP browser tests can use 65-75 s browser-side deadlines. They require ready, child-alive, browser-open, page-verified, privacy-verified, visible-window-proven state. These tests are correct but must not starve render or general GUI queues. |
| TCP stream tracking | `src/standalone/src/core/network/tcp_stream_tracker.hpp` `start` lines 116-151, `stop` lines 153-180, `poll_loop` lines 314-333 | Tracker posts a long-lived poll loop to `work_queue`, calls `driver_bridge::get_captured_packets(32)`, and sleeps 50 ms. This can occupy a shared worker during tests or active capture. |
| Active scanner | `src/standalone/src/core/network/burp/active_scanner.cpp` `enqueue_target` line area 864-938, `cancel_audit` lines 962-983, `wait_for_audit_idle` lines 986-1032 | Scanner jobs are posted to the shared `work_queue`. There are useful existing bounds, but audit work can still compete with GUI and browser lifecycle work. |

## Proposed Changes

### 1. Split Network Startup Into Lightweight Init And Lazy Runtime Start

Change `network_view::initialize` so authorized app startup creates state, mutexes, and cheap configuration only. Defer worker creation and Burp initialization until a user opens a relevant Network/Burp tab, an MCP tool requires the subsystem, or Test Lab explicitly enters the network/Burp phase.

Recommended target shape:

| Proposed symbol | Responsibility |
| --- | --- |
| `network_view::initialize` | State-only init. No capture/DNS/bandwidth/fuzzer worker start. No `aida::burp::initialize`. |
| `network_view::ensure_runtime_started(reason, active_tab)` | Idempotent start of only the workers needed for the active tab or caller. Logs reason, tab, queue stats, and elapsed time. |
| `network_view::ensure_burp_runtime_started(reason, module)` | Calls a lazy Burp module init path only when a Burp tab, browser tool, scanner, or Test Lab phase needs it. |

Make `last_render_tick_ms` tab-specific. Connection polling should require the Connections tab or an explicit auto-refresh caller, not just any Network view render. Capture, DNS, and bandwidth workers should start on explicit capture/monitor activation and stop or sleep when inactive.

### 2. Make Burp Module Initialization Demand-Driven

Split `burp_module.cpp` `initialize` lines 94-150 into a cheap core and module-level ensure functions. Scope, issue store, payload metadata, and logger can be core. Heavy or external modules should initialize on first use:

| Lazy module group | Existing init calls |
| --- | --- |
| Scanner modules | `passive_scanner::initialize`, `active_scanner::initialize`, `dom_xss::initialize` |
| Crawling and discovery | `crawler::initialize`, `content_discovery::initialize`, `subdomain_enum::initialize` |
| Browser/Camoufox | `browser::initialize`, `camoufox::install::initialize`, `headless_view::initialize` |
| Protocol labs | `auth_lab::initialize`, `jwt_lab::initialize`, `ws_editor::initialize` |
| Network routing | `upstream::initialize`, `match_replace::initialize`, `session_handler::initialize` |

Every public tool or tab entry should call the matching `ensure_*_initialized(caller)` before use. This preserves MCP/Test Lab behavior without forcing the entire Burp stack to run at GUI startup.

### 3. Move MITM Proxy Pre-Init Off The Startup Critical Path

Change `mitm_proxy::pre_initialize` lines 2197-2229 into state preparation only. Start the listener and worker pool in `mitm_proxy::start` or an explicit `ensure_proxy_workers_started(reason)` call.

The listener and proxy workers should use a dedicated proxy worker lane or owned threads, not the general `work_queue`. Long-lived listener/select loops and worker CV waits should not occupy shared GUI service capacity. `shutdown` lines 2232-2245 should use bounded waits with diagnostic logs instead of silent 1 ms busy-wait loops.

### 4. Make Browser View Lifecycle Commands Asynchronous

In `browser_view.cpp` `render` lines 118-347, replace synchronous Open/Stop button actions with a small UI command state machine:

| State | Behavior |
| --- | --- |
| Idle | Buttons enabled according to cached bridge status. |
| Starting | Open disabled, Stop can request cancellation/cleanup, render continues. Worker runs `browser_launch::launch`. |
| Stopping | Stop disabled or shows pending, render continues. Worker runs `browser_launch::kill_all` or `stop_bridge`. |
| Failed | Shows last error from worker and allows retry. |

Cache `browser_launch::list_running` and `camoufox::get_status` on a 750-1500 ms TTL or state-change event. Do not call status/list per frame. Use `kBridgeStateChanged` and lifecycle command completion to invalidate the cache immediately.

### 5. Throttle Headless View Polling And Separate Cheap Status From Detail Refresh

`headless_view.cpp` `schedule_status_poll` lines 208-266 currently performs status plus console logs, network requests, and page info. Replace it with two poll classes:

| Poll class | Trigger | Work |
| --- | --- | --- |
| Cheap status | View visible, operation completed, manual refresh, or 2-5 s backoff timer | `camoufox::get_status` only. |
| Detail refresh | Console/network/page subpane visible, manual refresh, or after navigation/start completes | One bounded call for the visible detail only. |

Do not call `list_network_requests` automatically every 750 ms. Use singleflight coalescing so a slow poll prevents another poll from starting. Add exponential or capped backoff when the bridge is not ready or the last poll failed.

`schedule_install_probe` lines 269-286 should run on initialization, explicit Re-probe, and a stale TTL such as 30-60 s. It should not be tied to high-frequency render polling.

### 6. Keep Camoufox Prewarm Explicit And Low Priority

`camoufox_bridge.cpp` `prewarm_default_disabled` lines 296-304 already disables prewarm by default unless `AIDA_CAMOUFOX_PREWARM` is enabled. Preserve that default.

If prewarm is enabled, schedule it only after GUI idle, no active Test Lab run, no active scanner/fuzzer, and no pending lifecycle command. Use the Camoufox service queue or a low-priority owned worker rather than the shared general `work_queue`. Preserve the existing full-test skip in `prewarm_default_async` lines 8163-8166.

Prewarm must be cancellable before launch if the user starts Test Lab, starts a heavy network operation, or manually opens/stops Camoufox.

### 7. Prioritize Camoufox Lifecycle Over Low-Priority Polls

Keep lifecycle and MCP calls on the service queue, but add explicit priority or cancellation rules:

| Work type | Priority |
| --- | --- |
| `start_bridge`, `stop_bridge`, `force_cleanup`, `launch_browser`, `close_browser` | High |
| User navigation/interaction/MCP tool calls | Normal |
| UI status/detail polls, install probes, post-render refreshes | Low and cancellable |

When a high-priority lifecycle operation starts, cancel or skip pending low-priority polls. Log the skipped poll reason instead of queueing work that will contend with lifecycle.

### 8. Add Lightweight Browser Navigation For UI And Tests Without Changing MCP Defaults

Do not silently change MCP `publish_to_burp` defaults in `camoufox_bridge_mcp.cpp` lines 2062-2385. Existing tools rely on `publish_to_burp=true` and body capture defaults.

Add explicit lightweight internal/test/UI call sites where the caller passes `publish_to_burp=false`, `capture_body=false`, and a bounded result count. This avoids the extra `list_network_requests` call after navigation for flows that only need a page load or readiness proof.

For normal publish-to-Burp paths, cap body bytes, request count, and publication batch size. Log captured count, published count, body bytes, elapsed time, and whether a post-navigation network list was necessary.

### 9. Isolate Long-Lived Network And Test Workers From Shared GUI Queues

Long-lived loops should not occupy the shared `work_queue`:

| Current symbol | Proposed isolation |
| --- | --- |
| `tcp_stream_tracker_t::poll_loop` lines 314-333 | Dedicated tracker worker or network polling lane with cooperative cancellation. |
| `mitm_proxy::listener_thread_func` lines 1996-2038 | Dedicated proxy listener thread/lane. |
| `active_scanner::enqueue_target` line area 864-938 | Bounded scanner pool with explicit max concurrency and cancellation token. |
| Test Lab loopback/WebSocket fixtures | Short-lived owned fixture workers or critical queue with guaranteed entry logging and timeout cleanup. |
| Network capture/DNS/bandwidth workers | Start only when corresponding feature is active; stop or park when inactive. |

Owned workers must run any required AiDA thread setup currently expected from `work_queue`, including manual-map TLS or runtime integrity entry logging, before touching protected code paths.

### 10. Make Test Lab Cancellation Cooperative And Non-Blocking For UI

Extend `test_lab::bounded_runner_t` lines 52-108 and `run_bounded_bool` lines 92-175 with a shared cancellation token passed into callees that can block or poll. On timeout, mark cancellation and log that the underlying task must exit. Do not only return timeout while the task continues silently.

Move `cancel_tests_impl` synchronous `camoufox::force_cleanup("testlab.cancel.inline")` into a bounded cleanup job so the UI can keep rendering. The UI should show cleanup pending, while logs prove worker entry, process tree, bridge status, and deadline result.

Keep full-test final cleanup in `test_all_features.cpp` lines 3235-3238, but log residual workers, active browser processes, reverse-MCP process state, service queue stats, and whether cleanup met its deadline.

## Logging Needed

Add diagnostic breadcrumbs before implementation verification:

| Area | Required fields |
| --- | --- |
| Network runtime | Worker start/stop reason, active tab, view visibility, caller, queue pending/active, worker enter/exit timestamps, driver call elapsed, batch counts, skipped poll reason. |
| Burp lazy init | Module name, caller tab/tool/test, cold/warm result, begin/end timestamps, elapsed ms, failure code/message. |
| MITM proxy | Pre-init/start/stop reason, listener enter/exit, worker count, queue/lane stats, shutdown deadline, accepted connection count, residual worker count. |
| Browser view lifecycle | Command id, UI submit timestamp, worker enter timestamp, queue delay, requested URL, start/stop/navigate elapsed, timeout, cancellation, status before/after. |
| Headless polling | Poll class, visible subpane, interval, coalesced/skipped reason, service queue stats, RPC elapsed, counts returned, error shape. |
| Camoufox lifecycle | Prewarm gating reason, lifecycle priority, low-priority poll cancellation, process tree before/after, managed bridge readiness, privacy proof state, visible window proof state. |
| Browser MCP capture | Tool name, timeout, publish flag, capture body flag, request count, published count, total body bytes, post-navigation list elapsed, failure envelope. |
| Test Lab | Phase begin/end, queue snapshots before/after, fixture worker enter/exit, cancellation token observed, timeout source, cleanup deadline, residual workers, bridge status, process tree. |
| UI responsiveness | Main-thread stall markers over 100 ms, 250 ms, and 1000 ms; active tab; current Test Lab phase; work queue, critical queue, service queue, and Camoufox lifecycle state. |

Do not log raw credentials, private keys, signing keys, KMS/HSM material, OAuth bearer tokens, API keys, or full license keys. Diagnostic process state, timing, paths, module names, privacy-proof flags, queue stats, and protocol failure shapes are acceptable for pre-release evidence.

## Verification Plan

The implementer should build only after code changes, using the repository's canonical host build process. This planning pass did not build.

1. Static review before build:
   - Confirm no implementation weakens Camoufox-only behavior.
   - If `src/standalone/src/main.cpp` is touched, preserve the standalone message-pump invariants: `kAidaQueuedPeekFlags` includes `PM_QS_SENDMESSAGE`, send-only pending work is drained with `PM_REMOVE | PM_QS_SENDMESSAGE`, and the empty-queue path still performs a nonblocking `PeekMessage` probe after `GetQueueStatus(QS_ALLINPUT) == 0`.
   - Confirm no long-lived proxy, tracker, scanner, or browser poll loop is posted to the general `work_queue` without an explicit bound or idle gate.

2. Cold-start runtime evidence:
   - Start the standalone app with `AIDA_CAMOUFOX_PREWARM` unset.
   - Verify no Camoufox process and no reverse-MCP process start before an explicit browser/tool action.
   - Verify logs show lightweight network init only, no full Burp module initialization, and no `managed_start`, `start_bridge`, or prewarm worker.
   - Confirm the UI remains responsive after authorization and IDE load.

3. Network view evidence:
   - Open Network view and switch tabs.
   - Verify only the active tab's worker starts or wakes.
   - Verify connection polling does not run merely because a non-Connections tab rendered.
   - Verify capture, DNS, bandwidth, and tracker workers stop, park, or skip with logged reasons when inactive.

4. Browser view evidence:
   - Click Open Camoufox and Stop Camoufox.
   - Confirm frames continue rendering while lifecycle work runs.
   - Verify logs show UI submit, worker enter, queue delay, operation elapsed, privacy proof, visible-window proof, and final status.
   - Confirm status/list refresh is TTL or event driven, not per frame.

5. Headless view evidence:
   - Open Headless view while bridge is stopped, ready, and busy.
   - Verify idle polling uses cheap status only with backoff.
   - Verify console/network/page detail calls happen only for the visible detail pane, manual refresh, or after operation completion.
   - Verify no automatic `list_network_requests` call repeats every 750 ms.

6. MCP/browser capture evidence:
   - Run a browser navigation with default `publish_to_burp=true`; verify capture and publication still occur and privacy guarantees remain enforced.
   - Run a lightweight internal/test navigation with `publish_to_burp=false`; verify no post-navigation network list or body capture runs.
   - Confirm failure responses retain fixed, non-leaky auth/security shapes where applicable.

7. Test Lab evidence:
   - Run the full Test Lab from the UI.
   - Verify `aida_full_test.log` contains phase begin/end markers, queue snapshots, worker entry logs, cancellation checkpoints, and bounded cleanup results.
   - Verify the shared `work_queue` does not saturate while browser, WebSocket, loopback, scanner, tracker, or MITM tests run.
   - Cancel mid-run and confirm the UI remains responsive while cleanup proceeds with deadline logs.
   - Verify no duplicate Camoufox browser roots or reverse-MCP processes remain after final cleanup.

8. Performance evidence:
   - Capture CPU/GPU idle usage before and after changes with Network/Burp closed, Network open, Browser open but idle, Headless open, and Test Lab running.
   - Capture frame-time or main-thread stall logs for p95/p99 responsiveness.
   - Treat any render stall over 250 ms during idle UI as a regression until logs prove a bounded intentional operation.

## Risks And Invariants

| Risk | Mitigation |
| --- | --- |
| Lazy init breaks tools or tests that assumed eager Burp state | Add `ensure_*_initialized(caller)` at every tab, MCP tool, and Test Lab entry that uses the module. Log cold/warm initialization. |
| Reduced polling delays UI state | Use `kBridgeStateChanged`, command completion invalidation, and manual refresh in addition to slower TTL polling. |
| Owned workers bypass required thread setup | Run required TLS/runtime-integrity setup at worker entry and log success before protected operations. |
| Async browser launch complicates UI state | Use a strict lifecycle state machine with one in-flight command and explicit cancellation/cleanup state. |
| Changing browser MCP defaults could break existing workflows | Do not change `publish_to_burp` defaults. Add explicit lightweight paths for UI/tests. |
| Test Lab timeout leaves work running | Pass cooperative cancellation tokens and log when each worker observes cancellation and exits. |
| MITM lazy start changes local API expectations | Keep `pre_initialize` idempotent and cheap; make `start` or tool entry perform the real listener/worker start. |
| Service queue prioritization hides diagnostics | Log every skipped/coalesced low-priority poll with reason and current lifecycle state. |

Security and privacy invariants:

| Invariant | Required behavior |
| --- | --- |
| Camoufox-only browser model | No non-Camoufox fallback, no system browser, no stock Playwright browser, no Chrome/Edge/Firefox fallback. |
| Privacy enforcement | Preserve `block_webrtc=true`, disabled WebRTC policy, privacy fail-closed behavior, UA/privacy checks, and visible-window proof for non-headless launches. |
| Customer sidecar model | Preserve frozen reverse-MCP executable and verified sidecar paths. Do not restore source-package or loose Python fallback for customer launch. |
| Fileless loader prohibition | Do not add PowerShell/fileless-host exceptions, in-memory launch, or special trust for a PowerShell-hosted process. |
| MCP trust boundary | Treat browser and Burp MCP tools as mutating local capabilities. Do not relax schemas, origin restrictions, request limits, or cancellation controls. |
| Licensing and anti-tamper | Do not weaken license, ARC, driver, protector, anti-tamper, or runtime-integrity checks for performance. |
| Logs | Preserve diagnostic evidence while excluding raw credentials, private keys, bearer tokens, API keys, and full license keys. |

## Implementation Order

1. Add logging and counters first so current behavior and every later change can be measured.
2. Make Browser view launch/stop/status asynchronous and cached because it directly protects the UI thread.
3. Throttle Headless polling and split cheap status from detail refresh to reduce Camoufox service queue pressure.
4. Split Network/Burp eager initialization into lazy ensure functions.
5. Move MITM, tracker, scanner, and fixture loops off the shared `work_queue` or behind active-use gates.
6. Add Test Lab cooperative cancellation and non-blocking cleanup.
7. Add lightweight internal browser navigation for UI/tests while preserving MCP defaults.
8. Run the verification plan and keep logs proving no GUI freeze, no queue starvation, and no weakened Camoufox privacy guarantees.

C:\Users\ruar1337\AiDAPrivate\docs\gui-performance-plans\camoufox_network_testlab_plan.md
