# AiDA GUI Background Worker And Logging Performance Plan

## Objective

Reduce idle GUI CPU, disk churn, and Microsoft Defender pressure without starving UI responsiveness or weakening license, ARC, driver, MCP, or anti-tamper enforcement. This is a planning document only. No source changes were made while preparing it.

## Current Evidence From Source Inspection

- `src/standalone/src/core/infra/work_queue.hpp:20-41` sizes the general pool to 32-64 threads and the service pool to 16-32 threads. `work_queue::detail::pool_t` at `work_queue.hpp:58-76` uses an unbounded FIFO `std::queue<task_t>` for both pools. `work_queue::post_to` at `work_queue.hpp:246-273` always accepts work while alive and has no queue depth cap, lane policy, dedupe, priority, or backpressure.
- `src/standalone/src/core/infra/critical_work_queue.hpp:26` creates a fixed 12-thread critical pool. `critical_work_queue::post_labeled` at `critical_work_queue.hpp:214-241` also uses an unbounded FIFO. This pool handles high-impact startup work from `src/standalone/src/main.cpp:4407` and `main.cpp:4682`.
- `src/standalone/src/core/mcp/mcp_standalone.cpp:136-207` defines MCP HTTP, batch, and tool executor sizing from environment variables. Defaults can reach 32 HTTP workers, 16 batch workers, 16 tool workers, queue depth 4096 per executor, and per-domain single-worker executors at `mcp_standalone.cpp:761-771`.
- `mcp_owned_executor_t` at `src/standalone/src/core/mcp/mcp_standalone.cpp:328-715` already has bounded queues and active-task snapshots, but logs dispatch delays over 100 ms at `mcp_standalone.cpp:650-661`. `mcp_request_task_queue` at `mcp_standalone.cpp:717-736` isolates HTTP work from global queues.
- `server_t::server_thread_func` at `src/standalone/src/core/mcp/mcp_standalone.cpp:4284-4490` logs every HTTP request entry and exit at `mcp_standalone.cpp:4342-4386`, every `POST /mcp` body metadata at `mcp_standalone.cpp:4398-4409`, and keeps SSE streams alive with a handler-loop sleep pattern at `mcp_standalone.cpp:4418-4472`.
- `server_t::start` at `src/standalone/src/core/mcp/mcp_standalone.cpp:4086-4207` starts the MCP server on a dedicated native thread except fileless/fallback paths, where it posts long-lived server work to `work_queue::post_service`.
- `mcp_client.cpp:2139-2168` polls stdio notifications from the UI-side manager path. `mcp_client.cpp:2171-2370` launches stdio MCP child processes with `CreateProcessW`, environment construction, inherited pipes, and a fixed `Sleep(200)`. `mcp_client.cpp:2406-2470` logs every stdio send, line receive, notification, inbound request, and response.
- `manager_t::poll` at `src/standalone/src/core/mcp/mcp_client.cpp:2858-2892` polls connected stdio servers and posts auto-reconnects to the general `work_queue` without label, per-server cooldown, or service-lane isolation.
- `src/standalone/src/helpers/diag_log.hpp:234-247` flushes the debug log when forced, after 64 KiB, on the first write, or every 1000 ms. `diag::log_tagged` at `diag_log.hpp:323-332` serializes all normal log writes behind one mutex and calls `FlushFileBuffers` through `coalesced_flush_log`. Critical logs at `diag_log.hpp:344-362` force flush every time.
- `src/standalone/src/main.cpp:4826-4904` logs message-pump empty-probe and send-only drain diagnostics with critical forced-flush logging. This is correct for freeze evidence, but routine samples can become disk-heavy if the UI is otherwise idle.
- `src/standalone/src/main.cpp:5568-5589` samples idle queue stats every 5 seconds and calls `work_queue::stats`, `service_stats`, and `critical_work_queue::stats`. These try-lock and snapshot active labels, which is useful evidence but should remain sample-rate bounded.
- `src/standalone/src/main.cpp:2000-2015` posts a one-shot `render_tracer` service task. `main.cpp:2035-2060` posts a `focus_monitor` service task that sleeps 200 ms once. These are low risk, but they still consume service pool slots during startup.
- `src/standalone/src/main.cpp:3211-3290` posts script-engine startup init to the service pool and falls back to the general queue. `main.cpp:3293-3368` initializes network, memory scanner, MITM, and script engine after authorization. `main.cpp:4407-4646` posts startup background init to the critical queue and runs chat, network, memory scanner, MITM, anti-tamper, code hash, and session health work.
- `src/standalone/src/core/runtime/standalone_license.cpp:8863-9056` runs the heartbeat worker below normal priority with 15-25 second normal cadence and extra PE/mitigation/thread diagnostics around heartbeat calls outside Full Test. `standalone_license.cpp:9059-9128` runs server-token refresh every 10 seconds. `standalone_license.cpp:9179-9258` posts both to the service pool.
- `src/standalone/src/core/runtime/standalone_anti_tamper.hpp:970-1001` starts a service-pool monitor loop that sleeps 5 seconds, then runs `run_verification_cycle` every 3 seconds. `standalone_anti_tamper.hpp:684-967` performs deep AI/tool scans every fourth verification pass and calls `standalone_anti_ai::full_scan_runtime_cached(15000, "runtime_verify")`.
- `src/standalone/src/core/runtime/standalone_anti_ai.hpp:3292-3463` performs heavyweight full scans: process collection/classification, handle scan, window scan, evidence hashing, and critical completion logging. `standalone_anti_ai.hpp:3475-3535` caches routine runtime scans for 15 seconds and rate-limits cache logs to 10 seconds.
- `src/standalone/src/core/anti-tamper/orchestrator.hpp:4726-4757` starts three watchdog worker loops at `THREAD_PRIORITY_ABOVE_NORMAL` and sleeps 75 ms between witness computations. `orchestrator.hpp:4891-4951` runs the monitor loop below normal every 500-750 ms and critical-logs guard timings. `orchestrator.hpp:4955-4992` posts these monitor tasks to the general `work_queue`.
- `src/standalone/src/core/network/network_view.cpp:229-258` posts long-lived network pollers to the general queue. `network_view.cpp:490-538` polls connections every 1 second and is already gated by `last_render_tick_ms` and auto-refresh. `network_view.cpp:541-745` creates capture, DNS, bandwidth, and fuzzer poller workers at initialization and keeps most of them parked behind condition variables. `network_view.cpp:886-957` starts all of these workers during network initialization.
- `src/standalone/src/core/mcp/mcp_marketplace.cpp:318-380` posts registry searches to the general queue. `mcp_marketplace.cpp:405-543` posts install jobs to the general queue, creates directories, runs `cmd.exe /c npm install` or Python setup, and probes `node_modules` or `venv\\Scripts`. This is a Defender-heavy path and should not share latency-sensitive queue capacity.

## Evidence To Gather Before Implementation

- Idle 5-minute trace from `aida_debug.log` with tags grouped by count and bytes: `mcp_srv`, `mcp_stdio`, `guard`, `monitor`, `network`, `render`, `msgpump`, `bg_init`, `license`, and `work_queue`.
- Process metrics during idle and during MCP usage: AiDA CPU percent, thread count, context switches/sec, disk writes/sec, handle count, and Defender CPU. Capture with Windows Performance Recorder or PerfView, plus Resource Monitor for Defender correlation.
- Queue pressure snapshots from existing `idle_pacing_sample`: general/service/critical active, pending, oldest active ms, thread count, and Full Test state. Confirm whether service slots are occupied by heartbeat, server refresh, MCP server fallback, render tracer, focus monitor, or anti-tamper monitor.
- MCP executor health from `/health`: HTTP/batch/tool executor workers, queued, active, rejected, active task lanes, active streams, and request latency under `tools/list`, `tools/call`, and one long SSE stream.
- Startup timeline from `bg_init`, `drv_init`, `license`, `mcp_srv`, and `network` tags: queued_ms, elapsed_ms, worker thread id, service pending/active, and whether any fallback ran inline.
- Defender-triggering events: process creation of stdio MCP servers and marketplace installs, npm/pip directory writes under marketplace paths, debug log flush frequency, and `aida_debug.log` write volume.
- Anti-tamper safety baseline: runtime scan cache hit/miss rate, `guard_elapsed_ms`, watchdog witness cadence, heartbeat success cadence, ARC heartbeat/driver seed state, and any existing soft violations.

## Proposed Implementation Plan

1. Add bounded, labeled queue policy to `work_queue`

   Target files and areas:
   - `src/standalone/src/core/infra/work_queue.hpp:20-41`, `58-76`, `84-152`, `155-235`, `246-289`.
   - `src/standalone/src/core/infra/critical_work_queue.hpp:26`, `43-60`, `67-128`, `130-211`, `214-241`.

   Proposed changes:
   - Keep existing public post APIs working, but add internal capacity limits for general and service queues. Start conservatively: general max pending around 2048, service max pending around 256, critical max pending around 256. Make caps environment-tunable for diagnostics only.
   - Add `max_pending`, `dropped_low_priority`, `coalesced`, `oldest_pending_ms`, and `last_reject_label` to stats. Keep active label snapshots intact.
   - Add optional labeled posting helpers for low-priority/coalescible work. Use them first for periodic samples, reconnect attempts, marketplace search, network pollers, and noncritical diagnostics.
   - Do not bound critical security transitions in a way that can fail open. If critical queue rejects a required fail-closed task, it must log critical and enforce or keep the existing fail-closed behavior.
   - Consider lowering worker thread defaults after measurement. A safer first step is caps/backpressure without reducing pool size. If idle CPU remains high, tune general to `min(max(hardware_concurrency, 8), 32)` and service to `min(max(hardware_concurrency / 2, 4), 16)` while keeping overrides.

2. Separate lanes by workload cost and lifetime

   Target files and areas:
   - `src/standalone/src/core/runtime/standalone_license.cpp:9179-9258`.
   - `src/standalone/src/core/runtime/standalone_anti_tamper.hpp:970-1001`.
   - `src/standalone/src/core/anti-tamper/orchestrator.hpp:4955-5090`.
   - `src/standalone/src/core/network/network_view.cpp:229-258`, `751-865`, `886-957`.
   - `src/standalone/src/core/mcp/mcp_marketplace.cpp:318-380`, `405-543`.

   Proposed changes:
   - Keep heartbeat and server-refresh on a protected service lane, but explicitly label them with `post_service_labeled` so queue stats identify them. They are security-critical and must not be starved by marketplace, MCP reconnects, or network scripts.
   - Move marketplace search/install jobs to a new low-priority disk/process lane or a bounded serial executor. Installs should run one at a time, report queued/running state, and never occupy general queue workers.
   - Move network long-lived poller startup from general queue to service or a small network executor. Keep capture/DNS/bandwidth condition-variable parking, but do not start fuzzer worker until a fuzz run is requested.
   - Keep watchdog worker loops functionally intact, but isolate them from general application work. Do not reduce the witness worker count or 75 ms cadence without a security signoff. If CPU evidence points at watchdogs, prefer `THREAD_MODE_BACKGROUND_BEGIN` experiments only for non-witness monitor loops, not for above-normal witness workers.
   - Keep MCP HTTP/batch/tool executors separate from `work_queue`. Add per-lane active/pending health output to prove MCP work is not starving heartbeat or UI work.

3. Reduce routine logging and flush pressure

   Target files and areas:
   - `src/standalone/src/helpers/diag_log.hpp:234-247`, `249-332`, `344-362`.
   - `src/standalone/src/core/mcp/mcp_standalone.cpp:4342-4386`, `4398-4409`, `4587-4640`.
   - `src/standalone/src/core/mcp/mcp_client.cpp:2406-2470`.
   - `src/standalone/src/main.cpp:4826-4904`, `5568-5589`.
   - `src/standalone/src/core/runtime/standalone_anti_ai.hpp:3292-3463`, `3475-3535`.

   Proposed changes:
   - Preserve critical logs for crashes, hangs, Runtime Integrity Lock, license/ARC failures, driver failures, anti-tamper violations, and first confirmed failure windows.
   - Add tag-level rate-limited normal logging wrappers for routine `mcp_srv` request entry/exit, stdio send/recv success lines, health success, message-pump empty probes, and idle pacing samples. Keep errors, slow paths, rejects, queue full events, stream failures, and authorization failures immediate.
   - Increase normal coalesced flush interval from 1000 ms to 2500-5000 ms only for noncritical logs, or add a background flush timer. Keep `log_tagged_critical` forced flush.
   - Add byte counters by tag so a future idle trace can prove which tags drive disk volume. Do not remove diagnostic fields needed to diagnose freezes; throttle repeated routine success lines instead.
   - For MCP request logs, sample success traffic by route and always log abnormal status, elapsed above threshold, queue wait above threshold, body over threshold, stream open/close, and unauthorized attempts.

4. Add backpressure and dedupe to MCP and stdio client paths

   Target files and areas:
   - `src/standalone/src/core/mcp/mcp_standalone.cpp:136-207`, `328-715`, `717-747`, `3329-3505`, `3863-4060`, `4284-4490`.
   - `src/standalone/src/core/mcp/mcp_client.cpp:2139-2168`, `2171-2370`, `2406-2470`, `2858-2892`, `3108-3255`.

   Proposed changes:
   - Lower default MCP queue depths after measurement. Current 4096 queue defaults can retain too much work during a client burst. A starting target is 512 HTTP, 512 batch, 512 tool queue, keeping environment overrides.
   - Keep `tools/list`, `initialize`, `ping`, and `/health` responsive by routing them through a fast lane or by prioritizing them in the HTTP executor. Do not let long browser or Burp tools occupy all tool workers.
   - Add per-server reconnect cooldown and dedupe in `manager_t::poll` so repeated disconnected auto-connects do not enqueue duplicate general queue tasks.
   - For stdio clients, avoid logging every successful request/response line at idle. Keep first N, failures, invalid JSON, inbound requests, notifications that mutate state, and slow operations.
   - Replace fixed `Sleep(200)` after stdio launch with readiness polling bounded by time and process-exit checks. This reduces startup latency without increasing churn.

5. Reduce Defender-triggering disk and process churn

   Target files and areas:
   - `src/standalone/src/core/mcp/mcp_marketplace.cpp:72-112`, `318-380`, `405-543`, `588-600`.
   - `src/standalone/src/core/mcp/mcp_client.cpp:2171-2370`.
   - `src/standalone/src/helpers/diag_log.hpp:234-247`, `323-362`.
   - `src/standalone/src/helpers/win32_dialog.hpp:668-969` for dialog broker script/process creation if dialog performance is still implicated.

   Proposed changes:
   - Gate marketplace installs behind an explicit UI action, serial executor, and clear running state. Never retry installs automatically. Use one stable marketplace root and avoid repeated canonicalization/probing loops.
   - Cache marketplace search results for a short TTL per query/registry and cancel or coalesce stale searches while the user types.
   - Keep Camoufox-only and trusted MCP posture checks intact. Do not add non-Camoufox browser fallback to reduce process-launch cost.
   - For stdio MCP child processes, persist trusted servers where safe, debounce reconnects, and avoid launch/kill loops on failing servers.
   - Reduce normal debug flush frequency and sampled success logs before considering any Defender exclusions. The product should behave well without requiring exclusions.

6. Tighten idle pollers

   Target files and areas:
   - `src/standalone/src/core/network/network_view.cpp:490-538`, `541-745`, `751-865`, `886-957`, `5900`.
   - `src/standalone/src/main.cpp:2627-2729`, `4826-4904`, `5351`, `5528-5589`.
   - `src/standalone/src/core/runtime/standalone_anti_tamper.hpp:970-1001`.

   Proposed changes:
   - Keep connection polling render-gated, but increase the idle skip interval when Network view has not rendered recently. Log only state transitions and occasional summaries.
   - Start fuzzer worker lazily. It should not occupy a general queue slot at network initialization.
   - Confirm capture/DNS/bandwidth workers stay parked when disabled. If idle traces show wakeups, convert their loops from `Sleep(10)` slices to condition-variable timed waits where applicable.
   - Keep frame-latency waitable and message pump invariants untouched: `kAidaQueuedPeekFlags` must include `PM_QS_SENDMESSAGE`, send-only pending work must drain with `PM_REMOVE | PM_QS_SENDMESSAGE`, and the empty-queue path must still perform a nonblocking `PeekMessage` probe.
   - Keep `idle_pacing_sample` at or above the current 5 second interval during diagnostics, then consider 15 seconds for routine builds while preserving Full Test verbosity.

## Verification Plan

- Build only by the host AI after implementation using the canonical wrapper `.\build-host.cmd`; this planner did not build.
- Run a clean idle GUI session for 5 minutes on the welcome view and 5 minutes after license/ARC ready. Compare CPU, thread count, context switches, disk writes/sec, Defender CPU, and log bytes/sec against the baseline.
- Validate UI responsiveness with active input, resize, drag, focus changes, and no-input idle. Confirm message-pump invariants remain intact in source and that `SendMessageTimeout(WM_NULL)` succeeds during idle.
- Exercise MCP:
  - `/health`, `initialize`, `tools/list`, one fast `tools/call`, one long browser/Burp call, and one long SSE `/mcp` stream.
  - Confirm `/health` reports executor active/queued/rejected counts and no queue starvation.
  - Confirm request success logs are sampled but rejects, slow calls, stream failures, unauthorized attempts, and errors are still complete.
- Exercise license and ARC:
  - Heartbeat success cadence remains 15-25 seconds with jitter.
  - Server refresh cadence remains 10 seconds.
  - ARC loaded/session-bound state remains fail-closed.
  - Queue backpressure cannot skip heartbeat, server refresh, Runtime Integrity Lock, driver bridge, or anti-tamper enforcement.
- Exercise anti-tamper:
  - Runtime monitor still runs every 3 seconds and deep verification every fourth cycle unless an explicit security-approved change is made.
  - Full AI posture scans remain cached at 15 seconds for routine runtime callers and still run immediately when cache policy requires it.
  - Watchdog worker witness loops and enforcement behavior remain intact.
- Exercise network:
  - Network view unopened idle does not enumerate connections.
  - Opening Network view refreshes connections within one poll interval.
  - Capture, DNS, bandwidth, and fuzzer still work when armed.
- Exercise marketplace:
  - Search coalesces while typing and reports latest result only.
  - Install runs serially, reports progress/failure, and does not occupy general or service queue capacity.

## Logging To Add During Implementation

- Queue enqueue rejection/coalescing logs with pool, label, priority, pending, active, cap, and disposition.
- Queue stats in `idle_pacing_sample`: include rejected/coalesced counts and oldest pending age.
- MCP executor summary every 15-30 seconds only while active: workers, queued, active, rejected, oldest active, slowest route/tool.
- Marketplace job lifecycle: queued, started, process id if spawned, elapsed, exit code, directories touched by hash/length only if sensitive path concerns exist.
- Stdio MCP lifecycle: launch requested, posture allowed/blocked, process id, readiness elapsed, reconnect cooldown, failure reason.
- Logging subsystem summary: bytes written and flush count by tag over a rolling interval, with critical flush count separated from normal flush count.

## Risks And Security Invariants

- Do not weaken license, ARC, heartbeat, driver, Runtime Integrity Lock, anti-tamper, protector, or Camoufox-only rules to reduce CPU.
- Do not make security checks best-effort. Queue overload for required security work must fail closed, not silently skip.
- Do not remove high-fidelity crash/hang logs. Throttle routine success noise only; preserve exact breadcrumbs for failures and confirmed evidence windows.
- Do not reduce watchdog witness cadence or priority without explicit security review. If those workers are confirmed as the idle CPU source, isolate and measure before changing cadence.
- Do not add Chrome, Edge, Firefox, system-default browser, or non-Camoufox fallback to avoid process-launch cost.
- Do not log raw credentials, private keys, OAuth bearer tokens, API keys, or full license keys while adding queue and process telemetry.
- Do not let marketplace installs, MCP reconnects, registry searches, or script work starve heartbeat, ARC, driver bridge, UI message pumping, or anti-tamper monitors.

## Recommended First Patch Slice

1. Add queue caps, rejection/coalescing counters, and labeled service posts without changing worker counts.
2. Sample routine MCP request/stdout logs while preserving errors and slow paths.
3. Move marketplace installs/searches to a serial low-priority lane.
4. Add reconnect dedupe/cooldown in `manager_t::poll`.
5. Verify idle, MCP, license heartbeat, and anti-tamper behavior before tuning pool sizes.

docs/gui-performance-plans/background_workers_logging_plan.md
