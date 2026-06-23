# AiDA Standalone Render Loop And Message Pump Performance Plan

Date: 2026-06-23

Scope: standalone Win32 render loop, message pump, DX11 swap chain/frame latency, and focus/background pacing. This is a planning document only. Source was inspected in the current dirty worktree; line numbers are 1-based and may move after later edits.

## Non-Negotiable Message Pump Invariants

Preserve these exactly when implementing any change near the render loop:

- `src/standalone/src/main.cpp:513`: `kAidaQueuedPeekFlags` must include `PM_QS_SENDMESSAGE`.
- `src/standalone/src/main.cpp:514`: send-only pending work must be drained with `PM_REMOVE | PM_QS_SENDMESSAGE`.
- `src/standalone/src/main.cpp:4831-4944`: when `GetQueueStatus(QS_ALLINPUT)` reports `queue_current == 0`, the loop must still fall through to the normal nonblocking `PeekMessage(&msg, nullptr, 0, 0, kAidaQueuedPeekFlags)` probe.
- `src/standalone/src/main.cpp:4861-4911`: after a send-only drain attempt, the loop must continue pumping instead of returning to rendering immediately.

These invariants address the confirmed 2026-06-23 hung-window class where rendering continued but Windows marked the top-level HWND unresponsive.

## Current Code Map

- `src/standalone/src/main.cpp:498-518`: D3D/swapchain globals and queue/pacing constants.
- `src/standalone/src/main.cpp:1668-1672`: `aida_tracer::render_pulse`, the heartbeat proving render-loop progress.
- `src/standalone/src/main.cpp:1833-1991`: present state capture and `aida_tracer::run_tracer_thread` stall diagnostics.
- `src/standalone/src/main.cpp:2020-2070`: `aida_focus_monitor`, currently a 200 ms service-worker poll of foreground ownership.
- `src/standalone/src/main.cpp:2605-2623`: `seh_swapchain_present`, currently `Present(1, 0)`.
- `src/standalone/src/main.cpp:2627-2656`: `configure_frame_latency_waitable`, which enables `IDXGISwapChain2::SetMaximumFrameLatency(1)` when available.
- `src/standalone/src/main.cpp:2658-2730`: `wait_for_frame_latency_object`, which waits up to `kAidaFrameLatencyWaitMs` using `MsgWaitForMultipleObjectsEx`.
- `src/standalone/src/main.cpp:2732-2742`: `aida_cursor_over_window`, per-frame cursor rectangle test.
- `src/standalone/src/main.cpp:2745-2768`: `seh_resize_buffers`, resize wrapper.
- `src/standalone/src/main.cpp:4770-4784`: focus monitor start and UI thread priority bump.
- `src/standalone/src/main.cpp:4822-5035`: primary Win32 message pump.
- `src/standalone/src/main.cpp:5039-5044`: occlusion test path, currently sleeps 10 ms while occluded.
- `src/standalone/src/main.cpp:5046-5095`: pending `WM_SIZE` resize path.
- `src/standalone/src/main.cpp:5220-5314`: layout-driven second resize path.
- `src/standalone/src/main.cpp:5351-5515`: frame-latency wait, ImGui/DX11 frame start, rendering, clear, draw, and present.
- `src/standalone/src/main.cpp:5517-5595`: post-frame interaction and idle diagnostic block.
- `src/standalone/src/main.cpp:5709-5759`: `CreateDeviceD3D`, optimized waitable swapchain attempt plus legacy fallback.
- `src/standalone/src/main.cpp:5762-5770`: `CleanupDeviceD3D`.
- `src/standalone/src/main.cpp:5772-5856`: `CreateRenderTarget` and render-target diagnostics.
- `src/standalone/src/main.cpp:5929-6107`: `WndProc` fast paths, hotkey, ImGui handler, paint, size, focus, activation.
- `src/standalone/src/helpers/helpers.cpp:333-341`: center-view render logging.
- `src/standalone/src/helpers/helpers.cpp:6677-6713`: `test_all_features::pump_ui_thread_jobs` timing.
- `src/standalone/src/helpers/helpers.cpp:6733-6748`: center-view slow-exit diagnostics.

## Evidence-Based Current Bottlenecks

- The message pump currently preserves the known responsiveness invariants. `kAidaQueuedPeekFlags` includes `PM_QS_SENDMESSAGE`, send-only drain uses `kAidaSendOnlyPeekFlags`, and the empty-queue branch logs `peek_empty_probe` but still reaches the normal `PeekMessage` call.
- `wait_for_frame_latency_object` currently wakes on `kAidaInteractiveQueueBits`, not the full pump mask. A synchronous send, paint, or timer posted after the pre-frame pump may not wake this wait until the 16 ms timeout. That is not proven to be a hang, but it is a measurable latency window.
- The post-frame idle block at `src/standalone/src/main.cpp:5517-5595` computes `bulk_busy`, `full_test_running`, `since_interaction_ms`, `foreground`, `cursor_over_aida`, `interactive_pending`, and `idle_block_mask`, then only logs `idle_pacing_sample`. In the inspected source it does not apply an adaptive wait after present, so visible background or idle foreground states can continue rendering at VSync cadence.
- `aida_focus_monitor::focused()` is updated by a worker that sleeps 200 ms. This is good enough as a fallback but too stale to be the sole foreground/background pacing signal. The direct `aida_cursor_over_window(hwnd)` check mitigates hover delay and must remain part of the foreground-like decision.
- `CreateDeviceD3D` logs waitable enablement, but it does not currently log the optimized swapchain creation HRESULT, fallback path, final swap effect, driver type, feature level, or whether waitable support survived resize paths. Without those fields, swapchain support and fallback behavior remain partially unknown.
- Existing render diagnostics are already rich for stalls (`RENDER_STALL`, `send_only_drain_slow`, `dispatch_slow`, render-center slow exits). New logs should be low-noise timing samples and state transitions, not per-frame spam.

## Proposed Implementation Plan

1. Add low-noise timing instrumentation before behavior changes.
   - Extend `idle_pacing_sample` near `src/standalone/src/main.cpp:5572` to include `foreground_like`, `may_wait`, `planned_wait_ms`, `wait_result`, `wait_elapsed_ms`, `wait_mask`, `queue_before`, `queue_after`, `occluded`, `iconic`, `present_hr`, and whether `g_FrameLatencyWaitableObject` is set.
   - Add a `swapchain_create_result` log in `CreateDeviceD3D` around `src/standalone/src/main.cpp:5740-5757` with optimized HRESULT, fallback HRESULT, driver type, feature level, flags, swap effect, resize flags, and final waitable state.
   - Add a `focus_state_change` log in `WndProc` focus/activate cases around `src/standalone/src/main.cpp:6087-6107` and in the focus monitor worker around `src/standalone/src/main.cpp:2048-2051`.
   - Keep log cadence state-transition based plus periodic 15 s samples in normal mode. Full Test can keep tighter samples.

2. Reintroduce adaptive post-frame pacing using message-aware waits, not blind sleeps.
   - Implement this in the post-frame block at `src/standalone/src/main.cpp:5517-5595`.
   - Use `foreground_like = aida_focus_monitor::foreground_belongs_to_process(hwnd) || aida_focus_monitor::focused() || cursor_over_aida`.
   - Use `may_wait = !full_test_running && !bulk_busy && !interactive_pending && since_interaction_ms >= 150 && !io.WantTextInput && !io.WantCaptureKeyboard && !ImGui::IsAnyItemActive() && !cursor_over_aida`.
   - Use `MsgWaitForMultipleObjectsEx(0, nullptr, planned_wait_ms, kAidaPumpQueueBits, MWMO_INPUTAVAILABLE)` so messages wake immediately.
   - Suggested first pass wait budget:
     - 0 ms when cursor is over AiDA, input is pending, Full Test is running, a bulk/static operation is active, text input is active, an ImGui item is active, or recent interaction is under 150 ms.
     - 4-8 ms for idle foreground-like state after 150 ms of no interaction.
     - 16-24 ms for foreground-like state after longer idle if no animations are active.
     - 50-75 ms only when truly background-like and not cursor-over.
     - 100-150 ms only when iconic or confirmed occluded, while still using `MsgWaitForMultipleObjectsEx` with the pump mask.
   - Do not use `Sleep` for the general idle path. Keep the existing occlusion path at `src/standalone/src/main.cpp:5039-5044` only until an equivalent message-aware occlusion wait is implemented and verified.

3. Broaden frame-latency wait wake conditions without weakening the pump.
   - In `wait_for_frame_latency_object` at `src/standalone/src/main.cpp:2663-2692`, evaluate replacing `kAidaInteractiveQueueBits` with a dedicated `kAidaFrameWaitQueueBits` that includes at least `kAidaInteractiveQueueBits | QS_SENDMESSAGE | QS_PAINT`.
   - Consider using `kAidaPumpQueueBits` if timer wakeups do not erase CPU savings in runtime logs.
   - Preserve all existing pre-wait skip logging and add fields for the exact wake mask and result class.
   - Unknown: whether including `QS_TIMER` will create excessive wakeups in AiDA's current UI. Measure before committing to the full mask.

4. Make focus/background pacing event-driven with the poll as a fallback.
   - Update focus state on `WM_SETFOCUS`, `WM_KILLFOCUS`, `WM_ACTIVATE`, and `WM_ACTIVATEAPP` near `src/standalone/src/main.cpp:6087-6107`.
   - Add `WM_MOUSEMOVE` and `WM_MOUSELEAVE` handling if needed to maintain an event-backed cursor-inside flag. The existing per-frame `aida_cursor_over_window` should remain as a correctness fallback.
   - Avoid any change that allows background pacing while `cursor_over_aida == true`; this was the confirmed cause of visible hover latency in prior diagnostics.

5. Keep DX11 swapchain changes conservative until logs prove a need.
   - Keep `Present(1, 0)` in `seh_swapchain_present` for stable VSync unless timing logs prove present blocking is the main responsiveness cost.
   - Do not replace `D3D11CreateDeviceAndSwapChain` with a factory/swapchain-desc1 path in the first implementation pass. That is higher risk than the pacing changes.
   - After resize paths at `src/standalone/src/main.cpp:5063-5092` and `src/standalone/src/main.cpp:5295-5311`, sample whether the waitable handle is still non-null and whether frame-latency waits continue returning expected values. Unknown: current runtime behavior across `ResizeBuffers` has not been proven by logs in this inspection.

6. Add frame phase timing only where it can isolate real bottlenecks.
   - Add sampled timings around `wait_for_frame_latency_object`, `seh_dx11_new_frame`, `seh_win32_new_frame`, `seh_imgui_new_frame`, `helper.Render`, `seh_clear_main_render_target`, `seh_imgui_dx11_render`, and `seh_swapchain_present`.
   - Report a compact `frame_timing_sample` every 15 s in normal mode and every 1 s during Full Test, plus immediate logs when any phase exceeds thresholds such as 16 ms for present/wait and 32 ms for UI/render phases.
   - Reuse existing `aida_tracer` fields where possible instead of adding independent state that can disagree with the stall tracer.

## Verification Steps For The Host Implementer

1. Static invariant check after edits:
   - Verify `kAidaQueuedPeekFlags` still contains `PM_QS_SENDMESSAGE`.
   - Verify `kAidaSendOnlyPeekFlags` is still `PM_REMOVE | PM_QS_SENDMESSAGE`.
   - Verify `queue_current == 0` still reaches the normal `PeekMessage(&msg, nullptr, 0, 0, kAidaQueuedPeekFlags)` path.
   - Verify the send-only branch still continues pumping after the drain attempt.

2. Build verification by the host only:
   - Run the canonical `.\build-host.cmd` after implementation.
   - Confirm build exit 0, verify exit 0, and no new warnings.
   - This planner did not build.

3. Runtime foreground responsiveness:
   - Launch the rebuilt `AiDAStandalone.exe`.
   - Let the IDE load and remain open for at least 5 minutes.
   - Probe `Get-Process AiDAStandalone | Select-Object Responding` and a `SendMessageTimeout(WM_NULL)` check against the top-level HWND.
   - Expected evidence: `Responding=True`, `IsHungAppWindow=False`, no repeated `send_only_drain_slow`, no `RENDER_STALL`, and frame logs continue.

4. Runtime cursor-over responsiveness:
   - Move the mouse over file/menu rows, hoverable buttons, and disassembly rows while AiDA is not foreground.
   - Expected evidence: `cursor_over=1`, `foreground_like=1`, `may_wait=0` or a very small wait, no 50-75 ms background wait while the cursor is over the window.

5. Runtime CPU/GPU pacing:
   - Compare foreground idle, background visible, minimized, and occluded states.
   - Expected evidence: background/iconic states show longer message-aware waits and lower CPU/GPU usage, while foreground/cursor-over states stay responsive.
   - Unknown until measured: exact CPU/GPU savings and whether `QS_TIMER` should be included in frame wait masks.

6. Full Test and busy-path protection:
   - Run Full Feature Test after host build if the user asks for runtime verification.
   - Expected evidence: `full_test=1` forces no idle wait, `pump_ui_thread_jobs_exit` remains bounded, and no test-induced UI freeze appears.

## Risks And Mitigations

- Risk: adaptive waits can reintroduce hover latency if foreground or cursor-over state is stale. Mitigation: use direct `foreground_belongs_to_process(hwnd)` and `aida_cursor_over_window(hwnd)` in the render loop, update state in `WndProc`, and log state transitions.
- Risk: broadening the frame wait mask can reduce CPU savings if timers are noisy. Mitigation: start with send/paint/input wakeups, measure timer wakeups before using the full pump mask.
- Risk: longer background waits can make background work appear slow if UI-thread jobs are tied to rendering. Mitigation: block waits when work queues are active or oldest pending/active age crosses a small threshold, and keep `pump_ui_thread_jobs_exit` slow logs.
- Risk: swapchain API changes can destabilize startup or protected builds. Mitigation: defer swapchain creation rewrites until logs prove the current optimized/fallback path is insufficient.
- Risk: extra diagnostics can become their own performance cost. Mitigation: transition-based logs plus 15 s normal cadence; Full Test remains intentionally more verbose.

## Unknowns To Resolve With Logs

- Whether the current waitable swapchain path is active on all user machines or silently falling back to the legacy swapchain.
- Whether the waitable object remains effective across `ResizeBuffers` in the current runtime path.
- The actual CPU/GPU delta between no post-frame wait, small foreground idle waits, and longer background waits.
- Whether `QS_TIMER` should be part of frame-latency and post-frame wake masks for this app.
- Whether any UI-thread jobs depend on every-frame rendering during idle background states.

docs/gui-performance-plans/render_loop_message_pump_plan.md
