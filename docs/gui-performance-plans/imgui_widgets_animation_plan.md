# ImGui Widgets Animation Performance Plan

## Goal

Make hover feedback feel immediate across AiDA's ImGui chrome and navigation without removing the smooth transitions that make panel changes, selected-tab movement, view swaps, press feedback, and intro states feel polished.

This plan intentionally avoids globally increasing animation constants. The primary fix is to separate hover entry feedback from longer-running motion: raw hover should become visible on the first rendered frame, while hover exit, active-selection movement, panel expansion, and view transitions can remain smooth.

## Inspected Areas

- `src/standalone/src/core/ui/transition.hpp:11-78`: `transition_t` drives timed view transitions.
- `src/standalone/src/core/ui/transition.hpp:111-121`: `hover_state_t::tick` springs hover amount toward 1 or 0.
- `src/standalone/src/core/ui/motion.hpp:141-174`: shared `smooth_lerp` and `spring_step`; `spring_step` clamps `dt` to 40 ms.
- `src/standalone/src/core/ui/components.hpp:104-203`: shared button uses `button_state_t.hover.tick`, then uses the delayed value for color, border, lift, and text.
- `src/standalone/src/core/ui/ui_anim.hpp:32-36`: older `ui_anim::smooth_lerp` helper.
- `src/standalone/src/core/ui/ui_anim.hpp:204-225`: `row_hover_select` already uses raw hover for instant row fill.
- `src/standalone/src/core/ui/ui_anim.hpp:678-711`: `render_pill_button` delays hover fill/text through `hover_anim`.
- `src/standalone/src/core/ui/ui_anim.hpp:738-830`: `render_hub_tab_bar` uses immediate tab hover fill/text, but still smooths scroll and active underline.
- `src/standalone/src/core/ui/ui_anim.hpp:1035-1059`: `render_popup_close_button` delays close hover through `hover_anim`.
- `src/standalone/src/core/ui/ui_anim.hpp:1128-1161`: `render_toolbar_button` delays hover fill/text through `hover_anim`.
- `src/standalone/src/core/ui/hub_strip.hpp:73-224`: `render_strip` recalculates tab widths every frame and delays tab hover through `st.hover_v[i]`.
- `src/standalone/src/helpers/helpers.cpp:3314-3388`: main IDE layout and panel width animations.
- `src/standalone/src/helpers/helpers.cpp:3389-3640`: title bar, breadcrumbs, close/max/min, and theme toggle hover paths.
- `src/standalone/src/helpers/helpers.cpp:4078-4135`: top menu bar hover smoothing through `h_v`.
- `src/standalone/src/helpers/helpers.cpp:4439-4548`: splitters already use raw hover for cursor and line feedback.
- `src/standalone/src/helpers/helpers.cpp:4572-4671`: activity bar icon hover smoothing and active indicator spring.
- `src/standalone/src/helpers/helpers.cpp:4685-4695`: activity-bar settings gear hover uses `hover_state_t`.
- `src/standalone/src/helpers/helpers.cpp:4719-5199`: search, recent, and explorer left-panel rows.
- `src/standalone/src/helpers/helpers.cpp:5144-5149`: explorer refresh and watcher are called inside render.
- `src/standalone/src/helpers/helpers.cpp:5152-5187`: explorer rows already draw hover from raw `hov`.
- `src/standalone/src/helpers/helpers.cpp:5210-5295`: center header `ghost_btn` and `flat_btn` smooth hover entry and underline width.
- `src/standalone/src/helpers/helpers.cpp:5344-5419`: tab-strip entry vector and text widths are rebuilt each frame.
- `src/standalone/src/helpers/helpers.cpp:5448-5573`: file tab strip scroll/active underline are smooth; tab hover fill is immediate.
- `src/standalone/src/helpers/helpers.cpp:5608-5764`: pseudocode and hex tab hover fill is immediate.
- `src/standalone/src/helpers/helpers.cpp:5795-5972`: strip chevrons, dropdown, and popup rows use raw hover.
- `src/standalone/src/helpers/helpers.cpp:5988-6283`: right-side hub tabs use raw hover fill, but hover preview underline is smoothed through `hub_uh_*`.
- `src/standalone/src/helpers/file_browser.cpp:44-137`: synchronous recursive refresh, sorting, and entry replacement.
- `src/standalone/src/helpers/file_browser.cpp:140-147`: directory toggle marks `needs_refresh`.
- `src/standalone/src/helpers/file_browser.cpp:572-799`: filesystem watcher runs on the work queue and marks `needs_refresh`.
- `src/standalone/src/helpers/globals.h:454-468`: `FileBrowserEntry` has no cached width, stable row id, or metadata for render caching.
- `src/standalone/src/main.cpp:2627-2728`: DXGI frame-latency waitable object uses `MsgWaitForMultipleObjectsEx` with interactive queue bits.
- `src/standalone/src/main.cpp:5518-5593`: post-frame idle pacing treats mouse movement as interaction and logs `idle_pacing_sample`.
- `src/standalone/src/core/ui/blur_layer.hpp:20-44`: blur requests append to a per-frame vector.
- `src/standalone/src/core/ui/blur_layer.hpp:46-85`: glass fill, border, inner glow, and drop shadow helpers add multiple draw calls.
- `src/standalone/src/helpers/blur.cpp:168-179`: slow blur callback logging already exists.

## Current Bottlenecks

1. Hover entry is animated in several chrome widgets, so the first hover frame can be visually faint even when the click path is instant. This affects shared buttons, title-bar controls, the top menu bar, activity-bar icons, the settings gear, center header buttons, `hub_strip::render_strip`, `render_pill_button`, `render_popup_close_button`, and `render_toolbar_button`.

2. The explorer tree rows themselves are not the main animation problem. `helpers.cpp:5159-5163` draws explorer row hover directly from raw `hov`. If explorer hover feels delayed after the frame-pacing fix, the likely causes are render-thread work around the explorer, synchronous refresh, or frame wake/present pacing rather than the row hover style.

3. `file_browser::refresh` is synchronous and can run from the render path when `needs_refresh` is set. Large directories or expanded trees can block the UI thread before the next hover frame.

4. `helpers::render_title` performs high-frequency allocation and layout work in chrome paths: breadcrumb `std::vector<std::string>`, tab-strip entry vectors, repeated `ImGui::CalcTextSize`, recent JSON parsing, recent open/closed filtering, search result grouping, and per-row string truncation.

5. `hub_strip::render_strip` recalculates all tab labels and widths every frame and smooths `st.hover_v[i]`, so tab hover appears delayed even though tab selection remains immediate.

6. Blur and glow helpers add multiple draw operations. The title bar, menu bar, activity bar, popups, inner glows, and drop shadows are acceptable visually, but they should be coalesced or skipped when invisible, not multiplied by unnecessary hover state.

7. Existing diagnostics cover render stalls, draw-data counts, slow blur callbacks, center slow exits, frame-latency waits, and idle pacing. They do not yet isolate raw hover transition latency per widget.

## Proposed Hover Model

Add a narrow hover-response primitive instead of changing animation speeds globally.

Recommended shared behavior:

- Hover enter: visual amount becomes 1.0 on the first frame that raw `hovered` is true, or at minimum jumps to a high floor such as 0.92 while retaining optional micro-lift smoothing.
- Hover stay: visual amount remains 1.0 while raw `hovered` is true.
- Hover exit: visual amount eases or springs back to 0 using the current balanced/snappy motion.
- Active/selected state: remains independently smooth where it represents navigation, selected underline movement, panel expansion, or content transitions.
- Press/click state: remains smooth and separate from hover so click feedback still has physical motion.

Best implementation shape:

- Extend `aida::ui::hover_state_t` in `transition.hpp:111-121` with a method such as `tick_instant_on_smooth_off(bool hovered, float dt, spring_t exit_spring)`.
- Add a simple helper in `motion.hpp` only if both `aida::ui` and legacy `ui_anim` call sites need a dependency-light version.
- For legacy `float& hover_anim` APIs in `ui_anim.hpp`, update the caller-local math to set `hover_anim = 1.f` on enter and smooth only when target is 0.
- Keep the existing `tick` method for non-hover uses that intentionally want a spring on both entry and exit.

## Targeted Code Changes

1. Shared components

- In `components.hpp:130-139`, use instant-on/smooth-off hover for the visual hover amount used by fill, border, text, and basic hover visibility.
- Keep `press.tick`, `flash.tick`, focused ring, and loading animation unchanged.
- Consider keeping the vertical lift partially smoothed if the instant 1.5 px lift feels jumpy. The color/fill/text must still be immediate.

2. Title bar

- In `helpers.cpp:3487-3503`, `3523-3543`, `3579-3593`, and `3597-3640`, replace `hover_state_t::tick` for close/max/min/theme with instant-on/smooth-off.
- Use raw hover or instant visual for the first-frame fill and icon color. Keep click handling exactly on raw hover.
- Breadcrumb hover at `helpers.cpp:3460-3474` is already immediate and should remain unchanged.

3. Top menu bar

- In `helpers.cpp:4121-4129`, set `h_v` to 1 immediately when `hov || is_open`, then smooth only when the menu is neither hovered nor open.
- Do not change popup open/close behavior at `helpers.cpp:4137-4164`; it already responds to raw hover/click.

4. Activity bar and gear

- In `helpers.cpp:4607-4626`, make icon hover wash and icon text immediate on hover; preserve the active indicator spring in `helpers.cpp:4651-4671`.
- In `helpers.cpp:4685-4695`, make the gear hover background immediate on enter and smooth on exit.

5. Center header buttons

- In `helpers.cpp:5243-5268`, make `ghost_btn` hover fill, border, and text immediate on enter; keep click flash `bft` smooth.
- In `helpers.cpp:5272-5295`, make `flat_btn` text brightness immediate on enter. For underline, either draw full underline immediately on enter and smooth out on leave, or snap to a high floor and finish in one frame.

6. Hub strip and tab helpers

- In `hub_strip.hpp:178-185`, stop using the smoothed `hover_v[i]` as the only gate for hover wash. Draw first-frame hover from raw `hovered`, then use smoothed state only for exit fade or secondary glow.
- In `hub_strip.hpp:188-194`, base text color on raw hover for first-frame brightness.
- In `helpers.cpp:6246-6281`, snap the hover preview underline target (`hub_uh_x`, `hub_uh_w`, `hub_uh_y`, `hub_uh_a`) on hover enter or target change. Smooth only fade-out when leaving.
- Keep active underline movement smooth in `hub_strip.hpp:155-164`, `helpers.cpp:5558-5573`, and `helpers.cpp:6184-6239`.

7. Legacy `ui_anim` helpers

- In `ui_anim.hpp:678-711`, make `render_pill_button` hover fill/text immediate on enter and smooth only on exit.
- In `ui_anim.hpp:1035-1059`, make popup close hover immediate on enter.
- In `ui_anim.hpp:1128-1161`, make toolbar button hover immediate on enter.
- Leave `row_hover_select` unchanged because it already uses raw hover.
- Leave `render_hub_tab_bar` active underline smoothing intact; its tab hover fill/text is already immediate.

8. Explorer rows

- Do not add hover smoothing to `helpers.cpp:5152-5187`. Preserve raw hover row fill.
- Add `ImGuiListClipper` for fixed-height explorer rows so only visible rows calculate hover/text/dummy layout.
- Add cached `name_width`, `icon_width`, and a stable id/hash to `FileBrowserEntry` if repeated width calculations or row-specific state are introduced.

## Layout, Draw-Call, and Caching Improvements

1. File browser refresh

- Replace render-thread synchronous refresh at `helpers.cpp:5144-5147` with an async snapshot request.
- Keep showing the current `file_browser::entries` while refresh is pending.
- Scan and sort on the work queue, then apply the completed snapshot on the UI thread.
- Preserve expanded directory paths across refresh.
- Validate `selected_idx` after applying the snapshot.
- Never mutate the UI-owned `entries` vector from the worker.

2. Explorer rendering

- Use `ImGuiListClipper` for `helpers.cpp:5152-5187`.
- Clip search result rows in `helpers.cpp:4857-4927`; build grouped search results once when `workspace_search::g_search.results` changes.
- Keep row hover raw and immediate for visible rows only.

3. Recent panel

- Cache parsed recent paths instead of parsing `g_sa_settings.recent_workspaces_json` every frame in `helpers.cpp:4948-4957`.
- Cache open/closed recent lists keyed by the recent JSON revision and analysis-session revision.
- Keep hover rendering immediate as currently done at `helpers.cpp:4997-5007` and `helpers.cpp:5085-5087`.

4. Tab/header strip

- Cache `strip_entries` from `helpers.cpp:5344-5419` using a small state object keyed by file tab count/active/dirty labels, pseudocode tab snapshot revision, hex active/source name, active center view, font scale, and DPI scale.
- Cache text widths instead of calling `ImGui::CalcTextSize` repeatedly in `helpers.cpp:5360-5414`, `5467-5573`, and related pseudocode/hex tab loops.
- Cache breadcrumb segments and widths in `helpers.cpp:3442-3474` until file name, editor name, or active center view changes.

5. Shared hub strip

- In `hub_strip.hpp:109-128`, cache label widths in `state_t` or caller state and invalidate on tab labels, short-label mode, font pointer, font size, or width threshold changes.
- Preserve scroll smoothing at `hub_strip.hpp:130-137` and active underline smoothing at `hub_strip.hpp:155-164`.

6. Blur and shadow

- In `blur_layer.hpp:28-44`, reserve a small pending capacity after clear or on first use so routine title/menu/activity scheduling does not reallocate.
- Skip scheduling when alpha is effectively zero or size is invalid.
- Keep popup blur separate from title/menu/activity blur because popup layering matters.
- Consider coalescing static full-width title/menu blur rectangles only if visual parity is confirmed.
- Use existing `blur_callback_slow` logging in `blur.cpp:168-179` to validate no regression.

7. Draw-data tracking

- Use existing `aida_tracer::inspect_dx11_draw_data` fields in `main.cpp:1698-1833` and render stall reports in `main.cpp:1920` to compare command count, vertex count, index count, callbacks, and reset callbacks before and after changes.

## Logging Needed

Add throttled, high-signal logs only around evidence windows:

- `ui_hover_latency_sample`: emit on hover target change for title controls, menu top items, activity bar, hub tabs, shared buttons, and explorer rows. Include widget kind, stable id, frame, raw hovered, visual value before/after, `dt`, mouse position, `g_render_section`, `cursor_over`, `interactive_pending`, and `since_interaction_ms`.
- `file_browser_refresh`: emit refresh request, worker start, worker end, UI apply start/end, directory, expanded count, entry count, elapsed ms, source reason, stale entries visible, and whether the work ran on the UI thread.
- `ui_cache_stats`: emit every 15 seconds or on cache miss burst with tab-strip cache hits/misses, width recalculations, recent parse rebuilds, search group rebuilds, clipped row count, and total row count.
- `blur_pending_sample`: emit every 15 seconds with pending request count, skipped count, coalesced count if implemented, total area, and max rect.
- Keep the existing `idle_pacing_sample` in `main.cpp:5571-5593`; after implementation it should show `cursor_over=1`, block mask including `0x00000040`, and no post-frame idle wait while the mouse is over AiDA.

These logs should be throttled and transition-driven so they diagnose hover latency without recreating the old log-volume problem.

## Verification Steps

1. Host builds after source implementation with `.\build-host.cmd`. The planner subagent must not build.

2. Review message-pump invariants if any source implementation touches `main.cpp`: `kAidaQueuedPeekFlags` includes `PM_QS_SENDMESSAGE`, send-only pending work is drained with `PM_REMOVE | PM_QS_SENDMESSAGE`, and the empty-queue path still performs a nonblocking `PeekMessage` probe after `GetQueueStatus(QS_ALLINPUT) == 0`.

3. Run AiDAStandalone and hover without clicking over:

- Title close, maximize, minimize, and theme controls.
- Top menu labels.
- Activity bar icons and gear.
- Explorer rows in a normal folder and a large folder.
- File tabs, pseudocode tabs, hex tab, tab chevrons, and tab dropdown rows.
- Right-side hub tabs such as Network, Scan, Debugger, Types, Analysis, and Binary Map.
- Shared component buttons in auth/settings/tool popups if reachable.

Expected result: hover fill/text appears on the first rendered frame after cursor entry; exit may fade smoothly.

4. Inspect `aida_debug.log` for pacing evidence while moving the mouse over AiDA:

- `idle_pacing_sample` should report `cursor_over=1` and `block_mask` containing `0x00000040`.
- `frame_latency_wait_skipped_input` should appear only as bounded input-aware skips, not as long waits during hover.
- No new `RENDER_STALL`, `peek_slow`, `dispatch_slow`, or `send_only_drain_slow` entries should appear during hover tests.

5. Inspect render-cost diagnostics:

- Existing `dx11_drawdata_inspect` and render stall context should show no material increase in draw command count, vertex count, index count, callbacks, or reset callbacks.
- Existing `blur_callback_slow` should not increase after blur scheduling cleanup.
- Existing `render_center slow_exit` and `pump_ui_thread_jobs_exit slow=1` should not correlate with simple hover.

6. Validate large explorer behavior:

- Open a directory with thousands of entries.
- Expand/collapse directories while moving the mouse over rows.
- Hover remains immediate during refresh; stale rows remain visible until the new snapshot is applied.
- Refresh logs show worker-side scan time and small UI apply time.

7. Regression checks:

- Active underline movement remains smooth.
- Panel show/hide and splitter drag remain smooth and responsive.
- Button press/click feedback still animates.
- Popups still close/open instantly from raw hover/click.
- No hover state leaks across widgets with duplicate labels.
- Theme/DPI/font changes invalidate cached widths.

## Risks

- Instant hover can make small lift animations feel abrupt. Mitigate by making color/fill/text immediate while keeping only physical lift as a short smooth motion.
- Label-based `ImGuiID` storage can collide in repeated widgets. Any new cached hover state should use stable pushed IDs or explicit row ids.
- Async file-browser refresh must not mutate UI vectors off the UI thread. Apply completed snapshots only on the render/UI thread.
- Cached tab and text widths must invalidate on theme, font, DPI, label, dirty-state, and active-view changes.
- `ImGuiListClipper` assumes fixed row height for explorer rows. If variable-height rows are later introduced, the clipper logic must be adjusted.
- Blur coalescing can subtly change layer order. Keep popup blur independent and verify visual parity before merging broad chrome layers.
- Changing frame pacing to hide hover latency would risk previous responsiveness regressions. Treat pacing as verification evidence, not the primary hover-animation fix.

## Implementation Order

1. Add the instant-on/smooth-off hover helper.
2. Apply it to shared button and legacy `ui_anim` hover helpers.
3. Apply it to title/menu/activity/header/hub call sites in `helpers.cpp` and `hub_strip.hpp`.
4. Add file-browser clipper and async refresh snapshot.
5. Add targeted hover/cache/refresh logs.
6. Add caching for recent paths, search groups, tab-strip entries, and repeated text widths.
7. Run the verification loop above and preserve smooth active/selection transitions.

Exact plan path: `C:\Users\ruar1337\AiDAPrivate\docs\gui-performance-plans\imgui_widgets_animation_plan.md`
