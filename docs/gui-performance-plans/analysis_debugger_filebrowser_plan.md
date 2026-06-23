# AiDA GUI Performance Plan: Analysis, Debugger, Disassembly, File Browser

## Scope

This plan covers standalone UI sluggishness sources in analysis/debugger/disassembly panels, the file explorer and watcher path, symbol/function indexing, and expensive per-frame or idle work. It is based on the current worktree contents only; existing modified source files were treated as user state and were not changed.

## Priority 1: File Explorer UI-Thread Work

### Hot paths

- `src/standalone/src/helpers/helpers.cpp:5144-5149`: the render path calls `file_browser::refresh()` when `needs_refresh` or `entries.empty()`, then calls `file_browser::tick_watcher()` every Explorer frame.
- `src/standalone/src/helpers/file_browser.cpp:44-137` (`file_browser::refresh`): recursively scans the current tree synchronously with `std::filesystem::directory_iterator`, sorts directories/files at every expanded node, and rebuilds `entries`.
- `src/standalone/src/helpers/helpers.cpp:5152-5187`: Explorer row rendering iterates every `file_browser::entries` row without an `ImGuiListClipper` or manual visible-row range.
- `src/standalone/src/helpers/file_browser.cpp:140-147` (`toggle_dir`): any folder expand/collapse marks the whole tree dirty, forcing a full synchronous rebuild on the next render.
- `src/standalone/src/helpers/file_browser.cpp:590-604` and `742-758`: changing watched directories can wait up to about 1 second in `stop_watcher_locked` from `ensure_running_for`, which is reached from render via `tick_watcher`.
- `src/standalone/src/helpers/file_browser.cpp:770-773`: the long-lived directory watcher is posted to the shared `work_queue`.
- `src/standalone/src/helpers/helpers.cpp:4832-4853`: Search results are regrouped every render from `workspace_search::g_search.results`.
- `src/standalone/src/helpers/helpers.cpp:4915-4919`: clicking a search result opens and reads the entire file synchronously on the UI thread.
- `src/standalone/src/helpers/helpers.cpp:4948-4957`: Recent workspaces JSON is parsed every render of the Recent tab.

### Proposed changes

- Replace synchronous `file_browser::refresh` use from render with a generation-based snapshot:
  - UI thread only requests a refresh and renders the last committed snapshot.
  - Worker builds `std::vector<FileBrowserEntry>` and publishes it by atomic generation/swap.
  - `needs_refresh` becomes a request flag, not direct permission to scan on render.
- Preserve expansion state in a `std::unordered_set<std::string>` or normalized path key, so `toggle_dir` only invalidates affected subtree metadata and does not require scanning unchanged sibling folders.
- Add `ImGuiListClipper` or a manual visible range to `helpers.cpp:5152-5187`.
- Replace watcher stop from render with nonblocking handoff:
  - `ensure_running_for` should enqueue stop/start state transitions and return immediately.
  - Add bounded logs when a previous watcher is still stopping, rather than sleeping in the render path.
- Move the watcher from the shared app `work_queue` to a dedicated filesystem watcher worker or a small watcher service queue. The watcher is long-lived and should not occupy shared analysis/debugger worker capacity.
- Cache Search result groups keyed by `results_generation`, `query`, and collapsed-file set. Render should consume immutable grouped rows.
- Open clicked search result files through a deferred file-open task or reuse an existing file-content cache; the UI thread should only switch once content is ready.
- Cache parsed recent workspace entries in settings/session state and invalidate only when `recent_workspaces_json` changes.

### Logging needed

- `file_browser_refresh_request`: `dir`, `reason`, `old_generation`, `expanded_count`.
- `file_browser_refresh_worker_enter/exit`: `dir`, `elapsed_ms`, `entry_count`, `dir_count`, `file_count`, `max_depth`, `cancelled`, `work_queue_pending`, `worker_tid`.
- `file_browser_refresh_publish`: `generation`, `entry_count`, `ui_wait_ms`.
- `file_browser_render_cost`: sampled at 1 to 5 seconds, `entries_total`, `visible_rows`, `elapsed_us`, `clipper=1`.
- `file_browser_watcher_transition`: `old_dir`, `new_dir`, `stop_requested`, `stop_elapsed_ms`, `post_ok`, `deduped_change_count`.
- `workspace_search_render_cost`: `results_total`, `groups_total`, `group_cache_hit`, `elapsed_us`.

## Priority 2: Disassembly Visible-Row Metadata and Layout Rebuilds

### Hot paths

- `src/standalone/src/core/disasm/disasm_view.cpp:4328-4344`: render entry logs periodically and drives all disassembly UI work.
- `src/standalone/src/core/disasm/disasm_view.cpp:4404-4421`: live pending instruction vectors are moved into the displayed file during render.
- `src/standalone/src/core/disasm/disasm_view.cpp:4449-4465`: live mode requests background decode from render on a timer.
- `src/standalone/src/core/disasm/disasm_view.cpp:4692-4721`: layout rebuilds when format/function-index signature changes; during static bulk function indexing the debounce is only 16 ms.
- `src/standalone/src/core/disasm/disasm_view.cpp:4804-4815`: visible range warming calls `xref_index::warm_range`, `function_index::warm_range`, and `symbol_classifier::warm_range`; static mode allows this every 16 ms.
- `src/standalone/src/core/disasm/disasm_view.cpp:5243-6208`: visible row rendering does many per-row lookups, string formats, cache checks, and optional annotation building.
- `src/standalone/src/core/disasm/disasm_view.cpp:5460-5479`: each uncached visible row may call `function_index::rows_before`, `rows_after`, `inline_label_at`, `xref_index::query_to`, `function_index::is_inside_known_function`, and `loc_label_for`.
- `src/standalone/src/core/disasm/disasm_view.cpp:5490-5501`: `prime_var_cache` may run per visible row or function.
- `src/standalone/src/core/disasm/disasm_view.cpp:5780-5783`: inline xref cache misses query xrefs while rendering visible rows.
- `src/standalone/src/core/disasm/disasm_view.cpp:5926-5968` and `6035-6129`: operand/comment composition lazily does symbol classification, builtin type lookup, auto-comment updates, symbol resolution, and demangling during row rendering.
- `src/standalone/src/core/disasm/disasm_view.cpp:6141-6166`: comment trimming performs width-dependent binary search with repeated text measurement.
- `src/standalone/src/core/disasm/zydis_disasm.hpp:167-170`: all `zydis_decode_one` calls serialize on one global mutex.
- `src/standalone/src/core/disasm/zydis_disasm.hpp:593-663`: live decode worker is posted to the shared `work_queue`; post failure is not handled here.

### Proposed changes

- Introduce a `visible_row_metadata_cache` keyed by `{address, instr_generation, function_index_generation, xref_generation, comment_generation, theme_generation}`. Store:
  - before/after injection rows,
  - inline label,
  - xref summaries,
  - directive/mnemonic overrides,
  - inline/function comments,
  - operand colored runs and measured widths,
  - trimmed comment by width bucket.
- Batch function-index/xref/symbol-classifier reads for the visible range:
  - Fetch all visible metadata once per frame into a snapshot.
  - Hold `function_index` shared locks once per visible range instead of once per accessor per row.
  - Keep the render loop mostly draw-only.
- Raise static-mode warm debounce from 16 ms during bulk indexing, or gate `warm_range` by scroll/input movement and last visible address range. Static bulk can otherwise compete with layout rebuilds and visible-row rendering.
- Make layout rebuild incremental:
  - Hard invalidation still rebuilds immediately.
  - Soft function-index signature changes should accumulate and rebuild at a lower cadence while bulk work is active, unless visible rows are affected.
- Move live pending instruction publish to a small immutable snapshot swap:
  - Worker prepares `DisasmFile`/instruction snapshot.
  - Render swaps pointers/generations rather than mutating the displayed file object and then recalculating selection state inline.
- Replace the global Zydis mutex with thread-local decoder/formatter state, or split decoder state from formatter state so background decode, CFG build, debugger CPU disasm, and function scans do not serialize.
- Handle `work_queue::post` failure in `request_live_decode` by resetting `live_decoding`, recording a bounded failure, and showing stale content rather than leaving the live decode state ambiguous.

### Logging needed

- `disasm_frame_cost`: `instrs`, `first_row`, `last_row`, `visible_count`, `layout_ready`, `layout_rebuilt`, `bulk_active`, `elapsed_us`.
- `disasm_visible_metadata`: `range_lo`, `range_hi`, `rows`, `cache_hits`, `cache_misses`, `function_index_queries`, `xref_queries`, `symbol_queries`, `elapsed_us`.
- `disasm_layout_rebuild`: keep existing lines at `4692-4721`, add `reason=hard|soft|bulk_tick|visible_affected`, `old_sig`, `new_sig`, `elapsed_ms`.
- `disasm_live_decode_post_failed`: `pid`, `win_start`, `read_sz`, `work_queue_pending`, `active`, `rejected`.
- `zydis_decode_contention`: sampled mutex wait time before replacing the global mutex.

## Priority 3: Function and Symbol Indexing Contention

### Hot paths

- `src/standalone/src/core/analysis/functions_panel.hpp:1196`: `detail::launch_build_if_needed` is called every Functions panel render.
- `src/standalone/src/core/analysis/functions_panel.hpp:902-910`: attached mode enumerates modules and selects a target module before deciding whether work is needed.
- `src/standalone/src/core/analysis/functions_panel.hpp:942-947` and `985-990`: build tasks are posted to `work_queue`, but the return value is ignored; `building` can remain true if the post fails.
- `src/standalone/src/core/analysis/functions_panel.hpp:260-358` and `815-879`: function list builds walk PE/runtime function data, exports, PDB symbols, and symbol resolution on workers.
- `src/standalone/src/core/analysis/functions_panel.hpp:993-1039`: filter rebuild lowercases names/sections and scans every entry when dirty.
- `src/standalone/src/core/analysis/functions_panel.hpp:1041-1092`: sorting copies `filtered_indices` and sorts under `s.mtx`.
- `src/standalone/src/core/analysis/functions_panel.hpp:1423-1448` and `1626-1645`: compact/table render copies the whole sorted index vector, then locks again per visible row to copy each `function_entry_t`.
- `src/standalone/src/core/disasm/function_index.hpp:1113-1274`: live bounds rebuild parses PE data and reads up to 64 MB of `.text` through the driver.
- `src/standalone/src/core/disasm/function_index.hpp:2130-2175`: function body scan can decode up to 1 MB per function with periodic sleeps.
- `src/standalone/src/core/disasm/function_index.hpp:3051-3075` and `3176-3209`: bulk function analysis fans out tasks through the shared `work_queue`.
- `src/standalone/src/core/disasm/function_index.hpp:3393-3445`: visible-range warm can schedule function builds from render-driven code.
- `src/standalone/src/core/disasm/function_index.hpp:3448-3500` and `3696-3845`: many function-index accessors each take a shared lock and perform `upper_bound` or map lookup.
- `src/standalone/src/core/analysis/symbol_store.hpp:471-476`: local PDB search can recursively scan the symbol cache.
- `src/standalone/src/core/analysis/symbol_store.hpp:637-797`: PDB load/parse is backgrounded but uses the shared `work_queue`.
- `src/standalone/src/core/analysis/symbol_store.hpp:1625-1638`, `1658-1668`, and `1791-1794`: symbol resolution can linearly scan all loaded PDB symbols under the global symbol mutex.

### Proposed changes

- Give the Functions panel a `module_snapshot` source updated by attach/session events and a slow timer. Render should compare immutable module generation, not call `driver_bridge::enumerate_modules()` itself.
- Handle `work_queue::post` results in `launch_build_if_needed`; on failure clear `building`, restore `ready` if a prior snapshot exists, and log post failure with queue stats.
- Replace per-visible-row locks in Functions render with an immutable `shared_ptr<const function_list_snapshot_t>` containing entries and sorted/filtered views. Rendering should copy the `shared_ptr`, not vectors.
- Precompute lowercase `name_lower` and `section_lower` during function list build. Filtering should not allocate/lowercase every entry on each filter change.
- Move sort/filter work to a small worker when the list is large, publish sorted index generation, and keep the previous view visible until the new one is ready.
- Create a dedicated analysis-index queue or bounded worker group for function-index bulk work, PDB parse, static code index, and live decode. Shared `work_queue` starvation has already been a known Test Lab issue.
- Add symbol-store range indexes:
  - sorted function symbols by RVA for nearest-symbol lookup,
  - case-insensitive name map,
  - module lookup by address range.
  This removes linear scans from `resolve_symbol`, `resolve_function_display_name`, and `resolve_name_to_addr`.
- Cache PDB local lookup results by `{cache_dir, pdb_name, cache_dir_mtime_generation}` to avoid repeated recursive scans.
- Limit function-index bulk dispatch concurrency. Instead of posting up to 256 nested tasks per chunk into the shared queue, use a bounded dispatcher with `max_in_flight` tied to worker count and cancellation.

### Logging needed

- `functions_panel_render_cost`: `entries`, `shown`, `row_view_copy_us`, `visible_row_lock_count`, `elapsed_us`.
- `functions_panel_build_request`: `source=live|disk`, `module`, `base`, `size`, `pid_token`, `need_build`, `post_ok`, queue stats.
- `functions_panel_filter_sort`: `entries`, `filter_len`, `filter_elapsed_ms`, `sort_elapsed_ms`, `dirty_reason`.
- `function_index_bulk`: `targets`, `posted`, `in_flight_max`, `post_failed`, `queue_pending`, `elapsed_ms`, `cancelled`.
- `symbol_resolve_slow`: sampled when lookup exceeds 1 ms, with module count, symbol count, exact/nearest/name lookup mode.

## Priority 4: Types Hub and Analysis Browser Per-Frame Rebuilds

### Hot paths

- `src/standalone/src/core/analysis/types_hub_view.hpp:691-705`: merged PDB/builtin/import type data is rebuilt synchronously when the 350 ms cache expires.
- `src/standalone/src/core/analysis/types_hub_view.hpp:504-666`: building the merged types snapshot walks PDB modules, builtin structs/enums/typedefs, synthesized imports, and sorts all lists.
- `src/standalone/src/core/analysis/types_hub_view.hpp:672-675`: merged type construction happens while holding `symbol_store::g_state.mutex`.
- `src/standalone/src/core/analysis/types_hub_view.hpp:1721-1870`: every browser render rebuilds labels, sublabels, origin vectors, and visible indexes from the full selected category.
- `src/standalone/src/core/analysis/types_hub_view.hpp:1617-1703`: `render_list_pane` loops all rows and manually skips invisible rows, rather than clipping the iteration itself.
- `src/standalone/src/core/analysis/types_hub_view.hpp:2056-2061`: active and previous tab content can both render during strip swap, doubling the current tab’s list/filter work during transitions.

### Proposed changes

- Invalidate `merged_types_t` only on PDB load/failure/module/import-generation events, not every 350 ms.
- Build merged type snapshots on a background analysis queue and publish immutable `shared_ptr<const merged_types_t>`; render uses the last complete snapshot.
- Avoid holding `symbol_store::g_state.mutex` while copying large PDB data. Capture minimal shared pointers or module snapshots under the mutex, then merge/sort outside it.
- Cache category filter results by `{merged_generation, tab, search_text}`. Store visible indexes and preformatted sublabels.
- Convert `render_list_pane` to `ImGuiListClipper` or manual first/last visible calculation before row work.
- During tab transitions, only render the previous tab as a lightweight cached bitmap-like draw state or suppress heavy list rebuild for the outgoing tab.

### Logging needed

- `types_merge_build`: `reason`, `pdb_modules`, `pdb_symbols`, `structs`, `enums`, `typedefs`, `imports`, `elapsed_ms`, `mutex_hold_ms`.
- `types_filter_build`: `tab`, `items`, `visible`, `query_len`, `elapsed_us`, `cache_hit`.
- `types_render_cost`: `active_tab`, `swap_active`, `rows_total`, `visible_rows`, `elapsed_us`.

## Priority 5: Debugger Panels and Driver Read Cadence

### Hot paths

- `src/standalone/src/core/debugger/debugger_view.cpp:1486-1487`: CPU tab requests register refresh every 120 ms and copies cached registers.
- `src/standalone/src/core/debugger/debugger_view.cpp:1148-1194`: live CPU disassembly requests bytes every 220 ms, then decodes up to 256 instructions on the render thread every frame from cached bytes.
- `src/standalone/src/core/debugger/debugger_engine.cpp:3703-3768`: `request_disasm_refresh` can perform synchronous `refresh_disasm_window_now` after work-queue post failure or forced recovery.
- `src/standalone/src/core/debugger/debugger_engine.cpp:3665-3700`: synchronous disasm refresh performs a driver `read_memory` of 0x400 bytes.
- `src/standalone/src/core/debugger/debugger_view.cpp:2914-2915`: Threads tab requests refresh every 250 ms and copies cached thread list.
- `src/standalone/src/core/debugger/debugger_view.cpp:3212-3216` and `3254-3257`: Watches tab copies all watches, then evaluates each visible watch expression during render.
- `src/standalone/src/core/debugger/debugger_view.cpp:3485-3506`: Trace tab filters the entire trace log and lowercases each instruction text every frame.
- `src/standalone/src/core/debugger/debugger_view.cpp:3634-3647`: Strings tab filters the entire string list and lowercases each string every frame.
- `src/standalone/src/core/debugger/memory_map_view.hpp:600-614` and `620-627`: Memory Map copies all regions, filters, then recomputes stats every frame.
- `src/standalone/src/core/debugger/module_view.hpp:229-241`: Modules auto-refresh every 5 seconds from render-triggered logic.
- `src/standalone/src/core/debugger/module_view.hpp:336-343`, `486-489`, and `553-559`: Module/import/export filtering copies matching rows every render.

### Proposed changes

- Cache CPU disassembly decoded rows by `{cached_disasm_base, bytes_generation, rip_window_start}`. Render should reuse decoded rows until bytes or RIP window changes.
- Remove synchronous driver-read fallback from render-triggered `request_disasm_refresh`; on worker post failure, keep stale cached bytes, reset in-flight state, log, and show a bounded stale indicator.
- Convert register/thread/stack/disasm refresh requests into a debugger refresh scheduler:
  - coalesce requests from visible panels,
  - prioritize active tab,
  - apply backoff when the target is running or reads fail,
  - expose snapshot generations.
- Move watch expression resolution out of row rendering. Recompute resolved addresses on register generation changes or watch edit events; render should display cached resolution.
- Cache trace and string filter results by `{trace_generation|string_generation, filter_text}`. Maintain lowercase fields on append/scan instead of lowercasing full rows in render.
- Cache memory-map filtered rows and stats by `{regions_generation, filter_text}`. Recompute on refresh completion or filter changes.
- Cache module/import/export filtered rows by `{modules_generation, selected_module, filter_text, detail_kind}`.

### Logging needed

- `debugger_refresh_scheduler`: `visible_tab`, `requested_regs`, `requested_threads`, `requested_stack`, `requested_disasm`, `coalesced`, `posted`, `post_failed`, queue stats.
- `debugger_cpu_disasm_render`: `bytes_generation`, `rip`, `rows_decoded`, `cache_hit`, `decode_elapsed_us`.
- `debugger_sync_read_blocked`: any render-path driver read attempt, with `source`, `addr`, `bytes`, `elapsed_ms`, `reason`.
- `debugger_filter_cost`: `panel=trace|strings|memory_map|modules`, `source_count`, `visible_count`, `filter_len`, `cache_hit`, `elapsed_us`.

## Priority 6: CFG View Build and Render Locking

### Hot paths

- `src/standalone/src/core/disasm/cfg_view.hpp:492-500`: CFG build is posted to the shared `work_queue`.
- `src/standalone/src/core/disasm/cfg_view.hpp:500-568`: CFG build reads up to 0x10000 bytes and decodes up to 4096 instructions.
- `src/standalone/src/core/disasm/cfg_view.hpp:679-693`: build queries function-index injection rows for entry blocks.
- `src/standalone/src/core/disasm/cfg_view.hpp:948`: render holds `g_state.mutex`.
- `src/standalone/src/core/disasm/cfg_view.hpp:1004-1031`: grid dots can draw up to 4000 points.
- `src/standalone/src/core/disasm/cfg_view.hpp:1038-1055`: edge rendering searches node endpoints with an O(edges * nodes) scan.
- `src/standalone/src/core/disasm/cfg_view.hpp:1145-1174`: node loop culls after motion/hover setup, but still visits every node.
- `src/standalone/src/core/disasm/cfg_view.hpp:1267-1327`: visible node text can classify symbols and measure/draw injection rows.

### Proposed changes

- Publish a render snapshot for CFG (`nodes`, `edges`, `blocks`, `entry_injections`, layout generation) so render does not hold `g_state.mutex` across drawing.
- Precompute `node_id_to_index` during CFG build to remove O(edges * nodes) endpoint lookup.
- Precompute screen-space or world-space bounds for nodes and edges; use visible node/edge ranges when panning/zooming.
- Cache grid point draw density by zoom and viewport, or lower the grid cap under high frame cost.
- Precompute node header strings, injection row render parts, and symbol-classifier color at build time or on function-index generation changes.
- Move CFG build to the bounded analysis queue and record post failure without trying to compensate from render.

### Logging needed

- `cfg_build_cost`: `entry`, `read_ms`, `decode_ms`, `layout_ms`, `blocks`, `nodes`, `edges`, `injections`, `queue_wait_ms`.
- `cfg_render_cost`: `nodes_total`, `nodes_visible`, `edges_total`, `edges_visible`, `grid_points`, `mutex_wait_us`, `elapsed_us`.

## Cross-Cutting Architecture Changes

### Dedicated queues

Create separate bounded queues for:

- UI-adjacent short jobs: register/thread snapshots, small metadata publishes.
- Analysis/indexing jobs: function-index bounds, bulk function scans, PDB parse, code index, CFG build, type merge.
- Filesystem jobs: file browser refresh, directory watcher, workspace search.
- Live debugger reads: memory/disasm/stack/watch refreshes, with cancellation and target-generation validation.

The shared `work_queue` should not host long-lived watcher loops or thousands of bulk function tasks. This follows the existing diagnostic lesson that shared queue starvation caused Test Lab stalls.

### Snapshot discipline

For every panel, the UI thread should render immutable snapshots:

- Copy or atomically load a `shared_ptr<const snapshot_t>`.
- Avoid holding engine/global mutexes while drawing.
- Avoid driver reads, recursive filesystem scans, PDB scans, regex scans, or bulk lowercasing in render.
- Keep stale snapshots visible with a small "refreshing" state rather than blocking.

### Invalidation keys

Use explicit generations:

- `file_browser_generation`, `watcher_change_generation`, `workspace_search_generation`.
- `analysis_session_generation`, `module_snapshot_generation`, `pdb_generation`, `symbol_store_generation`.
- `function_index_generation`, `xref_generation`, `comment_generation`, `rename_generation`.
- `debugger_regs_generation`, `debugger_threads_generation`, `memory_map_generation`, `trace_generation`, `strings_generation`.
- `theme_generation`, `font_generation`, `layout_width_bucket`.

## Verification Steps for Later Implementation

1. Add logging first, then reproduce on a large repo and a large PE/PDB before optimizing. Capture `aida_debug.log` with frame costs and queue stats.
2. Verify idle Explorer on a large tree: no synchronous `file_browser::refresh` in render, row render cost stays bounded by visible rows, watcher changes publish a generation without UI stall.
3. Verify Search tab with thousands of results: grouping cache hits after the first frame, clicking a result does not block the message pump while reading the file.
4. Verify Disassembly static PE with deep function analysis active: scroll remains responsive, layout rebuilds are debounced, visible metadata cache hit rate rises after one frame, no global Zydis mutex contention spike.
5. Verify live disassembly/debugger CPU tab: register, stack, and disasm refreshes coalesce; no render-path `driver_bridge::read_memory` is logged; stale data remains visible if the queue rejects a job.
6. Verify Functions panel with many PDB symbols: filtering/sorting happen on generation changes only, table render does not copy the full sorted vector each frame, and failed worker posts clear `building`.
7. Verify Types Hub on a symbol-heavy PDB: merged cache invalidates on PDB/module/import events, not every 350 ms; list filtering is cached and clipped.
8. Verify CFG with a large function: render does not hold `g_state.mutex` while drawing, endpoint lookup is O(edges), visible culling reduces node/edge draw counts.
9. Host-only build verification after implementation: run the canonical `.\build-host.cmd` from the repo root and confirm zero errors and zero new warnings. This planner did not build.
10. Runtime responsiveness verification: launch the rebuilt standalone, keep `aida_debug.log` open, and confirm no `IsHungAppWindow`/message-pump stalls while scrolling Explorer, Disassembly, Functions, Types, Debugger CPU, Strings, Trace, Memory Map, Modules, and CFG.

## Risks

- Moving work off render can introduce stale UI if generation publishing is wrong. Keep last-good snapshots and log generation transitions.
- Queue isolation must preserve shutdown ordering. Long-running filesystem/debugger workers need cancellation and bounded join behavior.
- Function-index caching must preserve security and diagnostic behavior; do not drop existing crash breadcrumbs or fail-closed checks.
- Snapshotting PDB/module data must not return pointers into containers that can be mutated after the mutex is released.
- Removing synchronous debugger fallback can hide immediate read failures unless stale-state UI and logs are explicit.
- Thread-local Zydis decoders need careful initialization and no shared formatter state assumptions.
- Less frequent layout rebuilds can temporarily show stale annotations; tie invalidation to visible address ranges to keep the active viewport correct.

C:\Users\ruar1337\AiDAPrivate\docs\gui-performance-plans\analysis_debugger_filebrowser_plan.md
