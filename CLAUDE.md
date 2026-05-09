# OpenWolf

@.wolf/OPENWOLF.md

This project uses OpenWolf for context management. Read and follow .wolf/OPENWOLF.md every session. Check .wolf/cerebrum.md before generating code. Check .wolf/anatomy.md before reading files.

# CLAUDE.md

The MAIN build system is: C:\Users\ruar\AiDAPrivate\CMakeLists.txt
The BUILD for sentinel AND the aida driver (Whoswho) is the .vcxproj files! (C:\Users\ruar\AiDAPrivate\driver\WhosWho\WhosWho\WhosWho.vcxproj), (C:\Users\ruar\AiDAPrivate\driver\Sentinel\Sentinel\Sentinel.vcxproj) or (C:\Users\ruar\AiDAPrivate\driver\WhosWho\WhosWho.sln)

**YOU MUST IMPLEMENT THE 100% working, production-grade, state-of-the-art, and ready for direct implementations!!! your implementations must not cause any build errors or warnings. DO NOT ADD ANY STUBS, OR PLACEHOLDERS. EVERYTHING MUST BE 100% PRODUCTION READY, EVERYTHING HAS TO BE ACTUALLY FUNCTIONAL, THERE MUST BE NO PLACEHOLDERS, THERE MUST BE NO "TODO"s, and THERE MUST BE NO COMMENTS IN THE CODEBASE! EVERYTHING MUST WORK CORRECTLY! everything must follow best-practices. please explain *why* the change is recommended and justify it with information from the provided source codes. This will help me understand the reasoning and confirm the changes are sound!**

**comments are not allowed in the codebase, so DO NOT ADD ANY COMMENTS ANYWHERE.***

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository shape

This is **not** a single product — it is a set of interlocking components that ship together as the AiDA reverse-engineering toolkit. A change in one component frequently requires rebuilds or regen in others.

| Component | Output | Source | Notes |
|---|---|---|---|
| `AiDA` | `AiDA.dll` | `src/*.cpp`, `src/*.hpp` | IDA Pro plugin (uses `ida-sdk/`). Filename is hard-checked. THE FULL IDA-SDK IS PROVIDED AT C:\Users\ruar1337\AiDAPrivate\ida-sdk\src\include, ALWAYS USE IT WHENEVER YOU MAKE ANY CHANGES/UPDATES TO THE IDA PRO PLUGIN! |
| `AiDAStandalone` | `AiDAStandalone.exe` | `src/standalone/src/**` + `src/driver_loader.cpp` + bits of `src/` | Standalone ImGui/DX11 reverse-engineering IDE. `WIN32` GUI, requires admin, statically linked. |
| `AiDA_ARC` | `aida_core.dll` | `src/standalone/src/core/arc/arc.cpp` | Runtime core delivered by the license server after validation. **Not** linked into AiDAStandalone — served separately. |
| `WhosWho` driver | `WhosWho.sys` | `driver/WhosWho/` (separate `.sln`) | Kernel driver: anti-debug, process guard, hv_detect, SentinelBridge. |
| `Sentinel` driver | `Sentinel.sys` | `driver/Sentinel/` (separate `.sln`) | Watchdog kernel driver: heartbeats, attestation, resurrect, WSK transport. |
| `WindMapper` driver | `WindMapper.sys` | `mapper/` (separate `.sln`) | Manual-mapper. |
| `AiDAProtector` | `aida_protector.exe` | `tools/protector/` | PE protector run as a post-build step on all three end-user binaries. |
| License server | Node.js / Express | `server/` (PostgreSQL) | Primary license server. PM2 process `aida-api` on port 3001, deployed via `deploy_server.ps1`. |
| Firebase functions | Cloud Functions | `firebase/` | Alternate/legacy license path; `src/license.cpp` (IDA plugin) defaults here. |
| Discord bot | Node.js | `bot/` | Issues/revokes license keys against the server DB. **Sole distribution channel for `AiDAStandalone.exe`.** |

### Encrypted-driver embedding

The three kernel drivers are shipped as **XOR-encrypted byte arrays embedded inside `AiDAStandalone.exe` and `AiDA.dll`**, then dropped + loaded at runtime by `src/driver_loader.cpp`.

Pipeline:
1. Build the driver in its own `.sln` → `WhosWho.sys` / `Sentinel.sys` / `WindMapper.sys`.
2. HxD-export the `.sys` to the top-level `WhosWho.c` / `Sentinel.c` / `WindMapper.c` (raw `0xNN, 0xNN, ...` hex; not C code to compile).
3. `src/encrypt_whoswho.py` / `encrypt_sentinel.py` / `encrypt_windmapper.py` re-encrypt → `src/whoswho_encrypted.h` / `src/sentinel_encrypted.h` / `src/windmapper_embedded.h` + `src/windmapper_data.inc`.
4. CMake's `encrypt_drivers` target regenerates headers when the `.c` hex dumps change. `driver_loader.cpp` is `OBJECT_DEPENDS`-linked to them so MSVC re-links correctly.
5. XOR keys are **duplicated** in the Python scripts and `driver_loader.cpp` — rotate both or decryption fails.

**Never hand-edit the `.c` hex dumps or the `_encrypted.h` headers.** If a driver change isn't reflecting, touch the `.c` file or rerun the encrypt script manually.

## Build

### Presets (`CMakePresets.json`)

There is **one** supported configure preset and **one** rebuild variant. There are no fast/dev/clang-cl/standalone-only presets — every build is the protected production build. This is intentional: anti-tamper instrumentation is layered into the runtime via the protector POST_BUILD step, and an unprotected binary behaves differently enough at runtime (no .epheme/.dthunk rotation, no IAT stub, no anti-dump re-encrypt) that "it works in fast mode" tells you nothing about whether the shipping binary works. So we don't ship a fast-mode escape hatch.

| Preset | Generator / toolset | Protector | Use case |
|---|---|---|---|
| `ninja-msvc-release` (configure + build, **recommended**) | Ninja+sccache / cl.exe (`/Z7`) | ON | The canonical and only build |
| `ninja-msvc-rebuild` (build) | Ninja+sccache / cl.exe | ON | Full clean rebuild over the same configure preset |

Output goes to `build-ninja/`. The protector POST_BUILD runs unconditionally on every successful build of `AiDAStandalone.exe`, `aida_core.dll`, and `AiDA.dll`. Expect 5–15 min per protected binary on a clean rebuild; subsequent incremental builds are much faster (sccache amortizes the compile, and the protector is idempotent — `transforms.hpp::detect_already_protected` short-circuits on a re-run).

If you genuinely need to debug the raw compiler output (e.g., to attach WinDbg to a non-protected build), pass `-DBUILD_PROTECTOR=OFF` directly on the cmake command line — there is no preset that does this for you. Don't ship a binary built that way.

### CMake targets

End-user binaries: `AiDAStandalone`, `AiDA` (plugin — needs `-DIDASDK_DIR=...` or `ida-sdk/src` present), `AiDA_ARC` (`aida_core.dll`).
Toolchain helpers: `aida_build_seed_gen` (per-build random seed via PowerShell + `BCryptGenRandom`, persisted in `build_seed.txt`), `aida_pdb_scrubber` (Rich + PDB path stripping), `ghidra_sleigh_compiler` (compiles `x86-64.slaspec` → `.sla` at build time when no prebuilt copy is present), `ghidra_specs` (custom target copies `.sla`/`.pspec`/`.cspec`/`.ldefs` to build output).
Encryption: `encrypt_drivers` (re-runs the three Python scripts when `.c` hex dumps change, stamps in `${CMAKE_BINARY_DIR}`).
Static libs: `lua54_static` (filters `lua.c`/`luac.c`/`onelua.c`), `libdecomp_aida` (Ghidra decompiler subset).
Tests/aux: `DriverTest` + `TestTarget`, `BINPROTO_TEST`, `BEDaisyDumper`, `WBAES_TEST`, `MATRYOSHKA_TEST`, `nanomite_drx_test`, `dag_dispatch_test`, `overlap_test`.
Protector chain: `AiDAProtector`, `AiDAExtractPayload`, `AiDAPayloadBlob` (compiles `payload.c` with `/GS-/GR-/Zl/Ob0/EHs-`), `AiDAProtectorVerify`, `AiDAProtectorTest`, payload test binaries (`AiDAHelloLoop`, `AiDAHelloDll`, `AiDADllLoader`).

### CMake options (defaults)

| Option | Default | Effect |
|---|---|---|
| `BUILD_AIDA_PLUGIN` | ON | Build IDA plugin |
| `BUILD_AIDA_STANDALONE` | ON | Build `AiDAStandalone.exe` |
| `BUILD_ARC_DLL` | ON | Build `aida_core.dll` |
| `BUILD_PROTECTOR` | ON | Build protector + register POST_BUILD steps |
| `BUILD_PROTECTOR_TESTS` | ON | Register CTest for protector matrix |
| `BUILD_DRIVER_TEST` | ON | Build DriverTest harness |
| `BUILD_BINPROTO_TEST` | ON | Build binary-protocol unit tests |
| `BUILD_BEDAISY_DUMPER` | ON | Build BEDaisyDumper utility |
| `BUILD_WBAES_TEST` | ON | Build white-box AES self-test |
| `BUILD_MATRYOSHKA_TEST` | ON | Build 3-layer pack test |
| `AIDA_ENABLE_LTCG` | OFF | `/GL` + `/LTCG` on DLLs (slower link) |
| `AIDA_FAST_LINK` | ON | `/DEBUG` (not `/DEBUG:FULL`) |
| `AIDA_ARC_ENCRYPT_IMPORTS` | OFF | Allow `--encrypt-imports` on `aida_core.dll` only (it has the api-set resolver path) |
| `AIDA_HARDEN_RELEASE` | ON | `/GS`, `/guard:cf`, `/guard:ehcont`, `/Qspectre`, `/sdl`, `/CETCOMPAT`, `/HIGHENTROPYVA`, `/NXCOMPAT`, `/DYNAMICBASE` |
| `AIDA_HARDEN_XFG` | ON | `/guard:xfg` (Win11 22H2+ only) |
| `AIDA_PROTECTOR_LEGACY_STUB` | OFF | Use legacy stub emitter when asmjit clone fails |

### VS Code tasks

All tasks call `vcvars64.bat` from `C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\` (the installed edition on this machine — adjust the path in `.vscode/tasks.json` if you have a different SKU/version).

- **`Configure (Ninja+sccache, Release)`** — runs `cmake --preset ninja-msvc-release`. Required once after a fresh checkout, after pulling new dependencies, or after touching `CMakeLists.txt`.
- **`Build (Ninja+sccache, Release, full protector)`** — runs `cmake --build --preset ninja-msvc-release`. **This is the default build task.** Builds everything (drivers' encrypted headers excluded — those use their own .sln files); runs the protector POST_BUILD on each end-user binary.
- **`Full rebuild (Ninja+sccache, Release, full protector)`** — runs `cmake --build --preset ninja-msvc-rebuild` (clean first). Use after pulling changes that invalidate sccache's preprocessed-input keys (compile-flag changes, MSVC update, header-storm refactors).
- **`sccache: show stats`** / **`sccache: zero stats`** — cache diagnostics.

There are no fast-iteration / no-protector / clang-cl / standalone-only tasks. All builds are full-protector; iteration speed comes from sccache (compile-cached) plus protector idempotency (already-protected sections short-circuit), not from skipping protection.

### Compiler flags & defines

- MSVC x64 Release: `/std:c++17`, `/MD`, `/W3`, `/permissive-`, `/EHsc` (standalone) or `/EHa` (plugin), `/Zp8`, `/bigobj`, `/Zc:__cplusplus`.
- Hardening (when enabled): `/GS`, `/guard:cf`, `/guard:ehcont`, `/guard:xfg`, `/Qspectre`, `/sdl`. Link: `/DYNAMICBASE`, `/HIGHENTROPYVA`, `/NXCOMPAT`, `/CETCOMPAT`.
- Project defines: `NOMINMAX`, `WIN32_LEAN_AND_MEAN`, `_CRT_SECURE_NO_WARNINGS`, `UNICODE`/`_UNICODE`, `AIDA_DEEP_STEAL=1` (standalone), `GHIDRA_SPECS_DIR=...`, `TRITON_Z3_INTERFACE`, `SOL_ALL_SAFETIES_ON=1`.
- `payload.c` (in `tools/protector/payload/`) is special: `/GS-`, `/GR-`, `/Od`, `/Ob0`, `/Zl` (no CRT), `/EHs-`, `/D_NO_CRT_STDIO_INLINE`. Don't add CRT-dependent code there.

### Post-build protector

`POST_BUILD` runs the protector on all three end-user binaries. Flags differ per target — they're load-bearing:

| Target | Protector args |
|---|---|
| `AiDAStandalone.exe` | `--all --no-encrypt-imports --bind-machine --tamper-level 3 --jit --no-llm-poison --verbose` |
| `aida_core.dll` (default) | `--all --no-encrypt-imports --tamper-level 2 --deep-steal --jit --no-llm-poison --target-arc --watermark <build-seed-32> --embed-watermark` |
| `aida_core.dll` with `AIDA_ARC_ENCRYPT_IMPORTS=ON` | as above with `--no-encrypt-imports` removed |
| `AiDA.dll` | `--all --no-encrypt-imports --tamper-level 2 --no-jit --no-llm-poison --verbose` |

After the protector, `aida_pdb_scrubber` strips Rich header and PDB paths.

`--no-encrypt-imports` is **not optional on `AiDAStandalone`/`AiDA.dll`**. The runtime stub's `rebuild_iat()` (`tools/protector/payload/payload.c`) cannot resolve api-set DLL names (e.g., `api-ms-win-shell-namespace-l1-1-0.dll`) via PEB walking, so any encrypted import fails silently and crashes the CRT before `main()`. The IAT stays visible to disassemblers in exchange — this is a deliberate trade-off documented in the protector source. The internal anti-tamper orchestrator's in-process `packer_imports` is disabled for the same reason (`orchestrator.hpp` logs `packer_imports_SKIPPED_breaks_crt`).

Every successful build **produces a protected binary, not the raw compiler output**. To debug the raw binary, configure with `BUILD_PROTECTOR=OFF`. The protector is **idempotent** — `transforms.hpp::detect_already_protected` scans every section's first 4 bytes for `kPackedMagic = 0x41504B44` and exits early on a re-run, so back-to-back MSBuilds don't double-pack.

### Dependencies

Vendored under `.deps/` and `sources/`, compiled as subdirs: Zydis (encoder enabled), Unicorn (x86 only), zlib, brotli, llhttp, nghttp2, Lua 5.4 (custom static), sol2, Capstone 5.0.7, Triton (`sources/Triton`, Z3 interface ON), Ghidra decompiler subset (`sources/ghidra/.../decompile/cpp` → `libdecomp_aida`), ImGui (`.deps/imgui-src` wrapped via shim), asmjit (cloned at configure time when `BUILD_PROTECTOR` is on, pinned commit).
Pre-built: Z3 4.13.4 at `.deps/z3/z3-4.13.4-x64-win` (delay-loaded via `libz3.dll`, embedded into the exe as `RT_RCDATA` resource ID `IDR_LIBZ3_DLL`).
System: OpenSSL (must be findable by `find_package(OpenSSL)`; static `libssl_static.lib`/`libcrypto_static.lib` forced).
Build-time only: Python 3 (encrypt scripts), PowerShell (build seed gen).

The Ghidra SLEIGH spec for `x86-64` is **compiled at build time** by `ghidra_sleigh_compiler` if no prebuilt `.sla` exists, then embedded as a Win32 resource via `aida_embedded.rc.in`.

### Drivers

Each driver has its own `.sln` — open in Visual Studio with the WDK installed:

- `driver/WhosWho/WhosWho.sln` — Platform Toolset `WindowsKernelModeDriver10.0`, WDK `10.0.26100.4204`, KMDF, links `cng.lib`. SignMode is Off (manual signing); Inf2Cat disabled.
- `driver/Sentinel/Sentinel.sln` — same toolset, additionally links `netio.lib`, defines `POOL_NX_OPTIN_AUTO`.
- `mapper/WindMapper.sln` — user-mode loader (PlatformToolset `v143`), links `ntdll.lib`, `setupapi.lib`, `Shlwapi.lib`, `crypt32.lib`. Despite the name, this is the user-mode side of the manual-mapper.

After building, re-export the `.sys` to the top-level `<Name>.c` hex file, then rebuild `AiDAStandalone` so the encrypted header regenerates.

### License server

```
cd server
npm install
npm start          # node server.js (PM2 process: aida-api, port 3001)
npm test           # node --test tests/*.js
npm run migrate    # node db/migrate.js (psql against schema.sql)
```

`deploy_server.ps1` SCPs `routes/`, `crypto/`, `db/`, `server.js` to the prod box, **aligns Ed25519 keys** by pushing `server/keys/ed25519_private_b64.txt` into the remote `.env` (mismatched keys produce `arc_paged_signature_invalid` on every page fetch), runs `psql $DATABASE_URL -f db/schema.sql` (idempotent), restarts PM2 (`pm2 restart aida-api --update-env`), and smoke-tests `/health` + a license create. Single-instance fork mode is enforced; cluster mode breaks in-process rotation state.

## Architecture

### Standalone app skeleton

Entry: `src/standalone/src/main.cpp`. Boot order is load-bearing:

1. **Delay-load Z3 hook** — `__pfnDliNotifyHook2` redirects `libz3.dll` imports to the in-memory module unpacked from `RT_RCDATA` `IDR_LIBZ3_DLL` by `embedded_resources::extract_and_load_z3()`. Z3 is never on disk.
2. **Phase 1/2 self-tests** — CFF and virtualizer primitives smoke-test before any UI.
3. **`anti_tamper::orchestrator`** boots on its own thread; long-running integrity work never touches the render thread.
4. **DPI / window / D3D11 / ImGui / Freetype** bootstrap; acrylic blur via `SetWindowCompositionAttribute`.
5. **`work_queue::initialize()`** spins up 12 worker threads (`POOL_SIZE=12`, `core/infra/work_queue.hpp`). Detached `bg_init` then sequentially initializes `init_standalone_chat`, `network_view::initialize`, `memory_scanner::initialize`, `mitm_proxy::pre_initialize`, `script_engine::initialize`, `standalone_license::snapshot_code_hashes`, `anti_tamper::initialize`.
6. **`driver_bridge::initialize()`** runs in its own detached thread; on connect failure → `driver_fast_fail("initialize", err)` → `__fastfail(0xBEA7DEADu)`. Watchdog: 3 consecutive heartbeat misses → same fastfail with full diagnostics in `aida_debug.log`.
7. **License + ARC gate** — `arc_unseal_feature_blocking(feature_id=1, nonce, &out_seed)` must succeed; failure → `__fastfail(0xA1DAFA17u)`. `s_arc_startup_gate_passed` blocks the render loop until then.
8. **Render loop** — every render call wraps in SEH (`seh_render_title`, `seh_render_source_reconstruct`, …) to isolate crashes.

`helpers::helper` is a static façade that owns most UI panel state (active tabs, icon caches). Tab/panel state lives in anonymous/static namespaces inside `src/standalone/src/helpers/globals.h` — not singletons, not god-objects. Center views are driven by `globals::ui::active_center_view` (a `center_view_t` enum); "hubs" (`scan_hub`, `types_hub`, `analysis_hub`, `binary_map`) are thin sub-tab multiplexers, not duplicate registrations.

`event_bus` (`core/infra/event_bus.{hpp,cpp}`) is a type-erased pub-sub keyed by event type name with a `std::shared_mutex`. `publish` snapshots the subscriber list before invoking, so subscribers can publish or unsubscribe inside their callbacks without deadlock. Subscription IDs come from a `std::atomic<uint64_t>` (id 0 is invalid).

### IDA plugin skeleton

Entry: `src/aida.cpp` (`DllMain` + IDA `plugmod_t`). Key invariants:

- **`has_expected_plugin_filename()`** asserts the loaded DLL's basename is exactly `AiDA.dll`. Renaming the DLL → `init()` returns `PLUGIN_SKIP` and IDA silently rejects the plugin.
- **`AiDA.def` exports a single symbol: `PLUGIN DATA`.** "PLUGIN" is exactly 6 chars — the minimum that `transforms.hpp::encrypt_strings` would otherwise match. Export names are now preserved unconditionally by `collect_loader_string_ranges()`. Don't change this.
- **Standalone watchdog** runs in a detached thread from `aida_plugin_t::aida_plugin_t()`. It enumerates processes via `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` looking for `AiDAStandalone.exe` (`_wcsicmp`) every 5s. There is a 30s startup grace (6 ticks); after the standalone has been seen at least once, 3 consecutive misses (~15s) → `__fastfail(0xA1DA1DA1u)`. The plugin destructor sets `g_standalone_watchdog_stop` so plugin unload terminates the thread cleanly.
- **`mcp_server_t`** (`src/mcp_server.{hpp,cpp}`) runs a JSON-RPC 2.0 MCP server on a configurable port and writes client configs to `~/.cline/mcp_servers.json`.
- **`agent_tools.hpp`** registers ~12 tool categories via `ToolRegistry`: function/memory/comment/type/search/segment/binary/python/navigation/analysis/deobfuscation/graphrag.
- **`graphrag.hpp`** stores 768-dim embeddings in an in-memory `VectorStore` (cosine similarity). Falls back to a TF-IDF `LocalVectorizer` when the embedding API is unavailable. Pipeline: `StructureExtractor::extract_all` → `SecurityFeatureExtractor` → `LocalVectorizer` → `VectorStore::add` → `QueryEngine::search_semantic`.

### ARC runtime core (`aida_core.dll`)

Delivered by the license server after activation, written to disk + manual-mapped, then rotated/sealed in memory. Exports (resolved by `anti_tamper::orchestrator` via `GetProcAddress` for VM-nested wrapping):

`arc_init`, `arc_set_key_seed`, `arc_validate_tool_exec`, `arc_heartbeat`, `arc_heartbeat_ex`, `arc_unseal_feature` / `arc_unseal_feature_blocking`, `arc_get_comm_bridge`, `arc_download_page`, `arc_bind_driver_device`, `arc_cleanup`.

Page manager (`core/runtime/arc_page_manager.hpp`): 4 KiB pages, **50 ms plaintext window** (page is re-sealed after 50 ms idle), function-token TTL 10 s, epoch rotation every 5 min. Page key derivation:

```
HKDF-SHA256(
  ikm  = license_key | session_token | hwid,
  salt = page_index_bytes[4],
  info = "aida/streaming-page/v1" || epoch_nonce[32]
) → 32-byte AES-256-GCM key
```

`arc_build_seed.hpp` is generated at configure time from a `BCryptGenRandom` seed (PowerShell), with a constant commitment that is checked at runtime to detect tampering. Per-tool subkeys: `arc_build_subkey_bytes(domain)` → `HKDF-SHA512(seed, info=domain) → 64 bytes`.

### Driver integration pattern

UM → `driver/comm.cpp` (`voyager::device_t`) → driver dispatcher (`driver/WhosWho/.../Dispatcher.h`).

IOCTL codes are **dynamic** — both UM and KM compute `((hash_build_key(key) ^ secondary_hash(key>>3)) & 0x7FF) | 0x800`, with optional XOR by `g_server_ioctl_seed` issued during attestation. Entropy includes CPUID output and Windows build number. The accessor functions (`HB()`, `DTB()`, `PHYS()`, `BASE()`, `NCON()`, …) are in `driver/comm.h:58-100`.

`device_t::send_heartbeat()` records six diagnostics on every call — `last_heartbeat_error_` (GetLastError), `last_heartbeat_bytes_` (bytes returned), `last_heartbeat_response_` (response payload), `last_heartbeat_ioctl_code_` (computed code), `last_heartbeat_magic_` (0xDEADC0DE), and the `dioctl_result` boolean. The watchdog dumps every field into `aida_debug.log` before `__fastfail(0xBEA7DEADu)`. Don't shrink that diagnostic — past failures were impossible to triage without it.

`driver/syscall.asm::do_syscall_4` is a direct-syscall stub used by `syscall_indices::resolve_syscall_indices()` — extracts the syscall number from ntdll prologues and finds a `0F 05 C3` gadget for invocation. Used to bypass user-mode hooks.

`SentinelBridge` is the shared-memory + heartbeat channel between WhosWho and Sentinel (`driver/Sentinel/Sentinel/src/core/Heartbeat.h`, `BridgeV2.h`). The struct has `magic = 0x57484F53` ('WHOS'), mutual TSC counters, sentinel command word, and a 16-byte HMAC tag with monotonic counter. **This is load-bearing for the anti-tamper story; do not weaken it.**

### License flow & gating

- **Standalone** (`core/runtime/standalone_license.{hpp,cpp}`): HTTPS → Node server (`server/routes/license.js`). Ed25519-signed responses. On success, downloads `aida_core.dll` (ARC), watermarked with a 256-byte trailer (license HMAC, HWID hash, IP hash, integrity HMAC).
- **IDA plugin** (`src/license.cpp`): default endpoint is the Firebase function (`https://europe-west1-aida-license-prod.cloudfunctions.net/...`, `OBFSTR`-obfuscated). Embedded Ed25519 public keys (KID 1 + KID 2) in DER hex; rotation requires updating `src/license.cpp` AND the server-side primary/next key pair before `ED25519_PRIMARY_RETIRE_AT`.
- **Both share constraints**: mandatory online (no offline fallback, no cached-bypass), single canonical online path (no legacy/alt routes), main EXE distribution is **Discord-only** (no public download route on the server — `/api/download/*` only serves encrypted ARC blobs).
- `state.license_pending_activation` defaults `true` so a crash inside `license::initialize` doesn't trip `enforce_violation("license_killed")` on round one. It clears to `false` only after cached validation + ARC defer + snapshot + heartbeat restart all succeed.

The license system exposes 24 inline gate slots (`gate_chat_pre_agentic`, `gate_chat_tool_exec`, `gate_driver_attach`, `gate_native_tool_use`, …). `VERIFY_LICENSE_INLINE(slot)` folds a runtime token through `inline_gate_check` → `verify_gate_token` → `fold_integrity_token`.

### Anti-tamper orchestrator

Header-only graph rooted at `core/anti-tamper/orchestrator.hpp`. On `initialize()` it resolves five critical exports via `GetProcAddress` for VM-nested wrapping: `arc_validate_tool_exec`, `arc_heartbeat`, `arc_init`, `arc_download_page`, `arc_get_comm_bridge`. Missing exports get logged via `webhook::write_log` and skipped (AiDAStandalone/AiDA.dll only export a subset — `aida_core.dll` exports the full set).

Per-RVA opcode shuffling: `derive_function_opcode_map(rva)` does HKDF-SHA256 over `state::g_vm_master_key` with `IKM = session_keys[0..2] || rva`, `info = "aida_orch_innerk"`. The VM (`virtualizer.hpp`) has 16 virtual registers, a 256-entry forward + reverse opcode map, and rotates through 4096 handler variants per execution. JIT contract (`vm_jit.hpp`): `using jit_hook_fn = bool(*)(vm_state_t&, const uint8_t*, uint32_t)`; returns true → block consumed, dispatcher re-invokes. Hook fires AFTER `decrypt_context(vm)`. **`ATP_JIT_DISABLED` compile guard** wraps the entire JIT body — set on the AiDA plugin target so `g_jit_hook` stays null and no `PAGE_EXECUTE_READ` allocations happen inside `ida64.exe` (ACG-safe).

Watchdog runs four threads: three worker loops (A/B/C) compute witness chains every 75 ms via HMAC-SHA256 folding; a monitor loop calls `guard()` and `enforcement_tick()` every 500 ms. If 2+ workers stall, `enforce_violation("watchdog_workers_stalled")` fires.

Graduated enforcement (`enforcement.hpp`):
- Round 1: `seh_violation_post()` → POST `/api/license/violation`.
- Round 2: corrupt 16 bytes of `.text` + `.rdata`, post again.
- Round 3: corrupt 256 bytes of `.text`, post again.
- Round 4+: `execute_all_kill_paths()` in parallel.

`graduated_enforcement` calls go through SSL init that can NULL-fault on a broken IAT — the violation post is therefore wrapped in a **noinline + outer-SEH** pattern (`enforcement.hpp::violation_post_impl` + `seh_violation_post`). Every function that mixes `__try`/`__except` with C++ objects (`std::string`, `std::lock_guard`) under `/EHsc` must be split this way to avoid `error C2712: Cannot use __try in functions that require object unwinding`.

Webhook log pattern: `CreateFileA(path, FILE_APPEND_DATA | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, ...)`. **Do not** drop `FILE_APPEND_DATA` or weaken the share mask — multi-thread append corruption was a load-bearing bugfix. Also do not call `FlushFileBuffers()` per write from the render thread (was a UI-freeze multiplier under `webhook::write_log`).

### Protector pipeline (`tools/protector/`)

Phase flag bitmap (`aux_block_t::phase_flags`, `0x7FF` = all 11 phases fired):
`0x001` polymorphic_stub · `0x002` merge_sections · `0x004` flatten_entropy · `0x008` deep_steal · `0x010` ghost_veh · `0x020` rdtsc_entangle · `0x040` opaque_predicates · `0x080` ast_poison · `0x100` symexec_bombs · `0x200` llm_poison · `0x400` jit.

Pipeline order (`transforms.hpp::protect_pe`): capture original exception RVA/size → `pack_sections` → `encrypt_strings` → (skip `encrypt_imports` when `--no-encrypt-imports`) → `randomize_section_names` → `mangle_headers` → `decoy_call_graph` → `ast_poison` → `symexec_bombs` → `llm_poison` → jit-mark → `stub_polymorphic`.

**Two skip lists must be kept in sync:**
1. `transforms.hpp::section_skip_list::is_skipped` — what `pack_sections` leaves alone (`.rsrc`, `.reloc`, `.pdata`, `.xdata`, `.idata`, `.tls`, plus any new protector sections like `.gehi`, `.epheme`, `.dseal`, `.dthunk`, `.licbind`, `.feat`).
2. `verify_api.hpp::probe_p03` — its OWN whitelist; new sections must be added to BOTH.

**LoadConfig preserve list** (`transforms.hpp::add_pointer_target`): every offset modern MSVC fills must be added or the post-pack zero loop nukes the slot and `call qword ptr [slot]` faults with `RIP=0`. Current set: `0x58, 0x70, 0x78, 0xD0, 0xD8, 0xE8, 0xF0, 0xF8, 0x100, 0x108, 0x118, 0x120, 0x128, 0x138`. The LoadConfig RVA + size are also pushed. Even slots that are linker-zero in current builds (XFG when `GuardFlags=0x100` only) must be preserved — turning on `/guard:xfg` in a future build must not silently break.

**`.pdata` / `DataDirectory[3]` (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`) must never be packed or zeroed.** x64 SEH unwinding goes through `RtlLookupFunctionEntry` which reads `RUNTIME_FUNCTION` via `DataDirectory[3]`. Zero either and every `__try`/`__except` in the protected binary dies silently — including `hv_preflight::xsetbv_probe` and any place that catches privileged-instruction faults.

**`collect_loader_string_ranges`** scans `IMAGE_IMPORT_DESCRIPTOR` + `ImgDelayDescr` + `IMAGE_EXPORT_DIRECTORY` DLL/function/forwarder name RVAs and excludes them from `encrypt_strings`. Imports are included only when `--no-encrypt-imports` is set (when imports ARE encrypted, `destroy_imports` already zeros them and `DataDirectory[1]=0` keeps the loader away). Exports are always preserved — needed for any `GetProcAddress` consumer (and specifically for IDA finding `PLUGIN`).

**Idempotency**: `transforms.hpp::detect_already_protected` scans every section's first 4 bytes for `kPackedMagic = 0x41504B44`. Hit → copy input→output verbatim, exit 0. To force a re-protect, do a Clean build.

**LLM poison strings** (`ai_deception.hpp::v2_a00..v2_d15` + honey strings) are consumed by the TARGET binary, not the protector. The protector has its own independent poison set in `tools/protector/llm_poison.hpp`. Do NOT cross-include.

`AiDAProtectorVerify` runs 27+ probes (P01: PE32+; P02: APKD magic in packed section; P03: original sections zeroed; P04: import-dir RVA cleared; P05: entry point inside packed section; P06: AUX block present; P07: debug dir stripped; P08: section names randomized; P09–P14: master key / stub / phase flags / structure validation).

### MCP, AI, agents (standalone)

- **Chat loop** (`core/ai/standalone_chat.cpp`): `tick_ai_chat()` parses `/skill_name` slash commands via `aida::commands::find/execute`, otherwise spawns `run_agentic()` on the work queue. `poll_ai_chat()` drains updates from `s_updates` (THINKING / CHUNK / COMPLETE / ERR) and applies them to the active assistant message.
- **Provider abstraction** (`core/ai/standalone_ai_client.{hpp,cpp}` + `provider_transforms.{hpp,cpp}`): four providers (Anthropic, OpenAI, Gemini, OpenRouter) unified into `ai_generation_result_t`. `transform_request` / `transform_response` / `compute_headers` / `resolve_endpoint` normalize the wire formats. Tool schema builders are per-provider (`build_anthropic_tools`, `build_openai_tools`, `build_gemini_tools`, `build_full_tools`).
- **Provider catalog** (`core/ai/provider_catalog.{hpp,cpp}`): models defined with `model_capabilities_t` (temperature/reasoning/attachment/tool_call/interleaved), `model_cost_t` (per-million in/out, cache, separate >200k tier); populated from a remote JSON manifest with disk caching.
- **Agents** (`core/ai/agent_registry.{hpp,cpp}`): `agent_info_t` holds `system_prompt`, `permission_rule_t[]` (allow/deny/ask + key wildcard + arg pattern), `tools_allowed`/`tools_denied`, optional `model_override`. `tool_allowed(agent, name)` checks the allow/deny lists and rule set.
- **Skills** (`core/ai/skills.hpp`): `SKILL.md` files with YAML frontmatter discovered under `%APPDATA%\AiDA\Standalone\skills`, `.aida/skills`, `.claude/skills`, `.agents/skills`. `manager_t::resolve(name)` parses frontmatter (`---`-delimited, supports block literals) and builds a `command_t` (template_text + placeholder hints).
- **`auto_approval`** (`core/ai/auto_approval.hpp`): five-layer gate — explicit toggles → agent permissions → categorical (read_only / write / execute / mcp / mode_switch / subtask / followup / always_auto) → cost budget (`task_counters_t`, max requests + max USD) → interactive dialog. `.aidaignore` patterns deny the call entirely.
- **Tool repetition** (`core/ai/tool_repetition.hpp`): hashes (tool, args), records into a 20-entry deque. ≥3 consecutive identical → warn; ≥5 → force `ask_followup_question`.
- **MCP duality**:
  - **Local server** (`core/mcp/mcp_standalone.{hpp,cpp}`) — JSON-RPC 2.0 server on localhost. Tools registered by `register_*_tools(server)` per domain (one file per area: `core/tools/coding_tools_standalone.cpp`, `core/tools/driver_tools_standalone.cpp`, `core/tools/workflow_tools_standalone.cpp`, `core/analysis/analysis_tools_standalone.cpp`, `core/debugger/debugger_tools_standalone.cpp`, `core/network/network_tools_standalone.cpp` + `net_security_tools_standalone.cpp`, `core/scanner/scanner_tools_standalone.cpp`, `core/tools/emulation_tools_standalone.cpp`).
  - **External client** (`core/mcp/mcp_client.{hpp,cpp}`) — connects to remote MCP servers (`http_sse` or `stdio` transport), supports OAuth2. `manager_t` aggregates many servers; tools are exposed as `mcp::<name>` to disambiguate from local tools.
  - **Marketplace** (`core/mcp/mcp_marketplace.{hpp,cpp}`).
- **Sandbox** (`core/tools/sandbox.hpp`): shells out to `C:\Windows\System32\WindowsSandbox.exe` with a generated `.wsb` config, captures stdout/stderr via `metadata.json` polling. Used by the `sandbox_execute` tool.
- **Script engine** (`core/tools/script_engine.{hpp,cpp}`): Lua 5.4 + sol2 with `SOL_ALL_SAFETIES_ON`. Always use `sol::protected_function` + `sol::protected_function_result`, and `obj.as<sol::optional<T>>()` for type extraction — the no-exceptions house rule applies inside scripting too. Same-name `load_script` reload triggers a full hook-table rebuild (the inner mutex is non-recursive, so the reload is inlined rather than calling `unload_script`).

### Claude Code OAuth (auth_claude_code)

Production flow: `https://claude.com/cai/oauth/authorize` for account login, `https://platform.claude.com/v1/oauth/token` for token exchange/refresh, `http://localhost:<port>/callback` for PKCE callback. Account scope union: `org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload`. Refresh requests should request the Claude.ai account scopes (`user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload`) so newly-added account capabilities can expand without forcing relogin. Reference: `core/auth/auth_claude_code.cpp`.

## Conventions

Condensed from `.github/agents/*.agent.md` (`.github/copilot-instructions.md` is empty; the agent specs are the source of truth):

- **No exceptions.** Return `bool` / enums. Diagnostics go through a static `s_last_error` string with a `last_error()` getter. Pattern repeats in every `.cpp`.
- **No raw `new`/`delete`**, no C-style casts, no `std::endl`.
- **No comments anywhere** — `strip_comments.py` is destructive and will rewrite anything you add. The only comment-shaped exception is CMake `COMMENT "..."` directives (those are strings, not code comments).
- **No TODOs / placeholders / stubs.** Every landed change must be production-ready.
- **snake_case** for variables, functions, files, namespaces. Types end in `_t`.
- **`#pragma once`** in every header.
- **Never block the render thread.** Network, file I/O, and CPU-heavy work go on `std::thread` with result queues guarded by `std::mutex`, or atomic flags for stop/stop-request. The 12-thread `work_queue` (`core/infra/work_queue.hpp`) is the canonical dispatcher.
- **Globals live in anonymous/static namespaces inside `helpers/globals.h`** — not singletons, not god-objects.
- **Match file indentation** (tabs vs spaces vary between `src/` and `src/standalone/src/`).
- **Compile-flag → MASM leakage**: any `target_compile_options(... PRIVATE/PUBLIC /wdNNNN)` MUST be wrapped in `$<$<COMPILE_LANGUAGE:C,CXX>:...>` or ML.exe receives it for `.asm` sources and emits `MASM : warning A4018: invalid command-line option`. Zycore (from Zydis) adds `/wd4201` PUBLIC; the top-of-tree `CMakeLists.txt` has the fix-up.
- **Win32 dialog idiom**: `OPENFILENAMEW`/`SAVEFILENAMEW` calls always set `sfn.hwndOwner = g_hwnd;` (declared `extern HWND g_hwnd;` in `helpers/helpers.h`). Save: `OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST`. Open: `OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR`. `NOMINMAX` is project-wide so `std::min`/`std::max` survive `<Windows.h>`.
- **Jump-to-disasm idiom** (every view's "go to address" path):
  ```
  globals::ui::active_center_view = center_view_t::disassembly;
  disasm_view::goto_address(addr, g_disasm);
  ```
  `g_disasm` must be declared `extern DisasmState g_disasm;` at **file scope** outside any namespace — `DisasmState` is global, and putting the `extern` inside a namespace creates a different symbol that fails to link.
- **Jump-to-hex idiom**: `hex_view::read_from_process(addr, size); globals::ui::active_center_view = center_view_t::hex_view;`. `read_from_process` already calls `driver_bridge::read_memory` + `set_data` and clamps `size` ≤ 1 MiB internally.
- **`render_row_entrance(i, accumulated_time, 0.012f)`** (`core/ui/ui_anim.hpp`): `accumulated_time` is a static float incremented by `ImGui::GetIO().DeltaTime` once per frame at the top of the render scope. Don't pass alpha as `stagger_delay` — that goes negative for `i ≥ 1` and bricks the entrance animation.
- **`zydis_detail` namespace lives in `disasm/zydis_disasm.hpp`** — `decoder()`, `formatter()`, `ensure_init()` are static-storage singletons. Any TU calling them must `#include "zydis_disasm.hpp"`; not auto-pulled by `<Zydis/Zydis.h>`.
- **Winsock RAII**: `static wsa_guard_t s_wsa_guard;` at namespace scope inside the `.cpp` is the standard pattern; replaces ad-hoc `WSAStartup` chains that leak the per-process refcount. Reference: `network/mitm_proxy.cpp`.

## Build-changes gotchas

- Editing any `src/standalone/src/core/anti-tamper/*.hpp` triggers a near-full rebuild — `orchestrator.hpp` pulls the whole graph. sccache catches most of the recompile cost on the second build; expect the protector POST_BUILD to dominate once the link finishes.
- Editing the root `.c` hex dumps (`WhosWho.c`, `Sentinel.c`, `WindMapper.c`) does not by itself rebuild anything except via timestamp; the `encrypt_drivers` target picks up the change and `OBJECT_DEPENDS` on `driver_loader.cpp` re-links. If a driver change isn't reflecting, `touch` the `.c` file or rerun the encrypt script.
- `strip_comments.py` at the repo root is destructive and rewrites all C/C++/CMake comments under `driver/`. It is not part of the normal build — do not run it as a "cleanup" pass.
- The protector POST_BUILD step runs every successful build. If you're diffing a binary or attaching a debugger, expect the output to be post-protection. To get raw compiler output for one-off debugging, configure with `-DBUILD_PROTECTOR=OFF` directly on the cmake command line — there's no preset that does this, on purpose, because unprotected behavior diverges enough at runtime (no .epheme/.dthunk rotation, no IAT stub, no anti-dump re-encrypt) that a "works in unprotected mode" result tells you nothing about the shipping binary.
- `ida-sdk/` is gitignored; the `AiDA` target refuses to configure without it (`-DIDASDK_DIR=...` or drop the SDK at `ida-sdk/src`).
- New protector sections must be added to **both** `transforms.hpp::section_skip_list::is_skipped` AND `verify_api.hpp::probe_p03`.
- New LoadConfig fields filled by future MSVC versions (e.g., when `/guard:xfg` is enabled) must be added to `add_pointer_target(...)` in `transforms.hpp` or the post-pack zero loop nukes them.
- AiDA.dll must compile with `ATP_JIT_DISABLED` defined (already wired in `CMakeLists.txt`). Removing this guard introduces `PAGE_EXECUTE_READ` allocations that violate ACG inside `ida64.exe`.
- Sibling-block `static T x;` declarations in two branches of the same function create **two** storage locations even with the same name — hoist `static` declarations to the function's outermost scope, then assign in any branch.
- `temp_arch_t::arch` is a `std::unique_ptr` (`disasm/ghidra_decompiler.hpp`); `do_decompile(aida_architecture_t* arch, ...)` takes a raw pointer — call sites must pass `ta.arch.get()`.

## Crash debugging

- **Diag log location**: `aida_debug.log` in the executable's directory. Append-only, atomic via `FILE_APPEND_DATA + FILE_SHARE_READ|FILE_SHARE_WRITE` (`helpers/diag_log.hpp`). Multiple threads + processes can write simultaneously without corruption — but only if every writer uses the same access/share masks. Mismatched masks (e.g., `GENERIC_WRITE + FILE_SHARE_READ` only) produce `ERROR_SHARING_VIOLATION` and silently drop entries.
- **Symbolicate a protected EXE**: `cdb -z <protected.exe> -y <pdb_dir> -c '.reload /f; ln <addr>; q'`. Works on the file (not a process) — loads the PDB and prints the nearest symbol pair. `uf` does NOT work on protected binaries because the section data on disk is zeroed/encrypted; use the symbol pair to navigate to the source-level function.
- **`__guard_*_icall_fptr` reads as `0` on disk** in protected EXEs — that's the post-pack zero loop, not runtime corruption. Runtime values are restored by `payload.c::unpack_sections` + `rebuild_iat`. If a slot stays NULL at runtime, it's a `tls_preserve_ranges` miss in `transforms.hpp::add_pointer_target`.
- **`SO_RCVTIMEO`/`SO_SNDTIMEO` do NOT bound `connect()` on Windows.** Use `ioctlsocket(FIONBIO, 1)` immediately after `socket()`, expect `connect()` to return `WSAEWOULDBLOCK`, then `WSAPoll(POLLOUT, remaining_ms)` and `getsockopt(SO_ERROR)`. SSL handshake follows the same pattern with `SSL_get_error` → `WANT_READ`/`WANT_WRITE` → `WSAPoll`. Reference: `core/runtime/standalone_license.cpp::raw_https_request`.
- **Windows `dnscache` caches NXDOMAIN for the SOA negative-TTL** (15+ min). For license endpoints, resolve via `getaddrinfo(AF_UNSPEC)` and on failure fall back to `DnsQuery_A(host, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE)`. Try every returned address, not just the first. Reference: `standalone_license.cpp::resolve_host_addrs`.
- **TLS 1.3 cipher-suite hash selection at the keylog layer**: `TLS_AES_128_GCM_SHA256` uses 32-byte secrets + SHA-256, `TLS_AES_256_GCM_SHA384` uses 48-byte secrets + SHA-384. Branch on `secret.size() == 48 || key_size == 32` to pick `EVP_sha384()`. Reference: `network/ssl_keylog.hpp`.
- **`__fastfail` codes** in this codebase: `0xBEA7DEADu` (driver heartbeat dead — `driver_bridge::initialize` or watchdog), `0xA1DA1DA1u` (AiDA.dll plugin watchdog: `AiDAStandalone.exe` missing), `0xA1DAFA17u` (ARC startup gate failed).

## Operational rules — do not touch without explicit instruction

- **License validation**: `src/license.cpp`, `src/license.hpp`, `core/runtime/standalone_license.{hpp,cpp}`, the embedded Ed25519 public keys, the gate macros, the Firebase / Node endpoints.
- **Anti-tamper enforcement**: corruption rounds in `enforcement.hpp`, watchdog `__fastfail` codes, the `license_pending_activation` default.
- **Driver heartbeat diagnostics**: the `last_heartbeat_*` getters on `voyager::device_t` (`driver/comm.h`).
- **AiDA.dll filename gate** (`has_expected_plugin_filename`) and the lone `PLUGIN` export.
- **Encrypted-driver headers**: `src/whoswho_encrypted.h`, `src/sentinel_encrypted.h`, `src/windmapper_embedded.h`, `src/windmapper_data.inc`. Regenerated; never hand-edit.
- **`.c` hex dumps at repo root**: regenerated from HxD exports of `.sys`; never hand-edit.
- **Section skip lists / LoadConfig preserve list / `.pdata` handling** in `transforms.hpp` and `verify_api.hpp` (load-bearing for SEH / CFG / XFG / IAT recovery).
- **Distribution channel**: `AiDAStandalone.exe` ships via Discord only. The license server may host encrypted ARC blobs (`/api/download/arc`, `/api/arc/page*`); do not add a public download route for the EXE.
- **SentinelBridge** between WhosWho and Sentinel — heartbeat protocol, magic, HMAC tag, counter are all load-bearing.
