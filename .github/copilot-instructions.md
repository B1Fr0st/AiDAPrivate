# AiDA — Global Copilot Instructions

## Project Identity

AiDA is a **standalone reverse-engineering IDE** with integrated AI assistance, kernel driver communication, MCP protocol support, and cloud-based licensing. The primary build target is `AiDAStandalone` — a single Windows x64 executable.

## Tech Stack

| Layer | Technology |
|---|---|
| Language | C++17 (MSVC `/std:c++17`, `/MD`, x64) |
| UI | Dear ImGui 1.91.8-docking on DirectX 11 |
| Font rendering | FreeType via imgui_freetype |
| Window effects | Windows 11 Acrylic blur (DwmSetWindowAttribute) |
| HTTP | cpp-httplib (header-only, OpenSSL-backed) |
| JSON | nlohmann/json (header-only) |
| Disassembly | Zydis v4.1.0 |
| Emulation | Unicorn Engine 2.1.1 |
| Crypto | OpenSSL (static), Windows DPAPI |
| Build system | CMake 3.21+ → MSVC .vcxproj |
| AI providers | Anthropic, OpenAI, Gemini, OpenRouter, Local (all SSE streaming) |
| Protocol | MCP (Model Context Protocol) — JSON-RPC 2.0, HTTP-SSE + stdio |
| Driver | Custom kernel driver via IOCTL (comm.h / comm.cpp) |
| Terminal | Windows ConPTY (terminal_view.hpp) |
| Config | `%APPDATA%\AiDA\Standalone\settings.json`, DPAPI encryption |
| License | Cloud functions (europe-west1), HWID (FNV-1a), heartbeat, session tokens |

## Source Layout

```
src/standalone/src/
├── main.cpp                    # Entry point, D3D11 init, render loop
├── verdana.h                   # Embedded font data
├── core/
│   ├── standalone_chat.hpp/cpp       # Chat orchestration, MCP integration
│   ├── standalone_ai_client.hpp/cpp  # Multi-provider AI client, streaming
│   ├── standalone_license.hpp/cpp    # License validation, code integrity
│   ├── standalone_settings.hpp       # Config persistence, DPAPI encryption
│   ├── standalone_compat.hpp         # IDA API compatibility shims
│   ├── standalone_driver.hpp/cpp     # Kernel driver bridge
│   ├── standalone_tools_fwd.hpp      # Tool namespace forward declarations
│   ├── mcp_client.hpp/cpp            # MCP client (connects to external servers)
│   ├── mcp_standalone.hpp/cpp        # MCP server (exposes AiDA tools)
│   ├── mcp_standalone_tools.cpp      # Tool registration
│   ├── chat_render.hpp/cpp           # Markdown rendering for chat
│   ├── code_editor.hpp/cpp           # Text editor with syntax highlighting
│   ├── disasm_view.hpp/cpp           # Disassembly viewer
│   ├── hex_view.hpp/cpp              # Hex dump viewer
│   ├── syntax_highlight.hpp          # Language tokenizers
│   ├── zydis_disasm.hpp              # Zydis wrapper
│   ├── sandbox.hpp                   # Tool execution sandbox
│   ├── terminal_view.hpp             # ConPTY terminal emulator
│   ├── workspace_search.hpp          # File/text search
│   ├── *_tools_standalone.cpp        # Tool implementations per category
│   └── ...
├── helpers/
│   ├── helpers.h / helpers.cpp       # UI rendering, tab management
│   ├── globals.h                     # Global state, enums, namespaces
│   ├── blur.h / blur.cpp             # DX11 Gaussian blur
│   ├── file_browser.cpp              # File system browser
│   ├── embedded_assets.cpp           # Linked binary assets
│   └── ...
└── assets/
    └── theme_icons/                  # Theme icon sets
```

## Code Style & Conventions

### Naming
- **snake_case** for everything: variables, functions, methods, namespaces, file names
- **UPPER_SNAKE_CASE** for macros and compile-time constants
- Type suffixes: `_t` for structs/classes (`call_result_t`, `server_config_t`, `process_info_t`)
- Enum value suffixes match context: `center_view_code_editor`, `bottom_tab_output`
- Namespace grouping: `standalone_license::`, `driver_bridge::`, `output_log::`, `conversations::`
- Header guards: not used — all headers use `#pragma once`

### Structure
- **Header-only** for small utilities and self-contained components (settings, terminal, search, syntax highlighting, compat layer)
- **hpp/cpp split** for substantial components (chat, AI client, MCP, driver, license, editor, viewers)
- Static class pattern for UI helpers: `struct helpers { static void render_tab(...); };`
- Namespace pattern for tool implementations: `namespace driver_tools { void register_tools(server_t&); }`

### Patterns
- **RAII** for Windows handles and GPU resources
- **std::mutex** + `std::lock_guard` for thread safety
- **std::thread** with atomic stop flags for background work
- **Callback queuing**: async results pushed to a queue, polled on main thread
- **ImGui immediate mode**: all UI through ImGui calls in render loop
- Streaming AI: SSE line-by-line chunk parsing with `on_chunk` callbacks
- Global state in namespaces inside `globals.h` — not classes, not singletons

### Error Handling
- Return-code based (bool, enum), not exceptions
- `last_error()` pattern for detailed error messages
- Log to `output_log::add()` for user-visible output tabs
- `OutputDebugStringA()` for developer debugging

### ImGui Conventions
- Colors as `ImU32` (via `IM_COL32(r,g,b,a)`)
- Accent colors extracted from theme: `float ax, ay, az` → `ImVec4(ax, ay, az, alpha)`
- Custom rendering via `ImDrawList*` (GetWindowDrawList, GetForegroundDrawList)
- Layout: `ImGui::SetCursorPos`, `ImGui::SameLine`, `ImGui::BeginChild`/`EndChild`
- Unique IDs: `ImGui::PushID(index)` / `PopID()`, or `"label##unique"`

## Build & Test

### Build
```powershell
# CMake configure (one-time)
cmake -S . -B build -G "Visual Studio 17 2022" -A x64

# Build via MSBuild (preferred — matches VS Code tasks)
& "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" `
    "build\AiDAStandalone.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:minimal /m

# Or use the VS Code task: "Build AiDAStandalone 2"
```

### Key compile definitions
```
_CRT_SECURE_NO_WARNINGS
NOMINMAX
WIN32_LEAN_AND_MEAN
CPPHTTPLIB_OPENSSL_SUPPORT
AIDA_STANDALONE
```

### Link libraries
```
d3d11 dxgi d3dcompiler dwmapi
OpenSSL::SSL OpenSSL::Crypto
ws2_32 dnsapi winhttp iphlpapi ntdll crypt32
Zydis unicorn
freetype
```

## Absolute Rules

1. **NEVER add anti-debug, anti-dynamic-analysis, or anti-RE features** — the binary has an external protector applied post-build
2. **NEVER remove or weaken license validation code** — it is critical and intentionally hardened with obfuscated XOR chains
3. **NEVER use exceptions** — the entire codebase is `/EHsc` but exception-free by convention
4. **NEVER use `new`/`delete` directly** — use `std::unique_ptr`, `std::shared_ptr`, or stack allocation
5. **NEVER use C-style casts** — use `static_cast`, `reinterpret_cast`, `const_cast`
6. **NEVER introduce global constructors** that do heavy work — init functions are called explicitly from `main()`
7. **NEVER use `std::endl`** — use `"\n"` (no unnecessary flushes)
8. **NEVER block the main/render thread** — heavy work goes on `std::thread` with result queuing
9. **NEVER hardcode paths** — use `%APPDATA%`, relative paths, or settings
10. **NEVER commit API keys, license keys, or secrets** — they live in encrypted settings or environment variables
11. **Keep `/MD` runtime** — the entire dependency chain is built against the dynamic CRT
12. **Preserve existing file structure** — do not reorganize, rename, or move files without explicit request
13. **All new headers use `#pragma once`** — no include guards
14. **All new files use snake_case** naming
15. **Match existing indentation** — tabs in some files, spaces in others; match the file you're editing

## AI Provider Integration Patterns

When adding or modifying AI provider code:
- Each provider has its own `generate_<provider>()` function in `standalone_ai_client.cpp`
- Streaming uses SSE: read lines, parse `data: {...}` JSON, extract delta content
- All HTTP calls happen on worker threads, results queued back to main thread
- Provider config (keys, endpoints, models) stored in `standalone_settings.hpp`
- Support temperature, system prompts, tool definitions, stop sequences

## MCP Protocol Patterns

When working with MCP:
- JSON-RPC 2.0 request/response format
- Tools have `name`, `description`, `inputSchema` (JSON Schema)
- Client: `mcp_client.hpp` — connects to external MCP servers
- Server: `mcp_standalone.hpp` — exposes AiDA capabilities as MCP tools
- Tool results: `tool_result_t` with `content` array (text or image)
- Server config: `server_config_t` with `type` (http-sse or stdio), `url`, `command`, `args`, `env`

## Driver Integration Patterns

When working with the kernel driver:
- Communication via `comm.h` / `comm.cpp` using Windows IOCTLs
- `device_t` class wraps driver handle
- Operations: process enum, module enum, memory read, thread enum
- All driver calls can fail — always check return values
- Driver must be loaded before use: `driver_bridge::load_kernel_driver()`
