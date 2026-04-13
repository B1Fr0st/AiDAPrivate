# Perception.cx — Complete Technical Analysis

> Full docs scraped from https://docs.perception.cx/ on 2026-04-13

---

## 1. Architecture Overview

Perception.cx is a **game-hacking overlay IDE** with:
- Native overlay panel (no Electron/browser)
- Integrated code editor with multi-tab, syntax highlighting (17 languages), IntelliSense
- AI chat (OpenAI-compatible, GitHub Models, Copilot OAuth)
- Integrated terminal (cmd.exe, up to 8 tabs)
- **Perception Analyzer** — IDA-style binary analysis
- **Dual scripting** — AngelScript + Lua (both with identical API surfaces)
- Extensions API for editor customization

---

## 2. Perception Analyzer (The "Engine")

### Confirmed: They ARE using Zydis
The docs explicitly reference Zydis throughout:
- `zydis_disasm()` — global function for disassembly
- `zydis_encode()` — global function for encoding  
- `ZydisEncoderRequest` / `ZydisBuilder` types
- `zydis_mnemonic_from_string()` / `zydis_register_from_string()`
- `zydis_decoded_to_request()` — decode → re-encode round-trip

### Analyzer Features
- **IDA-style disassembly view** with address/bytes/mnemonic/operands/comment columns
- **F5 Decompiler** — "Generates Pseudo C" (under development, described as "Advanced Decompiler")
- **Reconstruct Source** — experimental feature that generates full project structure from binary:
  - Header files (types, structs, enums, globals, imports, vtables, string constants)
  - Source files (decompiled functions grouped into named modules: `module_render`, `module_network`, etc.)
  - Common helpers extracted into `common.cpp`
  - Hostile/unresolved functions emit `__asm {}` blocks with raw disassembly
  - Cross-references and module assignments exported as JSON
- **Hex view** — traditional hex editor
- **Types/Structure Editor** — ReClass-style, with C struct import and export to C++/AngelScript/Lua
- **Memory Scanner** — first scan + next scan with changed/unchanged/increased/decreased refinement
- **Inspector Panel** — xrefs to/from, callers, callees, byte dump

### Analyzer Process Attachment
- Process selection screen with filter
- Module loading modes: Disabled, Primary, Selected, All
- Header-only loading for non-analyzed modules (exports + sections visible, on-demand decode)
- Module switching via toolbar dropdown

### Navigation
- Click branch targets, Ctrl+G (supports `base+0x1000` expressions)
- Alt+Left/Right, M4/M5 for back/forward
- Search: Hex mode with wildcards (`48 8B ?? 4C 89`) + String mode
- `N` to rename symbols, `;` to add comments (persisted across sessions)

### Sidebar
- Functions (with xref counts), Imports (grouped by DLL), Exports, Strings, Sections (with entropy)

---

## 3. AngelScript API

### Overview
AngelScript with standard add-ons: string, array, dictionary, math, any, grid, script helper

### Lifecycle
```cpp
int main()           // Entry point. Return > 0 = persistent, <= 0 = unload
void on_unload()     // Cleanup hook
```
- Persistent scripts use `register_callback(fn, every_ms, data_index)` for recurring work
- Each callback runs on its own thread with independent draw list and input

### Engine API
```cpp
int register_callback(fn, every_ms, data_index, render_on_top = false)
void unregister_callback(id)
void log(message)
void log_error(message)
void log_console(message)
void log_console_error(message)
string get_username()
```

### Atomic Types
- `atomic_int32` and `atomic_int64` — lock-free thread-safe integers
- Methods: `store`, `load`, `exchange`, `compare_exchange`, `add`, `sub`, `increment`, `decrement`, `and_op`, `or_op`, `xor_op`

### Unicorn Emulation API
Two modes:
- **Local** (`uc_create()`) — fully sandboxed
- **Process-backed** (`uc_create_process(proc, allow_writes)`) — pages from target process

Functions:
```cpp
uint64 uc_create()
uint64 uc_create_process(proc_t proc, bool allow_writes = true)
void uc_close(uint64 handle)
bool uc_mem_map(handle, addr, size, perms)
bool uc_mem_write(handle, addr, data)
bool uc_mem_read(handle, addr, size, out data)
bool uc_reg_write64(handle, reg, value)
uint64 uc_reg_read64(handle, reg)
bool uc_reg_write128/256(handle, reg, data)  // XMM/YMM
bool uc_reg_read128/256(handle, reg, out data)
bool uc_setup_stack(handle, stack_base, stack_size, stop_addr)
int uc_start(handle, begin, end, timeout = 0, count = 0)
bool uc_flush_code(handle)  // TB cache flush after code mutation
bool uc_hook_add(handle, type, cb)
void uc_emu_stop(handle)
int uc_get_last_exception(handle)
uint64 uc_get_exception_address(handle)
```

Constants: UC_PROT_READ/WRITE/EXEC/ALL, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, all x86_64 registers

### Proc API (Process Memory)
```cpp
proc_t ref_process(uint pid | string name)
void proc_t::deref()
uint64 proc_t::base_address()
uint64 proc_t::peb()
uint proc_t::pid()
bool proc_t::alive()
bool proc_t::is_valid_address(addr)

// Scalar reads
uint8/16/32/64 proc_t::ru8/ru16/ru32/ru64(addr)
int8/16/32/64  proc_t::r8/r16/r32/r64(addr)
float/double   proc_t::rf32/rf64(addr)

// Scalar writes  
bool proc_t::wu8/wu16/wu32/wu64(addr, val)
bool proc_t::w8/w16/w32/w64(addr, val)
bool proc_t::wf32/wf64(addr, val)

// Strings
string proc_t::rs(addr, max_chars)   // ANSI/UTF-8
string proc_t::rws(addr, max_chars)  // UTF-16 → UTF-8
bool proc_t::ws(addr, text)
bool proc_t::wws(addr, text)

// Raw memory
void proc_t::rvm(addr, size, out buf)
bool proc_t::wvm(addr, in buf)

// SIMD (16/32/64 bytes)
void proc_t::r128/r256/r512(addr, out)
bool proc_t::w128/w256/w512(addr, in)

// TEBs
array<uint64>@ proc_t::get_all_tebs()

// Modules & patterns
bool proc_t::get_module(name, out base, out size)
uint64 proc_t::find_code_pattern(start, size, signature)
void proc_t::find_all_code_patterns(start, size, signature, out result)

// Struct reading
bool proc_t::read_struct(addr, out result, descriptor)
bool proc_t::read_struct_array(base, count, size, out result, descriptor)

// Virtual memory
uint64 proc_t::alloc_vm(size)   // RWX allocation in target
bool proc_t::free_vm(address)
uint64 proc_t::get_proc_address(module_base, export_name)
uint64 proc_t::get_import_rdata_address(module_base, import_name)
array<uint64>@ proc_t::read_pointer_array(base, count, offset_delta)

// Memory analysis
bool proc_t::virtual_query(addr, out start, out size, out protection, out heap_likely)
array<dictionary@>@ proc_t::get_vad_snapshot(heap_likely_only = false)

// Memory scanning
array<uint64>@ proc_t::scan_u32(value, heap_only = false)
array<uint64>@ proc_t::scan_u64(value, heap_only = false)
array<uint64>@ proc_t::scan_float(value, heap_only = false)
array<uint64>@ proc_t::scan_double(value, heap_only = false)
array<uint64>@ proc_t::scan_string(text, heap_only = false)
array<uint64>@ proc_t::scan_wstring(text, heap_only = false)
array<uint64>@ proc_t::scan_pointer(target, heap_only = false)
```

### System API (CPU & Disassembly)
```cpp
string cpu_vendor()
string cpu_brand()
int64 perf_frequency()
int64 perf_time()
uint64 rdtsc()

// Zydis disassembly
void zydis_disasm(bytes, rip, out instructions)
// Returns array of dictionaries with: runtime_address, length, mnemonic, text, operand_count, operands[]
// Each operand has: id, visibility, type (reg/mem/imm/ptr), size, and type-specific fields

// Date/time
dictionary@ get_datetime()  // year, month, day, hour, minute, second, msec, day_name, month_name, hour12, ampm
uint64 get_timestamp()       // Unix UTC seconds

// Thread priority
bool set_thread_to_highest_priority()
bool set_thread_to_lowest_priority()
bool set_thread_to_normal_priority()
```

### Zydis Encoder API
```cpp
// Types
ZydisEncoderRequest  // value type - describes one instruction
ZydisBuilder         // reference type - collects instructions + raw bytes

// ZydisEncoderRequest methods
void set_mnemonic(int mnemonic)
void set_machine_mode(int mode)
void set_operand_count(int count)
void set_operand_reg(int index, int reg)
void set_operand_imm(int index, int64 imm)
void set_operand_mem(int index, int base, int idx, int scale, int64 disp, int size)
void set_operand_ptr(int index, uint16 segment, uint32 offset)
void set_branch_type(int type)
void set_branch_width(int width)

// ZydisBuilder methods
void set_machine_mode(int mode)
void set_base_address(uint64 addr)
void push(ZydisEncoderRequest req)
void push_bytes(array<uint8> bytes)
void push_byte/push_u16/push_u32/push_u64(value)
void push_nop(int count = 1)
void push_int3()
void push_ret()
bool build(out bytes)

// Global functions
bool zydis_encode(req, out bytes)
bool zydis_encode_absolute(req, runtime_address, out bytes)
bool zydis_nop_fill(out bytes, length)
bool zydis_decoded_to_request(bytes, runtime_rip, out req)
int zydis_mnemonic_from_string(name)
string zydis_mnemonic_to_string(mnemonic)
int zydis_register_from_string(name)
string zydis_register_to_string(reg)
```

### Intrinsics API
```cpp
// Bit rotation
uint8/16/32/64 rol8/16/32/64(value, count)
uint8/16/32/64 ror8/16/32/64(value, count)

// Byte swap
uint16/32/64 bswap16/32/64(value)

// Bit manipulation
int popcnt32/64(value)
int lzcnt32/64(value)
int tzcnt32/64(value)

// SSE operations (all use array<uint8> length=16)
mm_xor_si128, mm_or_si128, mm_and_si128, mm_andnot_si128
mm_slli_epi16/32/64, mm_srli_epi16/32/64, mm_slli_si128, mm_srli_si128
mm_shuffle_epi8/epi32, mm_shufflehi_epi16, mm_shufflelo_epi16
mm_unpackhi/lo_epi8/16/32/64
mm_add/sub_epi8/16/32/64, mm_mullo_epi16/32
mm_set_epi64x, mm_set_epi32, mm_set1_epi64x/32/16/8, mm_setzero_si128
mm_extract_epi64/32/16/8
mm_cmpeq_epi8/16/32
broadcast_qword, broadcast_dword
```

### Additional AngelScript APIs (not fully scraped but documented)
- **Render API** — draw shapes, text, images, gradients, GPU-accelerated
- **Input API** — mouse, keyboard, scroll
- **Mutex API** — thread-safety primitives
- **GUI API** — UI element creation (subtab_t, panel_t, checkbox_t, slider_double_t, button_t)
- **Net API** — HTTP/HTTPS/WebSocket
- **File System** — read/write/manage files
- **Extended Math API** — vectors (vector2/vector3), matrices (matrix4x4), quaternions
- **Json API** — json_parse/json_stringify
- **Utilities** — encoding/decoding
- **Sound API**
- **CS2 Extended API** — Counter-Strike 2 specific
- **Bit Reinterpret Helpers** — raw bit pattern conversion

---

## 4. Lua Script API

### Overview
Standard Lua libraries: base, package, coroutine, table, string, math, utf8

### Lifecycle (DIFFERENT from AngelScript)
```lua
function main()       -- Entry point. Return > 0 + on_frame exists = persistent
function on_frame()   -- Called every frame for persistent scripts
function on_unload()  -- Cleanup hook
```
Key difference: Lua uses `on_frame()` per-frame callback instead of AngelScript's `register_callback()` with custom intervals.

### Engine API
```lua
log(message)
log_error(message)
log_console(message)
log_console_error(message)
get_user_name()
```

### Proc API (identical API surface to AngelScript but Lua idiom)
```lua
local proc = ref_process("notepad.exe")   -- returns userdata or nil
deref_process(proc)                        -- release handle

proc:base_address()  --> uint64
proc:peb()           --> uint64
proc:pid()           --> uint
proc:alive()         --> bool
proc:is_valid_address(addr) --> bool

-- Scalar reads/writes (identical to AngelScript)
proc:ru8/16/32/64(addr), proc:r8/16/32/64(addr), proc:rf32/rf64(addr)
proc:wu8/16/32/64(addr, val), proc:w8/16/32/64(addr, val), proc:wf32/wf64(addr, val)

-- Strings
proc:rs(addr, max_chars), proc:rws(addr, max_chars)
proc:ws(addr, text), proc:wws(addr, text)

-- Raw memory (returns Lua tables)
proc:rvm(addr, size) --> {byte1, byte2, ...}
proc:wvm(addr, byte_table) --> bool

-- SIMD
proc:r128/r256/r512(addr) --> table
proc:w128/w256/w512(addr, table) --> bool

-- Modules & patterns
local base, size = proc:get_module(name)
proc:find_code_pattern(start, size, signature) --> addr

-- Struct reading (Lua table descriptors)
proc:read_struct(addr, descriptor) --> table
proc:read_struct_array(base, count, struct_size, descriptor) --> table

-- TEB/VAD/scanning (same as AngelScript)
proc:get_all_tebs()
proc:alloc_vm(size), proc:free_vm(addr)
proc:get_proc_address(module_base, name)
proc:get_import_rdata_address(module_base, name)
proc:virtual_query(addr)
proc:get_vad_snapshot(heap_only)
proc:scan_u32/u64/float/double/string/wstring/pointer(value, heap_only)
```

### System API (CPU & Disassembly)
```lua
cpu_vendor() --> string
cpu_brand() --> string
perf_frequency() --> int64
perf_time() --> int64
rdtsc() --> uint64

-- Zydis disassembly
local instructions = zydis_disasm(byte_table, rip)
-- Returns array of tables with: runtime_address, length, mnemonic, text, operand_count, operands[]
-- Operand structure: id, visibility, type, size, reg={name}, mem={segment,base,index,scale,has_displacement,displacement}, imm={is_signed,is_relative,value,absolute_address}, ptr={segment,offset}

get_datetime() --> table
get_timestamp() --> uint64
```

### Engine-Specific Helpers
```lua
-- Unreal Engine
unreal_engine.read_tarray(proc, addr, max_count?) --> table of pointers
unreal_engine.read_minimal_view_info(proc, addr) --> {location, rotation, fov}
unreal_engine.read_minimal_view_info_f64(proc, addr) --> same but double precision
unreal_engine.world_to_screen(world_pos, view_info) --> {x, y, visible} or nil

-- Generic W2S
world_to_screen_rowmajor(world_pos, view_matrix, viewport?) --> {x, y, visible} or nil
world_to_screen_transposed(world_pos, view_matrix, viewport?) --> {x, y, visible} or nil

-- Game-specific
fortnite_get_player_name(proc, addr) --> string
rust_get_transform_position(proc, addr) --> x, y, z
```

---

## 5. Extensions API (AngelScript only)

Extensions are `.as` files in `<scripting_main_path>/extensions/` that hook into the IDE:

### Available APIs in Extensions
Logging, rendering, input, CPU intrinsics, WinAPI, JSON, Zydis encoding, file I/O, clipboard, HTTP

### NOT available in Extensions
proc_t/ref_process, mutexes, GUI API, Unicorn, extended math, engine-specific API, atomics, register_callback

### Lifecycle Hooks
```cpp
void on_activate()
void on_deactivate()
void on_tick()  // every frame
```

### Editor Event Hooks
```cpp
void on_file_opened(path)
void on_file_saved(path)
void on_buffer_changed(path, line)
void on_tab_changed(path)
```

### AI Pipeline Hooks
```cpp
bool on_ai_before_send(prompt, system_prompt)    // return false to cancel
void on_ai_after_response(response)
string on_ai_tool_call(name, args)               // handle YOUR registered tools
void on_ai_after_tool(name, args, result)         // observe ALL tool calls
string on_ai_system_inject()                      // inject into system prompt
```

### IntelliSense Hooks
```cpp
void on_completion(file, line_text, col, out labels, out inserts, out details)
void on_hover(file, word, line, out tooltip)
```

### Editor API
```cpp
string get_active_file()
string get_active_file_content()
string get_active_language()
int get_cursor_line/col()
void set_cursor_pos(line, col)
string get_selection_text()
void insert_text(text)
void replace_selection(text)
void set_selection(start_line, start_col, end_line, end_col)
bool open_file(path)
bool save_active_file()
void goto_line(line)
string get_root_path()
void get_open_files(out files)
int get_tab_count()
string get_tab_file(index)
int get_active_tab()
void show_notification(msg)
void set_status(msg)
void send_chat_message(msg)
void override_prompt(new_prompt)  // only in on_ai_before_send
```

### File I/O, Clipboard, Network
```cpp
string read_file(path)
bool write_file(path, content)
bool file_exists(path)
void list_directory(path, out entries)
string get_clipboard()
void set_clipboard(text)
string http_get(url, headers="")
string http_post(url, body, headers="")
int http_get_status(url, headers="")
```

### Settings API (persisted per-extension as JSON)
```cpp
string setting_get/set(key[, value])
bool setting_get_bool/set_bool(key[, value])
double setting_get_number/set_number(key[, value])
```

### Widget API (for on_settings_render)
```cpp
create_label(text), create_label_colored(text, r, g, b)
create_separator(), create_spacing(px)
bool create_checkbox(label, key)
bool create_button(label)
double create_slider(label, key, min, max, step=0)
string create_input_text(label, key)
string create_text_area(label, key, visible_lines=4)
create_progress_bar(label, value, max)
int create_dropdown(label, key, options)
int create_color_picker(label, key)
int create_keybind(label, key)
```

### Tool Registration
```cpp
void register_tool(name, desc, params_json="")
void register_tool_param(tool, param, type, desc, required=true)
void unregister_tool(name)
```

---

## 6. Key Takeaways for AiDA

### What Perception Does That AiDA Already Has
- ✅ Zydis disassembly (you have zydis_disasm.hpp)
- ✅ Unicorn emulation (emulation_engine.hpp/cpp)
- ✅ Process memory read/write via kernel driver (standalone_driver.hpp)
- ✅ AI chat with multiple providers (standalone_ai_client.hpp)
- ✅ Code editor with syntax highlighting (code_editor.hpp)
- ✅ Hex view (hex_view.hpp)
- ✅ Memory scanner (memory_scanner.hpp)
- ✅ Structure editor/ReClass (struct_recon_view.hpp)
- ✅ Pattern scanning (already in driver tools)
- ✅ MCP protocol support (mcp_standalone.hpp)
- ✅ Terminal (terminal_view.hpp)
- ✅ Lua scripting engine (script_engine.hpp)
- ✅ Decompiler (decompiler_engine.hpp via Ghidra)

### What Perception Has That AiDA Could Add/Improve
1. **AngelScript as additional scripting language** — typed, compiled, thread-safe, ideal for RE
2. **Zydis Encoder exposed to scripts** — your Zydis is used internally but not exposed to scripting
3. **Unicorn exposed to scripts** — same story, your emulation engine exists but isn't script-accessible
4. **SSE Intrinsics in scripts** — for pointer decryption/deobfuscation
5. **Extensions API** — plugin system with AI pipeline hooks, IntelliSense hooks, editor manipulation
6. **Source Reconstruction** — multi-file project generation from binary analysis
7. **proc_t exposed to scripts** — your driver bridge exists but isn't scriptable
8. **Struct descriptor pattern** — dictionary-based struct reading (you have struct_recon but scripts can't define structs)
9. **World-to-screen helpers** — game-specific projection functions
10. **Engine-specific helpers** (Unreal TArray reading, Fortnite name decryption, Rust transforms)

### Architecture Differences
| Feature | Perception | AiDA |
|---|---|---|
| Memory access | Overlay-based (likely usermode with driver) | Kernel driver (IOCTL) |
| Decompiler | Custom "F5" (likely proprietary) | Ghidra SLEIGH/p-code |
| Scripting | AngelScript + Lua (dual) | Lua (single) |
| UI | Custom overlay (DirectX/ImGui) | Standalone window (DirectX 11 + ImGui) |
| Protocol | None visible | MCP (JSON-RPC 2.0) |
| AI | OpenAI-compatible only | Anthropic, OpenAI, Gemini, OpenRouter, Local |
