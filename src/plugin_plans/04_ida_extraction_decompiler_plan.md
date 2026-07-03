# IDA Extraction And Decompiler Plan

## Scope

This plan covers the IDA Pro plugin extraction layer for multi-binary vulnerability-chain verification. Its job is to convert each loaded IDB into a deterministic, cacheable fact graph containing functions, instructions, xrefs, basic blocks, types, stack/register effects, ctree facts, and Hex-Rays microcode facts when available. It must never treat decompiler output as required for correctness; decompiler and microcode data are high-value enrichment layers over a complete assembly-backed extraction baseline.

This plan is intentionally read-only for IDA database state. Type application, renaming, comments, patching, and other database mutations belong to separate tools and must not run as part of chain extraction.

## Mandatory Case-Study Requirements

The critical section in `driver/PROGRESS.md` defines the failure modes the extraction layer must make machine-verifiable:

1. NTFS to ETW failed because the overflow source was `memset` zeros, not user-controlled `memmove` data, and because the assumed ETW stop trigger never reached `RemoveEntryList`.
2. AFD to `_setjmp` failed because a hidden `LIST_ENTRY` self-reference check existed before the indirect call site.
3. pvScan0 failed because the logical data flow was wrong: writing through `pvScan0 = gpHandleManager` writes to `gpHandleManager`, not back to `pvScan0`.

The extraction layer must therefore record:

- Source and content class for every write, including constant-zero writes, copied user/data writes, unknown writes, and transformed writes.
- Complete intra-function path facts before claimed sinks, including branch predicates, call sites, memory reads, memory writes, fastfail/noreturn edges, and side-effecting helpers.
- Positive and negative trigger-path evidence, including which reachable functions were traversed and what cutoff prevented stronger proof when traversal is incomplete.
- Logical read/write relationships, not only mechanical facts. A write effect must expose both the destination expression and the value expression so the verifier can prove whether `write([X], Y)` changes `X` itself.
- Cross-binary address identity with module name, image base, RVA, import/export name, and symbol name so chains spanning `afd.sys`, `ntoskrnl.exe`, `win32kbase.sys`, `ntfs.sys`, and `Etw` code can be joined without losing provenance.

## Current-State Findings

Existing AiDA plugin extraction is useful but fragmented:

- `src/agent_tools.cpp:435-466` has a `get_pseudocode()` helper that checks `init_hexrays_plugin()`, gets a `func_t`, rejects unsafe functions through `ida_utils::is_safely_decompilable()`, calls `decompile_func(..., DECOMP_NO_WAIT)`, prints pseudo-C, and returns string errors on failure.
- `src/agent_tools.cpp:512-749` exposes `get_function`, `list_functions`, `decompile_function`, and `disassemble_function`. These return function metadata, optional prototype, pseudo-C, local variable names/types, strings referenced by data xrefs, disassembly, and frame sizes.
- `src/agent_tools.cpp:751-790` and `src/agent_tools.cpp:9055-9080` expose xref-to/from query wrappers. They preserve from/to addresses, code/data flag, type, and user-defined flag, but they do not normalize xrefs into a reusable graph index.
- `src/agent_tools.cpp:950-1024` builds a bounded direct call graph by walking function items and code xrefs. This is a useful seed but is not path-sensitive and does not capture branch predicates or intermediate effects.
- `src/agent_tools.cpp:4495-4574` classifies indirect calls from raw `insn_t` operands, but target resolution remains local and heuristic.
- `src/agent_tools.cpp:13114-13193` bulk decompiles through `execute_sync(..., MFF_WRITE)` and reuses `ida_utils::get_full_cached_context()`. This proves there is already a batch path, but it caches text-oriented context rather than normalized extractor facts.
- `src/ida_utils.cpp:39-548` implements an in-memory plus `netnode` backed RAG cache keyed by binary hash and function EA. It enforces entry limits and record byte limits. This should be reused as a design pattern, but the chain extractor needs schema-versioned function facts, byte digests, type digests, and per-layer quality metadata.
- `src/ida_utils.cpp:726-775` falls back from Hex-Rays pseudo-C to `gen_disasm_text()` and tag-stripped assembly. This is the right resilience pattern, but the new layer must return structured instruction facts rather than only text.
- `src/ida_utils.cpp:2780-2799` rejects null, tail, thunk, outline, and zero-size functions before decompilation. This should remain the minimum safety gate.
- `src/vuln/microcode_engine.cpp:749-783` already wraps `gen_microcode()` at requested maturity with `vd_failure_t` and catch-all containment. It returns an owning `mba_handle_t`.
- `src/vuln/microcode_engine.cpp:846-913` dumps microcode blocks with maturity, block count, predecessors, successors, and instructions. This is close to the extraction substrate needed for path verification, but the new layer must persist provenance, operand/effect models, and failure reasons.
- `src/vuln/microcode_engine.cpp:968-1043` resolves microcode direct/helper calls and extracts call arguments. This should become the primary call-argument source when microcode is available.
- `src/vuln/microcode_engine.cpp:1106-1248` builds use/def evidence from SDK `mlist_t` lists. This is the correct low-level source for write/read effects when available.
- `src/vuln/symbolic_engine.cpp:602-665` collects branch predicates from microcode blocks, and `src/vuln/symbolic_engine.cpp:1085-1135` maps microcode condition opcodes into SMT AST predicates. This should consume extraction-layer facts rather than regenerate one-off local views.

Current gaps:

- No single canonical function fact schema. Text, xrefs, ctree scans, microcode dumps, and vulnerability scanners each create their own partial model.
- Decompiler failures are represented as strings in user-facing output, not structured layer statuses with failure reason, confidence, and fallback facts.
- Caches are not keyed by function byte digest, type state, Hex-Rays availability/version, microcode maturity, architecture, or extractor schema version.
- Raw instruction extraction does not consistently emit normalized operand semantics, instruction bytes, direct fallthrough, branch targets, call type, stack/register effects, and data/code xrefs in one record.
- Ctree and microcode facts are not aligned back to raw instruction records by EA plus synthetic/fictive EA mapping, which weakens path provenance.
- Cross-binary graph identity is not first-class. A fact needs `{module_id, image_base, rva, ea, symbol}` for every address-bearing record.
- Negative evidence is not modeled. For example, "ETW stop path did not call RemoveEntryList within the fully traversed reachable set" must be a first-class proof result, not absence of text.

## SDK Evidence And API Recommendations

The local SDK under `ida-sdk/src/include` is the source of truth. The extractor should use these APIs exactly because the headers define the supported contracts.

### Function Inventory

Use `get_func()`, `getn_func()`, `get_func_qty()`, `func_contains()`, and `func_item_iterator_t` for function and item enumeration.

```cpp
// ida-sdk/src/include/funcs.hpp:288-327
/// Get pointer to function structure by address.
/// \param ea  any address in a function
/// \return ptr to a function or nullptr.
idaman func_t *ida_export get_func(ea_t ea);
inline bool func_contains(func_t *pfn, ea_t ea)
{
  return get_func_chunknum(pfn, ea) >= 0;
}
/// Get pointer to function structure by number.
idaman func_t *ida_export getn_func(size_t n);
/// Get total number of functions in the program
idaman size_t ida_export get_func_qty(void);
```

```cpp
// ida-sdk/src/include/funcs.hpp:783-823
class func_item_iterator_t
{
public:
  func_item_iterator_t(func_t *pfn, ea_t _ea=BADADDR) { set(pfn, _ea); }
  bool first(void) { if ( !fti.main() ) return false; ea=fti.chunk().start_ea; return true; }
  ea_t current(void) const { return ea; }
  bool next_head(void) { return next(f_is_head, nullptr); }
  bool next_code(void) { return next(f_is_code, nullptr); }
  bool decode_prev_insn(insn_t *out) { return func_item_iterator_decode_prev_insn(this, out); }
};
```

### Instruction And Operand Decoding

Use `decode_insn()` into `insn_t`, then inspect `op_t` fields. This is the fallback baseline when Hex-Rays is unavailable and the ground truth for instruction bytes, control transfer, direct operands, and raw stack/register effects.

```cpp
// ida-sdk/src/include/ua.hpp:169-178
class op_t
{
public:
  uchar n = 0;
  /// Type of operand (see \ref o_)
  optype_t type = o_void;
```

```cpp
// ida-sdk/src/include/ua.hpp:222-257
/// Type of operand value (see \ref dt_).
op_dtype_t dtype = 0;
#define dt_byte         0
#define dt_word         1
#define dt_dword        2
#define dt_qword        7
union
{
  uint16 reg;
  uint16 phrase;
```

```cpp
// ida-sdk/src/include/ua.hpp:370-411
class insn_t
{
public:
  ea_t ea = BADADDR;
  uint16 itype = 0;
  /// Size of instruction in bytes.
  uint16 size = 0;
  op_t ops[UA_MAXOP];
```

```cpp
// ida-sdk/src/include/ua.hpp:1501-1509
/// Analyze the specified address and fill 'out'.
/// This function does not modify the database.
/// \return the length of the (possible) instruction or 0
idaman int ida_export decode_insn(insn_t *out, ea_t ea);
```

### Bytes, Mapping, And Disassembly Fallback

Use `is_mapped()`, `get_item_end()`, `get_item_size()`, `get_bytes()`, `is_code()`, `is_head()`, `generate_disasm_line()`, `tag_remove()`, and `gen_disasm_text()` for stable assembly-backed extraction and UI display text.

```cpp
// ida-sdk/src/include/bytes.hpp:231-273
/// Get the end address of the item at 'ea'.
idaman ea_t ida_export get_item_end(ea_t ea);
/// Get size of item (instruction/data) in bytes.
inline asize_t get_item_size(ea_t ea) { return get_item_end(ea) - ea; }
/// Is the specified address 'ea' present in the program?
idaman bool ida_export is_mapped(ea_t ea);
```

```cpp
// ida-sdk/src/include/bytes.hpp:720-731
idaman ssize_t ida_export get_bytes(
        void *buf,
        ssize_t size,
        ea_t ea,
        int gmb_flags=0,
        void *mask=nullptr);
#define GMB_READALL 0x01
```

```cpp
// ida-sdk/src/include/bytes.hpp:783-810
/// Does flag denote start of an instruction?
inline THREAD_SAFE constexpr bool idaapi is_code(flags64_t F)  { return (F & MS_CLS) == FF_CODE; }
/// Does flag denote start of instruction OR data?
inline THREAD_SAFE constexpr bool idaapi is_head(flags64_t F)  { return (F & FF_DATA) != 0; }
```

```cpp
// ida-sdk/src/include/lines.hpp:293-304
idaman THREAD_SAFE ssize_t ida_export tag_remove(qstring *buf, const char *str, int init_level=0);
inline THREAD_SAFE ssize_t idaapi tag_remove(qstring *buf, int init_level=0)
{
  if ( buf->empty() )
    return 0;
  return tag_remove(buf, buf->begin(), init_level);
}
```

```cpp
// ida-sdk/src/include/lines.hpp:509-522
// Generate one line of disassembly
idaman bool ida_export generate_disasm_line(
        qstring *buf,
        ea_t ea,
        int flags=0);
#define GENDSM_FORCE_CODE  (1 << 0)
#define GENDSM_REMOVE_TAGS (1 << 2)
```

```cpp
// ida-sdk/src/include/kernwin.hpp:5072-5077
/// \param[out] text  result
/// \param ea1        start address
/// \param ea2        end address
inline void gen_disasm_text(text_t &text, ea_t ea1, ea_t ea2, bool truncate_lines) { callui(ui_gen_disasm_text, &text, ea1, ea2, truncate_lines); }
```

### Xrefs

Use `xrefblk_t` in both directions and preserve every returned field. The extractor must not mutate `xrefblk_t` contents.

```cpp
// ida-sdk/src/include/xref.hpp:170-194
/// Structure to enumerate all xrefs.
/// First, all code references will be returned, then all data references.
/// If you need only data references, pass #XREF_DATA flag to first().
/// You may not modify the contents of a xrefblk_t structure! It is read only.
struct xrefblk_t
```

```cpp
// ida-sdk/src/include/xref.hpp:195-214
{
  ea_t from;
  ea_t to;
  bool iscode;
  uchar type;
  bool user;
#define XREF_FLOW       0x00
#define XREF_NOFLOW     0x01
#define XREF_DATA       0x02
#define XREF_CODE       0x04
```

```cpp
// ida-sdk/src/include/xref.hpp:228-242
bool first_from(ea_t _from, int flags=XREF_FLOW)
  { return xrefblk_t_first_from(this, _from, flags); }
bool next_from()
  { return xrefblk_t_next_from(this); }
bool first_to(ea_t _to, int flags=XREF_FLOW)
  { return xrefblk_t_first_to(this, _to, flags); }
bool next_to()
  { return xrefblk_t_next_to(this); }
```

### IDA Main-Thread Scheduling

Run IDB and Hex-Rays reads through `execute_sync()` with `MFF_READ` for read-only extraction. Use `MFF_NOWAIT` only for queueing owned heap request objects that survive until execution. Avoid `MFF_WRITE` for extraction because the layer must be read-only.

```cpp
// ida-sdk/src/include/kernwin.hpp:4434-4456
/// \defgroup MFF_ Exec request flags
#define MFF_FAST   0x0000
#define MFF_READ   0x0001       ///< Execute code only when ida is idle and it is safe
                                ///< to query the database.
#define MFF_WRITE  0x0002       ///< Execute code only when ida is idle and it is safe
                                ///< to modify the database.
#define MFF_NOWAIT 0x0004       ///< Do not wait for the request to be executed.
```

```cpp
// ida-sdk/src/include/kernwin.hpp:4468-4487
/// Execute code in the main thread - to be used with execute_sync().
struct exec_request_t
{
  /// Callback to be executed.
  /// If this function raises an exception, execute_sync() never returns.
  virtual ssize_t idaapi execute() = 0;
```

```cpp
// ida-sdk/src/include/kernwin.hpp:5080-5086
/// Execute code in the main thread.
/// \param req   request specifying the code to execute
/// \param reqf  \ref MFF_
THREAD_SAFE inline ssize_t execute_sync(exec_request_t &req, int reqf) { return callui(ui_execute_sync, &req, reqf).ssize; }
```

### Hex-Rays Availability And Pseudo-C

Use `init_hexrays_plugin()` before any decompiler call. Use `decompile_func()` with `hexrays_failure_t` and `DECOMP_NO_WAIT`; add `DECOMP_WARNINGS` when diagnostics matter. Keep decompiler failures as structured status, not fatal extraction failure.

```cpp
// ida-sdk/src/include/hexrays.hpp:9187-9190
inline bool init_hexrays_plugin(int flags=0)
{
  hexdsp_t *dummy;
  return callui(ui_broadcast, HEXRAYS_API_MAGIC, &dummy, flags).i == (HEXRAYS_API_MAGIC >> 32);
}
```

```cpp
// ida-sdk/src/include/hexrays.hpp:7687-7701
/// \defgroup DECOMP_ decompile() flags
#define DECOMP_NO_WAIT      0x0001
#define DECOMP_NO_CACHE     0x0002
#define DECOMP_WARNINGS     0x0008
#define DECOMP_GXREFS_NOUPD 0x0040
#define DECOMP_GXREFS_FORCE 0x0080
#define DECOMP_VOID_MBA     0x0100
```

```cpp
// ida-sdk/src/include/hexrays.hpp:7724-7739
/// Decompile a function.
/// Multiple decompilations of the same function return the same object.
inline cfuncptr_t decompile_func(
        func_t *pfn,
        hexrays_failure_t *hf=nullptr,
        int decomp_flags=0)
{
  mba_ranges_t mbr(pfn);
  return decompile(mbr, hf, decomp_flags);
}
```

Use `cfunc_t` for function-level pseudo-C, local variables, EA maps, and ctree roots.

```cpp
// ida-sdk/src/include/hexrays.hpp:7477-7505
struct cfunc_t
{
  ea_t entry_ea;
  mba_t *mba;
  cinsn_t body;
  intvec_t &argidx;
  ctree_maturity_t maturity;
  eamap_t *eamap;
  boundaries_t *boundaries;
  strvec_t sv;
```

```cpp
// ida-sdk/src/include/hexrays.hpp:7532-7544
/// Print function text.
void hexapi print_func(vc_printer_t &vp) const;
/// Get vector of local variables.
/// \return pointer to the vector of local variables.
lvars_t *hexapi get_lvars();
```

Use `ctree_visitor_t` with `CV_PARENTS` for path-sensitive extraction of parent statements, enclosing conditions, and expression context. Use `CV_FAST` only for flat scans where parent context is irrelevant.

```cpp
// ida-sdk/src/include/hexrays.hpp:7026-7065
#define CV_FAST    0x0000
#define CV_PRUNE   0x0001
#define CV_PARENTS 0x0002
#define CV_POST    0x0004
parents_t parents;
/// This constructor can be used with CV_FAST, CV_PARENTS
ctree_visitor_t(int _flags) : cv_flags(_flags) {}
```

### Microcode

Use `gen_microcode()` for microcode extraction, `mba_maturity_t` to request the right layer, `mba_t::get_mblock()` and `mba_t::for_all_topinsns()` for block/instruction iteration, and `mba_t::verify(false)` only for debug assertions after any future microcode modifications. The extraction layer itself should not modify microcode, so it should not need `mark_chains_dirty()`.

```cpp
// ida-sdk/src/include/hexrays.hpp:4769-4781
enum mba_maturity_t
{
  MMAT_ZERO,
  MMAT_GENERATED,
  MMAT_PREOPTIMIZED,
  MMAT_LOCOPT,
  MMAT_CALLS,
  MMAT_GLBOPT1,
  MMAT_GLBOPT2,
  MMAT_GLBOPT3,
  MMAT_LVARS,
};
```

```cpp
// ida-sdk/src/include/hexrays.hpp:7759-7772
/// Generate microcode of an arbitrary code snippet
/// \param reqmat       required microcode maturity
/// \return pointer to  the microcode, nullptr if failed.
mba_t *hexapi gen_microcode(
        const mba_ranges_t &mbr,
        hexrays_failure_t *hf=nullptr,
        const mlist_t *retlist=nullptr,
        int decomp_flags=0,
        mba_maturity_t reqmat=MMAT_GLBOPT3);
```

```cpp
// ida-sdk/src/include/hexrays.hpp:5273-5356
/// Verify microcode consistency.
void hexapi verify(bool always) const;
/// Mark the microcode use-def chains dirty.
void hexapi mark_chains_dirty();
/// Get basic block by its serial number.
const mblock_t *get_mblock(uint n) const { QASSERT(52719, n < qty); return natural[n]; }
/// Visit all instructions.
int hexapi for_all_insns(minsn_visitor_t &mv);
/// Visit all top level instructions.
int hexapi for_all_topinsns(minsn_visitor_t &mv);
```

```cpp
// ida-sdk/src/include/hexrays.hpp:11969-12037
inline void mba_t::verify(bool always) const
{
  HEXDSP(hx_mba_t_verify, this, always);
}
inline int mba_t::for_all_insns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mba_t_for_all_insns, this, &mv);
}
inline int mba_t::for_all_topinsns(minsn_visitor_t &mv)
{
  return (int)(size_t)HEXDSP(hx_mba_t_for_all_topinsns, this, &mv);
}
```

### Type Information

Use `get_tinfo()` for read-only type retrieval, `tinfo_t::get_func_details()` for calling convention, args, return, stack args, and spoiled registers, and `tinfo_t::get_udt_details()` / `get_udm_by_offset()` for structure fields and offsets.

```cpp
// ida-sdk/src/include/nalt.hpp:1317
idaman bool ida_export get_tinfo(tinfo_t *tif, ea_t ea);
```

```cpp
// ida-sdk/src/include/typeinf.hpp:3478-3490
bool is_void() const     { return is_type_void(get_realtype());     }
bool is_unknown() const  { return is_type_unknown(get_realtype());  }
bool is_ptr() const      { return is_type_ptr(get_realtype());      }
bool is_func() const     { return is_type_func(get_realtype());     }
bool is_struct() const   { return is_type_struct(get_realtype());   }
bool is_union() const    { return is_type_union(get_realtype());    }
bool is_udt() const      { return is_type_struni(get_realtype());   }
bool is_enum() const     { return is_type_enum(get_realtype());     }
```

```cpp
// ida-sdk/src/include/typeinf.hpp:3544-3580
/// Get the udt specific info
bool get_udt_details(udt_type_data_t *udt, gtd_udt_t gtd=GTD_CALC_LAYOUT) const
{
  return get_type_details(BTF_STRUCT|gtd, udt);
}
/// Get only the function specific info for this tinfo_t
bool get_func_details(func_type_data_t *fi, gtd_func_t gtd=GTD_CALC_ARGLOCS) const
{
  return get_type_details(BT_FUNC|gtd, fi);
}
/// ::BT_PTR: get type of pointed object.
tinfo_t get_pointed_object() const { tinfo_t r; r.typid = get_tinfo_property(typid, GTA_PTR_OBJ); return r; }
```

```cpp
// ida-sdk/src/include/typeinf.hpp:4782-4825
/// Function type information (see tinfo_t::get_func_details())
struct func_type_data_t : public funcargvec_t
{
  int flags = 0;
#define FTI_SPOILED  0x0001
#define FTI_NORET    0x0002
#define FTI_ARGLOCS  0x0100
  tinfo_t rettype;
  argloc_t retloc;
  uval_t stkargs = 0;
  reginfovec_t spoiled;
```

```cpp
// ida-sdk/src/include/typeinf.hpp:5938-5945
inline int tinfo_t::get_udm_by_offset(udm_t *out, uint64 offset) const
{
  udm_t tmp;
  tmp.offset = offset;
  int rc = find_udm(&tmp, STRMEM_OFFSET);
  if ( rc >= 0 )
    out->swap(tmp);
  return rc;
}
```

## Extractor Architecture

### 1. `ida_extraction_service`

Create a single read-only service responsible for all IDB reads. It owns scheduling, cancellation, cache lookup, extraction budgeting, and result serialization. All IDA SDK and Hex-Rays calls enter through this service so crash containment and cache invalidation are consistent.

Recommended public operations:

- `extract_module_overview(options)` returns module identity, segment map, architecture, image base, function index summary, import/export summaries, type summary, and cache status.
- `extract_function_fact(module_id, ea_or_rva, layers, budget)` returns one normalized function fact with requested layers: raw, xrefs, types, ctree, microcode.
- `extract_function_batch(module_id, functions, layers, budget)` returns chunked facts with per-function status and no all-or-nothing failure.
- `query_xrefs(module_id, address_set, direction, filters)` returns indexed xrefs with provenance and completeness state.
- `invalidate_extraction_cache(scope)` clears only extraction-layer cache entries; it must not disturb existing unrelated RAG cache entries unless explicitly wired through a shared cache adapter.

### 2. Scheduler And Threading

Extraction must run on IDA's main thread through `execute_sync(..., MFF_READ)` because SDK reads and Hex-Rays state are not safe to access freely from arbitrary worker threads. Worker threads may prepare requests, merge JSON, compress results, and serve MCP responses, but the actual IDB and Hex-Rays calls must be inside a read-only request.

Each request body must catch `vd_failure_t`, `std::exception`, and `...` before returning to `execute_sync()` because `exec_request_t::execute()` documents that an escaping exception can prevent `execute_sync()` from returning. A failed function extraction returns `{status:"failed", layer:"ctree", reason:"vd_failure: ...", fallback_layers:["raw","xrefs","types"]}` rather than failing the whole batch.

`MFF_NOWAIT` is only acceptable for heap-owned requests that self-delete after execution, matching the existing `decomp_request_t` pattern. Batch extraction should prefer bounded synchronous chunks to simplify lifetime ownership.

### 3. Module Identity

Every address-bearing fact must include:

- `module_id`: stable digest over input path, loader input MD5/SHA256 if available, image base, bitness, processor, and IDB creation metadata.
- `module_name`: IDA root filename or canonical PE image name.
- `ea`: IDA linear address.
- `rva`: `ea - image_base` when inside the image.
- `segment`: segment name, start/end, permissions/class when available.
- `symbol`: best known name, demangled name, import/export name, ordinal when applicable.

Multi-binary chain verification must join by `{module_id, rva}` first and by `{normalized_module_name, export/import/symbol}` only as an explicitly weaker match.

### 4. Function Fact Schema

Each function fact should have:

- `identity`: module, start EA/RVA, end EA/RVA, name, demangled name, flags, size, frame sizes, hash of function bytes, and extractor schema version.
- `quality`: extraction completeness, layer status, decompiler availability, decompiler failure reason, microcode maturity emitted, truncation flags, and time spent per layer.
- `raw_instructions`: ordered instruction records from `func_item_iterator_t` plus `decode_insn()`.
- `basic_blocks`: raw CFG blocks, microcode blocks when available, and a mapping between raw block IDs and microcode block serials where possible.
- `xrefs_from` and `xrefs_to`: direct xrefs with code/data/type/user fields and reference EA.
- `calls`: direct, thunk-resolved, import, helper, indirect, virtual/table, register-indirect, and unresolved calls with target provenance.
- `effects`: normalized reads, writes, calls, returns, stack deltas, register definitions/uses, branch predicates, allocation/free markers, lock/atomic operations, and noreturn/fastfail exits.
- `types`: function prototype, return type, argument types/locations, spoiled registers, local variables, stack variables, referenced UDTs/enums, UDT member offsets used by the function.
- `ctree`: pseudo-C text plus structured ctree nodes when Hex-Rays succeeds.
- `microcode`: one or more maturity-specific extracts when Hex-Rays microcode succeeds.
- `diagnostics`: exact layer errors, timeouts, skips, function-size cutoffs, and cache hit/miss.

### 5. Raw Instruction Layer

This is mandatory for every function and must be sufficient for conservative verification when Hex-Rays is absent.

For each instruction:

- `ea`, `rva`, `size`, raw bytes, `itype`, canonical mnemonic when available, tag-free disassembly line, and original item flags.
- Operands with `n`, `type`, `dtype`, register/phrase, immediate value, address/displacement, operand byte offsets, shown/hidden state, and best-effort width.
- Direct control-flow facts: fallthrough EA, xref branch/call targets, call/return/jump classification, ordinary-flow xref marker, and block-end marker.
- Data/code xrefs from the instruction and xrefs to the instruction.
- Conservative register effects for common x86/x64 opcodes used in case studies: moves, lea, arithmetic, compare/test, call, return, push/pop, xadd, atomic/lock-prefixed instructions, string ops, and conditional branches. Unknown effects must remain unknown, not guessed.

This layer catches AFD-style hidden checks even without decompiler support because it records every branch and instruction before the indirect call.

### 6. Xref Graph Layer

Build two indexes per module:

- `from_index[ea] -> xref[]`
- `to_index[ea] -> xref[]`

Each xref includes `from`, `to`, `is_code`, `type`, `user`, source function, target function if any, source disassembly, and target symbol. The extractor must preserve ordinary flow xrefs for raw CFG construction but expose filters so callers can exclude them for call graph queries.

For trigger-path confirmation, the graph layer must return both positive and negative evidence:

- Positive: all paths or bounded best paths from trigger root to target behavior.
- Negative: reachable set fully traversed under declared budgets and target absent.
- Incomplete: target absent but traversal cut off by depth, node count, timeout, missing binary, unresolved indirect call, or decompiler/microcode failure.

### 7. Type And Operand Model

Use a single normalized operand/effect vocabulary across raw instructions, ctree, and microcode:

- `value_ref`: `reg`, `imm`, `mem`, `stack`, `lvar`, `gvar`, `arg`, `ret`, `helper`, `phi`, `unknown`.
- `width_bits`: exact where known, derived from `op_t::dtype`, `tinfo_t`, `mop_t::size`, or ABI; unknown otherwise.
- `type_ref`: stable serialized type name, ordinal/tid if available, UDT member reference, pointer target type, enum info.
- `address_expr`: base register/lvar, index, scale, displacement, absolute EA, module RVA, symbolic expression text.
- `value_origin`: `constant_zero`, `constant_nonzero`, `copied_from_input`, `copied_from_memory`, `derived`, `unknown`, with provenance to the defining instruction/microinstruction.
- `alias_class`: conservative identifier for stack slot, lvar index, global address, UDT member, register, or unknown memory.

For case-study accuracy, stores must record both destination and source:

- `memset` produces `write(dst+i, 0)` with `value_origin=constant_zero`.
- `memmove`/copy helpers produce `write(dst+i, read(src+i))` with source provenance and size expression.
- `SetBitmapBits`-style effects expose `write(address=value(pvScan0), value=user_buffer)` so the verifier can ask whether the write changes `pvScan0` itself.

### 8. Ctree Layer

When `init_hexrays_plugin()` and safety gates pass, decompile through `decompile_func()` and extract:

- Pseudo-C text with tag-free output for UI and LLM context.
- `cfunc_t` function type, lvars, argument mapping, local variable locations, and user-visible names/types.
- Ctree nodes with node id, operation, EA, parent chain, statement/expression role, printed expression, type, lvar refs, member offsets, object EAs, constants, calls, assignments, branches, returns, switches, and loop headers.
- Branch facts with condition expression, true/false child statement IDs, parent path, and all enclosing predicates.
- Call facts with callee expression, direct object EA when present, argument summaries, argument lvar/constant/member refs, and whether target is unresolved/indirect.
- Memory facts from `cot_memptr` and `cot_memref`, including base expression, member offset, and resolved UDT member when type data allows.

Use `CV_PARENTS` for branch/effect extraction because the parent list is required to identify checks between function entry and a target sink. Use `CV_FAST` only for flat collection such as "all calls in a function" where parent context is explicitly unnecessary.

### 9. Microcode Layer

Generate microcode only after raw extraction succeeds. Emit layer status independently.

Recommended maturity strategy:

- `MMAT_CALLS`: call argument discovery when call info is needed and full lvar allocation is expensive or fails.
- `MMAT_GLBOPT3`: stable optimized control/data-flow for reads, writes, branch predicates, and call targets.
- `MMAT_LVARS`: lvar-aware facts for source/sink variable naming, stack/local mapping, and SMT handoff.
- Optional dual extraction at `MMAT_GENERATED` or `MMAT_LOCOPT` for difficult compiler patterns where optimization erases a relevant intermediate write-source distinction. This must be budgeted and explicitly reported as an extra layer.

For each `mba_t`:

- Record maturity, `entry_ea`, block count, block serials, block type, start/end, predecessor/successor sets, and instruction count.
- For each top-level `minsn_t`, record EA, opcode, printed text, l/r/d operands, nested instructions, call info, branch target, block serial, and source raw instruction mapping.
- For each `mop_t`, record kind, size, value/register/lvar/stack/global/helper info, nested call args, and type where available.
- Use `mblock_t::build_use_list()` and `build_def_list()` through the existing helper pattern to compute read/write location lists for each microinstruction.
- Resolve microcode calls through the existing `resolve_call_target()` behavior and store direct, helper, thunk-resolved, indirect, and unresolved target states.
- Feed branch predicates to the existing symbolic engine only after extraction has recorded the underlying microinstruction facts and branch target relationship.

The extraction layer should not modify microcode. If a future optimizer/normalizer pass is added, it must call `mark_chains_dirty()` after inter-block dependency changes and `verify()` before returning to Hex-Rays, per SDK guidance.

### 10. Basic Block And CFG Construction

Primary CFG order:

1. Use microcode block predecessor/successor sets when microcode succeeds because Hex-Rays has already constructed a normalized CFG.
2. Otherwise build raw basic blocks from instruction leaders: function start, xref branch targets inside the function, fallthrough after conditional block ends, and exception/indirect targets when known.
3. Preserve both CFGs when both exist. Do not collapse raw and microcode blocks into one lossy graph.

Every edge must include:

- `from_block`, `to_block`
- `kind`: fallthrough, conditional_true, conditional_false, unconditional_jump, call_return, exception, indirect, unknown
- `condition_ref` when conditional
- `evidence`: raw xref, decoded instruction, microcode succset, ctree branch

### 11. Cross-Binary Resolution

The extraction layer should not try to load binaries by itself. It should accept multiple loaded module fact stores and provide a resolver over them:

- Direct address: exact `{module_id, rva}`
- Import/export: importing module import entry to exporting module export/name/ordinal
- Known kernel public symbol: normalized module name plus symbol/RVA from PDB/IDA names
- Thunk: `FUNC_THUNK` plus `calc_thunk_func_target()` when available in current codebase patterns
- Indirect controlled target: value produced by prior chain state, represented as a symbolic target with required preconditions

Resolution quality must be explicit:

- `exact`: same module digest and RVA
- `symbolic_exact`: export/PDB/public symbol match
- `name_weak`: normalized name match without same binary digest
- `controlled`: chain state supplies the pointer
- `unresolved`: no supported resolution

### 12. Caching Design

Use a two-level cache:

- In-memory LRU for hot function facts.
- Persistent IDB-local `netnode` or existing analysis DB storage for serialized MsgPack/JSON facts.

Cache key:

```text
extractor_schema_version
module_id
function_start_rva
function_end_rva
function_bytes_sha256
function_flags
type_digest_for_function_and_referenced_udts
hexrays_available
hexrays_sdk_version_marker
requested_layers
requested_microcode_maturities
architecture_and_bitness
```

Cache value:

- Function fact payload.
- Per-layer status and failure reason.
- Byte count, instruction count, node count, extraction duration.
- Dependency list: referenced type names/tids, import/export names, call target RVAs, data addresses.

Invalidation:

- Function bytes changed: invalidate function raw, ctree, microcode, and effects.
- Function type or referenced UDT digest changed: invalidate type, ctree, microcode lvar/type facts, and effects that use type offsets.
- Hex-Rays availability changed: keep raw/xref/type facts; invalidate ctree/microcode layers only.
- Extractor schema version changed: invalidate all extractor facts for that schema.
- User asks for force refresh: refresh requested function/module only.

The cache must never persist raw SDK pointers such as `func_t*`, `cfunc_t*`, `mba_t*`, `mblock_t*`, `minsn_t*`, `mop_t*`, or `lvar_t*`. Persist only normalized values.

### 13. Error Containment

The extractor must fail closed and continue:

- Every per-function layer returns `ok`, `skipped`, `failed`, or `timeout`.
- Every failure includes `layer`, `function`, `exception_class`, `message`, and fallback layers emitted.
- Hex-Rays failure marks only ctree/microcode layers failed. Raw instructions, xrefs, and type facts remain valid if extracted.
- Oversized functions are chunked or skipped by layer with explicit size thresholds. Raw instruction extraction can be chunked; ctree/microcode can be skipped if over budget.
- JSON/string output is size capped per function and per batch. Structured facts are paginated by block/instruction index.
- Batches are per-function isolated. One decompiler crash or SDK exception cannot abort the whole module extraction.
- Cancellation checks occur between functions and between expensive layer steps.
- Diagnostics must capture time spent, cache hit/miss, function size, layer statuses, and exact fallback decision.

## Files Likely Affected In Implementation

The implementation should be isolated to new extraction modules plus narrow tool registration changes:

- `src/ida_extraction.hpp`
- `src/ida_extraction.cpp`
- `src/agent_tools.cpp` for new MCP/tool entry points and aliases only
- `src/agent_tools.hpp` if public declarations are needed
- `src/ida_utils.hpp`
- `src/ida_utils.cpp` only for shared cache adapters or common safe-decompile helpers
- `src/vuln/microcode_engine.hpp`
- `src/vuln/microcode_engine.cpp` only if existing microcode helpers need non-breaking structured extensions
- `src/analysis_db.hpp` only if persistent cache storage moves there rather than `netnode`
- `src/mcp_server.cpp` only if new tools require registration surface changes outside `agent_tools.cpp`
- Focused tests under existing plugin/testlab MCP coverage files after implementation

No encrypted generated headers, driver files, server files, protector files, or standalone UI files should be touched for this extraction layer unless a later implementation brief explicitly expands scope.

## Proposed Tool Surface

Expose read-only tools:

- `extract_module_facts`: returns module overview and cache status.
- `extract_function_facts`: returns normalized facts for one function with `layers` and `maturities` options.
- `extract_function_batch`: returns normalized facts for multiple functions with pagination and per-function layer statuses.
- `extract_xref_graph`: returns xref subgraph around addresses/functions, with direction, depth, ordinary-flow filter, and completeness reason.
- `extract_path_window`: returns all raw/ctree/microcode facts between `start_ea` and `target_ea` inside a function, intended to catch hidden intermediate checks.
- `extract_type_facts`: returns UDT/function type facts, member offsets, argument locations, and spoiled registers.
- `extraction_cache_status`: returns hit/miss, version, storage byte counts, and invalidation reasons.

These tools should return facts, not conclusions. Chain feasibility, SMT solving, and vulnerability-specific claims should consume the facts in later layers.

## Acceptance Criteria

The extraction layer is acceptable when all criteria are true:

1. A function can be extracted with Hex-Rays unavailable and still returns raw instructions, operands, xrefs, basic blocks, direct calls, bytes, disassembly, type facts where present, and explicit `ctree`/`microcode` unavailable statuses.
2. A function can be extracted with Hex-Rays available and returns pseudo-C, ctree nodes with parent paths, lvars, structured calls, branch facts, memory/member refs, microcode blocks, microinstructions, use/def lists, and call arguments.
3. Decompiler failure for one function does not abort batch extraction and does not prevent raw/xref/type facts from being returned for that function.
4. Cache hits are keyed by byte digest, type digest, schema version, module identity, requested layers, and microcode maturity. A changed function byte or UDT member layout invalidates affected facts.
5. No extraction code mutates IDA database state. No `apply_tinfo`, comments, renames, patches, or dirty-marking calls are part of extraction.
6. Every address in every fact includes module identity and RVA when applicable.
7. Every effect fact records both destination and source expression, width, source layer, provenance EA, and confidence.
8. Case Study 1 can represent `memset` overflow as constant-zero writes and `memmove` as copied data, allowing postcondition/precondition mismatch detection.
9. Case Study 1 trigger-path extraction can return complete negative evidence when a bounded ETW stop reachable set contains no `RemoveEntryList`, or explicit incomplete evidence if traversal is cut off.
10. Case Study 2 extraction can return the `LIST_ENTRY` branch/check before the indirect call with parent/path context and memory offsets `conn+0x48` / `conn+0x50` when type/operand evidence supports them.
11. Case Study 3 extraction can represent `SetBitmapBits`-style writes as `write([pvScan0], user_value)` so the verifier can prove whether the write changes `pvScan0`.
12. Batch extraction over a large IDB is paginated, cancellable, and bounded by time and result-size budgets.
13. All layer failures include structured diagnostics and exact fallback status.

## Verification Plan

After implementation, the host AI should build with the canonical wrapper. This planning subagent must not build.

Recommended verification sequence:

1. Static review: confirm extraction modules do not call mutation APIs such as `apply_tinfo`, `set_cmt`, rename APIs, patch APIs, or type application helpers.
2. Unit-level plugin tests: feed a small fixture IDB and assert function inventory, raw instruction records, xrefs, operand fields, bytes, and disassembly are present without Hex-Rays.
3. Hex-Rays-enabled fixture: extract a known function with branches, calls, locals, member accesses, and indirect calls; assert ctree parent paths, lvars, call args, branch nodes, and member offsets are emitted.
4. Microcode fixture: extract at `MMAT_CALLS`, `MMAT_GLBOPT3`, and `MMAT_LVARS`; assert block pred/succ sets, minsn/mop facts, call targets, call args, and use/def lists are emitted with maturity labels.
5. Failure fixture: force or select a non-decompilable thunk/tail/extern/oversized function; assert raw facts return and ctree/microcode layers return structured skip/failure statuses.
6. Cache fixture: extract a function twice and assert second run is a cache hit; modify only type information in a test IDB and assert type-dependent facts invalidate while raw byte facts remain reusable.
7. Cross-binary fixture: load two related binaries and assert imported/exported/direct symbol references resolve with explicit resolution quality.
8. Case-study replay tests:
   - NTFS path: assert write-source classification distinguishes `memset` zero writes from `memmove` copied writes.
   - ETW trigger: assert reachable-set evidence can state whether `RemoveEntryList` is reached or why proof is incomplete.
   - AFD path: assert extraction of branch/check facts before indirect call and extraction of the indirect call operand source.
   - pvScan0 path: assert destination/source expressions preserve the self-reference requirement.
9. Stress test: extract a large Windows driver IDB with paginated batches, cancellation, and result-size caps; assert no unhandled exception crosses `execute_sync()`.
10. MCP/tool test: call each new read-only extraction tool and assert schemas, error envelopes, cache status, and layer statuses are stable.

## Implementation Order

1. Add normalized schemas and value/effect/type models.
2. Add read-only scheduler and per-function extraction request containment.
3. Implement raw function, instruction, xref, bytes, and CFG extraction.
4. Add cache key/value storage and invalidation.
5. Add type extraction and operand type annotation.
6. Add ctree extraction with parent-aware visitors.
7. Add microcode extraction adapters over existing `src/vuln/microcode_engine` helpers.
8. Add cross-binary resolver and resolution-quality tagging.
9. Add read-only MCP tools and paginated batch responses.
10. Add focused fixtures and verification coverage for the three documented chain failures.

This order guarantees that assembly-backed facts work before optional decompiler enrichment is introduced, which is required for robust chain verification on machines without Hex-Rays or on functions Hex-Rays cannot decompile.
