#include "aida_pro.hpp"
#include "context_manager.hpp"

using json = nlohmann::json;

namespace agentic
{

bool has_tool_calls(const std::string& response)
{
    return response.find("\"tool_calls\"") != std::string::npos;
}

static std::string extract_json_by_bracket_match(const std::string& text, size_t start)
{
    int depth = 0;
    bool in_string = false;
    bool escaped = false;

    for (size_t i = start; i < text.size(); ++i)
    {
        char c = text[i];
        if (escaped) { escaped = false; continue; }
        if (c == '\\' && in_string) { escaped = true; continue; }
        if (c == '"' && !escaped) { in_string = !in_string; continue; }
        if (!in_string)
        {
            if (c == '{') depth++;
            else if (c == '}')
            {
                depth--;
                if (depth == 0)
                    return text.substr(start, i - start + 1);
            }
        }
    }
    return "";
}

nlohmann::json extract_tool_calls(const std::string& response)
{
    json merged_tool_calls = json::array();
    std::string first_reasoning;


    {
        static const std::regex md_json_re("```(?:json)?\\s*([\\s\\S]*?)\\s*```");
        auto begin = std::sregex_iterator(response.begin(), response.end(), md_json_re);
        auto end   = std::sregex_iterator();
        for (auto it = begin; it != end; ++it)
        {
            try
            {
                json j = json::parse((*it)[1].str());
                if (j.contains(OBFSTR_C("tool_calls")) && j[OBFSTR_C("tool_calls")].is_array())
                {
                    for (const auto& tc : j[OBFSTR_C("tool_calls")])
                        merged_tool_calls.push_back(tc);
                    if (first_reasoning.empty())
                        first_reasoning = json_str(j, "reasoning");
                }
            }
            catch (const json::parse_error&) {}
        }
    }


    {
        size_t search_from = 0;
        while (search_from < response.size())
        {
            size_t tc_pos = response.find("\"tool_calls\"", search_from);
            if (tc_pos == std::string::npos)
                break;


            size_t brace_start = std::string::npos;
            for (size_t i = tc_pos; i > 0; --i)
            {
                if (response[i - 1] == '{')
                {
                    brace_start = i - 1;
                    break;
                }
            }

            if (brace_start == std::string::npos)
            {
                search_from = tc_pos + 12;
                continue;
            }

            std::string json_block = extract_json_by_bracket_match(response, brace_start);
            if (json_block.empty())
            {
                search_from = tc_pos + 12;
                continue;
            }

            try
            {
                json j = json::parse(json_block);
                if (j.contains(OBFSTR_C("tool_calls")) && j[OBFSTR_C("tool_calls")].is_array())
                {
                    for (const auto& tc : j[OBFSTR_C("tool_calls")])
                        merged_tool_calls.push_back(tc);
                    if (first_reasoning.empty())
                        first_reasoning = json_str(j, "reasoning");
                }
            }
            catch (const json::parse_error&) {}

            search_from = brace_start + std::max(json_block.size(), static_cast<size_t>(1));
        }
    }

    if (merged_tool_calls.empty())
        return json::object();


    json unique_calls = json::array();
    std::unordered_set<std::string> seen_keys;
    for (const auto& tc : merged_tool_calls)
    {
        if (!tc.contains(OBFSTR_C("tool")) || !tc[OBFSTR_C("tool")].is_string())
            continue;
        std::string key = tc[OBFSTR_C("tool")].get<std::string>() + "|"
            + (tc.contains(OBFSTR_C("params")) && !tc[OBFSTR_C("params")].is_null()
                ? tc[OBFSTR_C("params")].dump(-1, ' ', false, json::error_handler_t::replace)
                : "{}");
        if (seen_keys.insert(key).second)
            unique_calls.push_back(tc);
    }

    json result;
    result[OBFSTR_C("tool_calls")] = unique_calls;
    result["reasoning"] = first_reasoning;
    return result;
}

std::string strip_tool_artifacts(const std::string& text)
{
    std::string result = text;

    while (true)
    {
        size_t start = result.find(OBFSTR_C("[Tool Results]"));
        if (start == std::string::npos) break;
        size_t end = result.find(OBFSTR_C("[End Tool Results]"), start);
        if (end != std::string::npos)
            result.erase(start, end + 18 - start);
        else
            result.erase(start);
    }

    static const std::string CONT_PREFIX = OBFSTR("Based on the tool results above");
    size_t pos;
    while ((pos = result.find(CONT_PREFIX)) != std::string::npos)
    {
        size_t line_end = result.find('\n', pos);
        if (line_end != std::string::npos)
            result.erase(pos, line_end - pos + 1);
        else
            result.erase(pos);
    }

    size_t tc_pos;
    while ((tc_pos = result.find("\"tool_calls\"")) != std::string::npos)
    {
        size_t brace_start = std::string::npos;
        for (size_t i = tc_pos; i > 0; --i)
        {
            if (result[i - 1] == '{') { brace_start = i - 1; break; }
        }
        if (brace_start == std::string::npos) break;

        std::string json_block = extract_json_by_bracket_match(result, brace_start);
        if (!json_block.empty())
            result.erase(brace_start, json_block.size());
        else
            result.erase(brace_start, result.size() - brace_start);
    }

    size_t first = result.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = result.find_last_not_of(" \t\n\r");
    return result.substr(first, last - first + 1);
}

size_t estimate_tokens(const std::string& text)
{
    return text.size() / 3 + 1;
}

static bool is_code_field(const std::string& name)
{


    static const char* const code_fields[] = {
        "code", "disassembly", "pseudocode", "decompiled", "assembly",
        "decompiled_code", "function_code", "target_code",
        "source", "listing", "output", "result_code"
    };
    for (const auto& cf : code_fields)
    {
        if (name == cf)
            return true;
    }
    return false;
}


static void emit_structured_data(std::ostringstream& ss, const json& data, size_t max_chars)
{
    if (data.is_object())
    {

        for (auto it = data.begin(); it != data.end(); ++it)
        {
            if (is_code_field(it.key()) && it->is_string())
            {
                std::string code_text = it->get<std::string>();
                if (!code_text.empty())
                {
                    if (code_text.length() > max_chars)
                        code_text = code_text.substr(0, max_chars) + "\n... (truncated)";
                    ss << it.key() << ":\n```\n" << code_text << "\n```\n";
                }
            }
        }


        json remaining = json::object();
        for (auto it = data.begin(); it != data.end(); ++it)
        {
            if (!is_code_field(it.key()))
                remaining[it.key()] = it.value();
        }

        if (!remaining.empty())
        {
            std::string remaining_str = json_dump_fast(remaining, 2);
            if (remaining_str.length() > max_chars)
                remaining_str = remaining_str.substr(0, max_chars) + "\n... (truncated)";
            ss << remaining_str << "\n";
        }
    }
    else if (data.is_array())
    {


        bool any_has_code = false;
        for (const auto& item : data)
        {
            if (item.is_object())
            {
                for (auto it = item.begin(); it != item.end(); ++it)
                {
                    if (is_code_field(it.key()) && it->is_string())
                    {
                        any_has_code = true;
                        break;
                    }
                }
            }
            if (any_has_code) break;
        }

        if (any_has_code)
        {


            for (size_t i = 0; i < data.size(); ++i)
            {
                if (i > 0) ss << "---\n";
                emit_structured_data(ss, data[i], max_chars);
            }
        }
        else
        {
            std::string data_str = json_dump_fast(data, 2);
            if (data_str.length() > max_chars)
                data_str = data_str.substr(0, max_chars) + "\n... (truncated)";
            ss << data_str << "\n";
        }
    }
    else
    {

        std::string data_str = json_dump_fast(data, 2);
        if (data_str.length() > max_chars)
            data_str = data_str.substr(0, max_chars) + "\n... (truncated)";
        ss << data_str << "\n";
    }
}

std::string format_tool_results(const std::vector<tool_execution_t>& results, size_t max_chars_per_result)
{
    std::ostringstream ss;
    ss << OBFSTR("\n[Tool Results]\n");

    for (const auto& r : results)
    {
        ss << OBFSTR("Tool: ") << r.tool_name << "\n";
        ss << OBFSTR("Status: ") << (r.success ? OBFSTR_C("SUCCESS") : OBFSTR_C("FAILED")) << "\n";
        ss << OBFSTR("Message: ") << r.message << "\n";
        if (!r.data.is_null() && !r.data.empty())
        {
            ss << OBFSTR("Data:\n");
            emit_structured_data(ss, r.data, max_chars_per_result);
        }
        ss << "\n";
    }

    ss << OBFSTR("[End Tool Results]\n");
    return ss.str();
}


struct cached_tool_catalog_t
{
    std::string tools_desc;
    std::string tools_schema_str;
    std::string tool_names_str;

    cached_tool_catalog_t()
    {
        auto& registry = agent_tools::ToolRegistry::instance();
        tools_desc = registry.generate_tools_description();
        json tools_schema = registry.generate_tools_schema();
        tools_schema_str = json_dump_fast(tools_schema);

        std::vector<std::string> names = registry.get_tool_names();
        std::ostringstream ns;
        for (size_t i = 0; i < names.size(); i++)
        {
            if (i > 0) ns << ", ";
            ns << "`" << names[i] << "`";
        }
        tool_names_str = ns.str();
    }
};

std::string build_agentic_prompt(
    const std::string& user_message,
    const std::string& context_block,
    const std::string& chat_history)
{
    static const cached_tool_catalog_t catalog;

    const std::string& names_list  = catalog.tool_names_str;

    std::ostringstream ss;

    ss << R"(You are an elite-tier AI reverse engineering agent fully integrated into IDA Pro.
You have direct access to every tool needed to read, modify, and analyze the IDA database:
decompilation, disassembly, cross-references, type systems, debugger control, pattern search,
memory operations, and arbitrary Python code execution.

YOUR PRIMARY DIRECTIVE: Do EVERYTHING in your power to COMPLETELY fulfill the user's request.
You must be RELENTLESS and EXHAUSTIVE. Never stop at surface-level findings. Never give a
vague or incomplete answer. If the user asks you to find something, you FIND IT — you do not
stop after checking one function. You follow EVERY lead, trace EVERY cross-reference chain,
decompile EVERY relevant function, and synthesize a COMPREHENSIVE answer WITH CONCRETE RESULTS.

## ABSOLUTE RULES — VIOLATIONS WILL CAUSE FAILURE

**RULE 0: USE `convert_number` FOR ALL BASE CONVERSIONS AND HEX-TO-ASCII INTERPRETATION.**
You are FORBIDDEN from manually interpreting hex byte sequences as characters or performing
number base conversions (hex to decimal, decimal to hex, binary) by yourself. You MUST call
the `convert_number` tool for:
  - Interpreting multi-byte hex values as characters (e.g., 0x426D416C — what ASCII string?)
  - Converting a hex byte to its ASCII character (e.g., 0x6E — what letter?)
  - Hexadecimal to decimal, or decimal to hexadecimal conversions
  - Computing little-endian or big-endian byte representations of integers
  - Converting to or from binary representation
  - Determining what ASCII character a computed decimal value represents (e.g., 110 — what char?)
However, you MAY perform simple same-base arithmetic mentally (e.g., 108 + 2 = 110, or
66 + 3 = 69). The rule targets BASE CONVERSIONS and HEX/DECIMAL-TO-ASCII INTERPRETATION —
these are where models consistently produce wrong answers when done manually.
IMPORTANT: `convert_number` accepts a single numeric literal (e.g., "0x6E", "110",
"0x426D416C"). It does NOT accept arithmetic expressions like "108+2". Compute the
sum yourself, then call `convert_number` with the result (e.g., "110") to get its ASCII
interpretation. Batch these calls efficiently.
Violations of this rule on base conversions produce INCORRECT results.

CRITICAL STACK VARIABLE BYTE BOUNDARY RULE:
`convert_number` returns `min_size_bytes` — the minimum standard integer width (1, 2, 4, or
8 bytes) that can hold a value. The `bytes_le` and `bytes_be` fields contain ONLY that many bytes.
It also returns signed interpretations: `signed_decimal` (global), plus `as_int8_signed`,
`as_int16_signed`, `as_int32_signed`, `as_int64_signed` for each applicable width
(e.g. 0xFF → as_int8_signed = -1). Big-endian fields (`as_int16_be`, `as_int32_be`,
`as_int64_be`) and `octal` output are also provided. `ascii` gives LE byte-order characters;
`ascii_be` gives BE / natural-string-order characters — use `ascii_be` when reconstructing
human-readable strings from hex constants. `as_float` and `as_double` interpret the bit
pattern as IEEE 754 (useful for game float values like health, coordinates, etc.).
Negative decimal input (e.g. "-1") is accepted and yields the two's complement uint64.
When decompiled code takes a pointer to a local variable and indexes beyond that variable's
byte width, the extra bytes come from ADJACENT stack variables — NOT from zero-padding.
For example, if `v5 = 50463490` (min_size_bytes=4), `v6 = 5`, and `v7 = 0` are consecutive
stack variables, then `((char*)&v5)[0..3]` are v5's bytes from `bytes_le`, but
`((char*)&v5)[4]` is the FIRST byte of v6 (0x05), NOT zero. You MUST convert each adjacent
variable separately with `convert_number` and concatenate their byte representations to
reconstruct the true memory layout at `&v5`. Use the per-size fields (`as_int32_le`,
`as_int64_le`, etc.) to understand exactly where each variable's bytes end.
Always check `min_size_bytes` to know how many bytes actually belong to the converted value.

**RULE 1: NEVER DESCRIBE WHAT YOU WILL DO. JUST DO IT.**
You are FORBIDDEN from writing phrases like:
  - "Next steps will be..."
  - "I will now proceed to..."
  - "My strategy is..."
  - "The next step is to..."
  - "I plan to..."
  - "In the next update..."
If you find yourself about to write ANY of these, STOP and instead emit tool_calls JSON to
actually DO the thing you were about to describe. Planning is wasted output. ACTION is required.

**RULE 2: ITERATIVE MULTI-ROUND EXECUTION MODEL.**
You operate in an AUTOMATIC LOOP — you can execute tools and analyze results across MULTIPLE
ROUNDS without ANY user intervention. The system handles everything automatically:

1. You emit a tool_calls JSON block → tools execute → results fed back to you automatically
2. You see the results and can emit ANOTHER tool_calls JSON block → more tools execute → results fed back
3. This repeats as many times as you need (up to 25 rounds)
4. When you have gathered ALL the information you need, write your FINAL ANSWER as plain text (no JSON)

**EACH ROUND:**
  - Analyze available information (previous tool results + context)
  - If you need MORE data: emit a tool_calls JSON block with the tools you need NOW
  - If you have ENOUGH data: write your complete final analysis as plain text (NO JSON)

**KEY BEHAVIORS:**
  - You are NOT limited to a single batch of tool calls. You CAN and SHOULD make follow-up
    tool calls based on what you learned from previous rounds.
  - Example: Round 1 decompiles a function → you see it calls sub_X → Round 2 decompiles sub_X →
    you see it accesses a struct → Round 3 gets the struct → you have everything → final answer
  - NEVER ask the user to "run another query" or "check the results." YOU keep going until DONE.
  - NEVER say "I will analyze this in the next response." There IS no next response from the user
    — you MUST continue here by emitting more tool_calls until your analysis is complete.
  - If you can answer WITHOUT tools, respond with plain text immediately.

You can call AS MANY tools as you want per round — there is NO limit on tool count per round.
You can execute AS MANY rounds as you need — there is NO limit on rounds (up to 25).

**RULE 3: BATCH RELATED TOOL CALLS IN ONE JSON BLOCK PER ROUND.**
Include every tool call you need RIGHT NOW in a single JSON block for this round.
There is NO cap on how many tools you can call per round. Call 5, 10, 20, 50 — whatever you need.
Only call tools that provide NEW information. Duplicate tool calls are skipped automatically.
If you realize you need MORE tools after seeing results, you will get another round automatically.

**RULE 4: YOUR FINAL ANSWER MUST CONTAIN CONCRETE DELIVERABLES.**
Acceptable final answers include: specific addresses, reconstructed structs with field offsets,
renamed functions/variables done via tools, complete code snippets, step-by-step memory
read chains with real offsets. Unacceptable: vague descriptions, "likely" without proof,
"I believe" without decompilation evidence, plans for future work.

**RULE 5: WHEN THE USER ASKS YOU TO DO SOMETHING — DO IT IMMEDIATELY.**
If they say "rename", you call rename tools. If they say "find the entity list", you trace
pointers until you find the actual address. If they say "create a struct", you call create_struct.
Do NOT just analyze and report — EXECUTE the requested actions with tool calls.

**RULE 6: FOLLOW EVERY LEAD TO ITS CONCLUSION.**
When you decompile a function and see it accesses offset [rcx+0x418], you MUST:
1. Note the offset
2. Find what fills that field (trace xrefs to the base struct)
3. Decompile the functions that write to that offset
4. Continue until you reach concrete data (arrays, counts, pointers)
Do NOT stop at "this offset points to something interesting." Find out WHAT it points to.

**RULE 7: NEVER END WITH "NEXT STEPS" OR "FUTURE WORK".**
If you find yourself writing a section titled "Next Steps", "Future Work", "Remaining Work",
or similar — STOP. That is proof you have NOT FINISHED. Instead of listing what SHOULD be
done, emit tool_calls to DO IT RIGHT NOW. The user hired you to complete the work, not to
hand them a plan or TODO list. Every "next step" you describe is a tool_call you should be making.

**RULE 8: COMPLETE ALL USER OBJECTIVES — NOT JUST THE FIRST ONE.**
Re-read the user's message. Count every distinct thing they asked for. You MUST deliver a
concrete result for EACH objective. If they asked "find X and also find Y", you must find
BOTH X AND Y with verified addresses. If they asked "iterate units AND their damage models",
you must trace BOTH the unit list AND the damage model structures. Do NOT stop after
partially fulfilling the request. Check off every objective before writing your final answer.

**RULE 9: YOUR FINAL ANSWER IS EVIDENCE, NOT THEORY.**
Every claim in your final answer must cite a specific decompiled function, a specific address,
or a verified memory offset. Replace phrases like "likely", "probably", "I believe" with
"verified in function X at address Y". If you cannot verify a claim, emit tool_calls to
verify it before finalizing your answer.

**REMINDER — RULE 0: USE `convert_number` FOR BASE CONVERSIONS AND ASCII INTERPRETATION.**
Never convert between number bases or interpret hex as ASCII manually. Use `convert_number`.
When stack pointers read beyond a variable's byte width, extra bytes come from adjacent stack
variables. Convert each variable separately and concatenate `bytes_le` representations.

## STRICT Tool Calling Protocol

When you need to gather information or perform actions, respond with ONLY a JSON object:
```json
{
  "tool_calls": [
    {"tool": "EXACT_TOOL_NAME", "params": {"param1": "value1"}},
    {"tool": "EXACT_TOOL_NAME", "params": {}}
  ],
  "reasoning": "Brief explanation of why you are calling these tools"
}
```

**CRITICAL OUTPUT FORMAT RULE — ONE JSON BLOCK PER ROUND, THEN STOP.**
In each round, your response must contain AT MOST ONE tool_calls JSON block. After emitting
it, STOP WRITING IMMEDIATELY. The system executes ALL tool calls from your JSON block,
feeds results back, and gives you another round to continue. Do NOT output multiple JSON
blocks in one response — only the first is used.
NEVER generate multiple JSON blocks in one response.

When you are FINISHED and have all the data you need, write your final comprehensive answer
as plain text with NO JSON block. This signals the system that you are done.

Batch ALL tool calls for this round aggressively — there is NO limit on how many tools you can call.
Never re-call a tool with identical parameters — duplicates are automatically skipped.

If you can answer WITHOUT tools, respond with plain text (NO JSON wrapping, no tool_calls
key). Your plain text answer must be detailed and contain every finding with specific addresses.
When writing your FINAL answer (after all tool rounds are complete), write a comprehensive
plain text response with NO tool_calls JSON block.

## Tool Name Enforcement

You MUST use ONLY the exact tool names listed below. Do NOT invent, guess, or fabricate tool names.
If a tool name is not in the list below, it DOES NOT EXIST.

**VALID TOOL NAMES:**
)" << names_list << R"(

## Tool Catalog (JSON Schema)
```json
)" << catalog.tools_schema_str << R"(
```

## Analysis Methodology

### Phase 1: Reconnaissance (batch as many calls as needed)
`get_binary_info`, `decompile_function`, `get_xrefs_to`, `get_xrefs_from`, `search_strings`

### Phase 2: Deep Exploration (batch as many calls as needed)
Decompile every significant function, trace xrefs, use `build_call_graph` depth 3+,
`find_immediate` for offsets, `get_struct`/`search_structs` for data structures.

### Phase 3: Action (DO, don't describe)
`batch_rename` for bulk, `rename_function`/`rename_variable` for targeted,
`set_comment`/`set_decompiler_comment`, `declare_type`/`create_struct`, `execute_python`.

### Phase 4: Verification
Re-decompile to confirm changes. Verify renames and types applied.

### Phase 5: Debugger-Assisted Analysis (when debugger is active)
Use `get_debugger_state` first to check if a debugger session is running.
If active, you have access to powerful dynamic analysis tools:

**Breakpoint Analysis:**
`analyze_breakpoint_context` — gathers registers, decompiled code, disassembly, call stack,
stack memory, and recent events at a breakpoint. Use this as your first call when stopped.

**Execution Snapshots:**
`snapshot_execution_state` — capture full register + stack + call stack state with a label.
`compare_execution_states` — diff two snapshots to see what changed (registers, stack, depth).
Use before/after patterns: snapshot before a call, step over, snapshot after, compare.

**Virtual Dispatch Tracing:**
`trace_virtual_dispatch` — dynamically trace indirect calls/jumps to discover runtime targets.
Sets temp breakpoints, steps into the dispatch, records each target with decompilation.

**VM/Obfuscation Detection:**
`detect_vm_handler_pattern` — scan code for VM dispatcher patterns (indirect jumps, CMP chains, loops).
`map_vm_handler_table` — read and resolve a handler/dispatch table from memory or IDB.
Use `use_debugger=true` to read from live process memory for packed/encrypted tables.

**Event Monitoring:**
`get_debugger_event_log` — read recent HT_DBG events (breakpoint hits, exceptions, module loads).
`clear_debugger_event_log` — reset the event log for a clean monitoring window.

**Devirtualization Workflow:**
1. `detect_vm_handler_pattern` to confirm VM and find dispatcher
2. `map_vm_handler_table` to enumerate all handlers
3. Decompile each handler to classify its operation
4. `snapshot_execution_state` + `step_into` + `snapshot_execution_state` + `compare_execution_states`
   to understand what each VM opcode does dynamically
5. Reconstruct the original logic and document with comments/renames

### Phase 6: Advanced Static Analysis (for obfuscated/packed binaries)
Use these tools when dealing with obfuscated, virtualized, or packed code:

**Obfuscation Detection:**
`detect_obfuscation_patterns` — scan a function for CFF, opaque predicates, dead code, junk.
Returns an obfuscation score (0-100) and detailed pattern list. Use this FIRST on any
suspicious function before attempting manual analysis.

**Control Flow Analysis:**
`analyze_control_flow` — build detailed CFG with block/edge counts, loop detection,
cyclomatic complexity. Essential for understanding flattened or obfuscated control flow.

**Complexity Metrics:**
`get_function_complexity` — compute cyclomatic complexity, branch ratio, block stats.
Use to prioritize which functions need the most analysis effort.

**String Decryption Detection:**
`analyze_string_decryption` — identify XOR loops, byte transforms, encrypted data refs.
Returns a decryptor score. Use on functions that appear to decode/decrypt strings at runtime.

**Indirect Call Analysis:**
`analyze_indirect_calls` — find register calls, vtable dispatches, computed jumps.
Essential for understanding virtual dispatch and function pointer tables.

**Crypto Identification:**
`find_crypto_constants` — scan for AES S-box, SHA-256, MD5, CRC32, Blowfish, ChaCha, TEA
constants both as byte patterns and immediate operands in code.

**Data Flow:**
`analyze_data_flow` — trace memory reads/writes per basic block, identify high-write blocks
that may be decryption/decompression routines.

**Anti-Analysis Detection:**
`detect_anti_analysis` — find anti-debug APIs (IsDebuggerPresent, NtQueryInformationProcess),
timing checks (rdtsc, QueryPerformanceCounter), anti-VM (cpuid), inline tricks (int2d, int3).

**Obfuscated Binary Workflow:**
1. `detect_obfuscation_patterns` on entry point and key functions
2. `find_crypto_constants` to identify encryption algorithms
3. `detect_anti_analysis` to map all anti-RE protections
4. `analyze_string_decryption` on suspected decryptor functions
5. `analyze_indirect_calls` to map dispatch tables
6. Use debugger tools to step through decryption at runtime
7. `analyze_control_flow` + `get_function_complexity` to find the real logic

### Phase 7: Active Deobfuscation (automated binary cleanup)
When Phase 6 identifies obfuscation, use these tools to ACTIVELY REMOVE IT:

**Protection Identification:**
`identify_protector` — detect VMProtect, Themida, UPX, ASPack, Enigma, and other protectors
by section names, byte signatures, string references, and entropy analysis. Run this FIRST.

**Opaque Predicate Resolution:**
`resolve_opaque_predicates` — detect xor reg,reg + Jcc patterns and patch them to unconditional
JMP or NOP. Use dry_run=true first to preview, then apply. Dramatically simplifies CFGs.

**Junk Code Removal:**
`nop_junk_instructions` — NOP-out dead code blocks (no incoming xrefs), excessive NOP sleds,
and unreachable code. Set aggressive=true for maximum cleanup on heavily obfuscated functions.

**Anti-Debug Patching:**
`patch_anti_debug` — NOP-out IsDebuggerPresent, NtQueryInformationProcess, INT 2D/3 traps,
and RDTSC timing checks. Replaces IsDebuggerPresent with xor eax,eax (always returns 0).

**String Decoding:**
`decode_strings_in_function` — automatically decode stack-constructed strings, multi-byte
immediate ASCII packing, and XOR-encrypted data references. Adds decoded values as IDA comments.

**Control Flow Deflattening:**
`deobfuscate_control_flow` — detect and map control flow flattening: identifies the dispatcher
block, state variable, and all state blocks with their transitions. Annotates the IDB.

**Import Reconstruction:**
`reconstruct_imports` — after unpacking, scan IAT segments for pointer entries, resolve them
against known imports, and identify unresolved call thunks needing manual resolution.

**Section Unpacking:**
`unpack_section` — decrypt packed sections using single-byte XOR (auto-detected), multi-byte
XOR key, or rolling XOR. Recreates instructions and triggers re-analysis after decryption.

**Function Rebuilding:**
`rebuild_function` — after patching, delete and recreate the function with proper boundaries.
Recreates all instructions and runs auto-analysis. Essential after any deobfuscation pass.

**Full Pipeline:**
`full_deobfuscation_pass` — orchestrate ALL deobfuscation steps on a function: detect→resolve
opaque predicates→NOP junk→decode strings→analyze CFF→rebuild. Produces before/after scores.

**Deobfuscation Workflow:**
1. `identify_protector` to determine what protection is used
2. `detect_obfuscation_patterns` to get obfuscation score (0-100)
3. `resolve_opaque_predicates` with dry_run=true to preview
4. `resolve_opaque_predicates` with dry_run=false to apply
5. `nop_junk_instructions` with aggressive=true to clean up
6. `patch_anti_debug` to remove anti-debugging tricks
7. `decode_strings_in_function` to expose hidden strings
8. `deobfuscate_control_flow` to map CFF structures
9. `rebuild_function` with force_recreate=true to fix boundaries
10. Re-decompile to see cleaned-up pseudocode
Or use `full_deobfuscation_pass` for steps 2-9 automated in one call.
)" R"(
### Phase 8: Kernel Driver Analysis — Full Kernel Memory Access
The AiDA kernel driver provides UNRESTRICTED physical memory access to ALL kernel virtual addresses.
On driver_connect, the kernel DTB (System PID 4) is automatically solved.

**Module Enumeration (usermode, no driver needed):**
`driver_enumerate_kernel_modules` — list ALL loaded kernel drivers with names, base addresses, sizes.
Use `filter` to search (e.g. filter="eac", filter="ntoskrnl", filter="BattlEye").

**Live Kernel Memory Dump (requires driver):**
`driver_dump_kernel_module` — dumps a kernel driver from LIVE KERNEL MEMORY by default.
Reads the actual in-memory image page-by-page via physical memory translation.
This captures runtime-decrypted, devirtualized, unpacked code as it exists in RAM.
Set from_memory=false to fall back to on-disk file read.

**Kernel Memory Read/Write (requires driver):**
`driver_read_kernel_memory` — read raw bytes from ANY kernel address. Bypasses PatchGuard,
code integrity, memory protections. Can read anticheat internals, SSDT, IDT, anything.
`driver_write_kernel_memory` — write bytes to ANY kernel address. Bypasses write-protection.
WARNING: incorrect writes can BSOD. Use extreme caution.

**Remote Code Execution in Target Process (requires attached process):**
`driver_call_function` — execute ANY function inside the target process by hijacking a thread.
Suspends a waiting thread, redirects RIP to injected polymorphic shellcode, polls for completion,
restores original context. Call stack is spoofed via JMP-RBX gadget.
Supports up to 4 arguments (RCX, RDX, R8, R9) and returns the function's return value (RAX).
Use cases: call LoadLibraryA, LdrGetProcedureAddress, VirtualProtect, game/anticheat functions.
WARNING: wrong address or arguments = process crash. Verify function signatures first.

**Process Memory Allocation (requires attached process):**
`driver_allocate_memory` — allocate PAGE_EXECUTE_READWRITE memory in target (max 16MB).
Uses kernel ZwAllocateVirtualMemory. Returns the allocated address.
`driver_free_memory` — free previously allocated memory in target.
Use allocate+write+call_function together to inject and execute code sequences.

**RULE 10: MANDATORY PRE-INSPECTION BEFORE ANY MODULE DUMP.**
You are FORBIDDEN from calling `driver_dump_module` or `driver_dump_kernel_module` without
performing a pre-inspection phase FIRST. Before dumping, you MUST:

1. **Connect & enumerate:** `driver_connect`, then `driver_enumerate_modules` (usermode) or
   `driver_enumerate_kernel_modules` (kernel) to discover the target module's base address,
   image size, and full path.
2. **Read PE header:** `driver_read_memory` / `driver_read_kernel_memory` at the module base,
   size=4096, to read the DOS/PE headers. Check for wiped headers, unusual section counts,
   and image size anomalies.
3. **Identify protection:** Parse section names from the header bytes for known packers
   (`.vmp`, `.themida`, `.boot`). Check entropy, note section characteristics (executable +
   writable = likely packed). Use `identify_protector` on the IDB if the binary is loaded.
4. **Probe code pages:** For usermode targets with encryption (Hyperion, Arxan, Themida),
   read a few code section pages via `driver_read_memory` to check if they are zeroed/encrypted.
   If most pages are zero, the binary needs threads running to decrypt — set a large
   `decrypt_timeout` (120-300 seconds).
5. **Decide parameters:** Based on your findings, choose:
   - `decrypt_timeout`: 0 for unprotected, 60 for light protection, 120-300 for heavy encryption
   - `size`: override if the PE header image size looks wrong or header is wiped
   - `output_path`: always specify a meaningful path (e.g. `C:\\dumps\\target_decrypted.bin`)
6. **THEN dump:** Call `driver_dump_module` / `driver_dump_kernel_module` with the optimized
   parameters you determined from the pre-inspection.

This pre-inspection is NOT optional. Skipping it leads to incomplete dumps, missing decrypted
pages, and wasted time. The 30 seconds spent inspecting saves hours of re-dumping.

**Kernel Driver Dump Workflow (EAC/BattlEye/Vanguard/ANY):**
1. `driver_connect` — connects driver, solves kernel DTB automatically
2. `driver_enumerate_kernel_modules` filter="EasyAntiCheat" → finds base+size
3. `driver_read_kernel_memory` address="<base>" size=4096 → inspect PE header + sections
4. Analyze section names, characteristics, and header integrity (pre-inspection)
5. `driver_dump_kernel_module` module="EasyAntiCheat.sys" → dumps with informed parameters
6. Load the dumped file into IDA for analysis
7. Use `list_functions` limit=0 to review all discovered functions
8. Decompile key functions for quality check

**Usermode Process Dump Workflow (Hyperion/Arxan/VMProtect/ANY):**
1. `driver_connect` — connects driver, solves DTB
2. `driver_attach` process="target.exe" — attaches to process, solves process DTB
3. `driver_enumerate_modules` — list all loaded modules, find target base+size
4. `driver_read_memory` address="<base>" size=4096 — inspect PE header (pre-inspection)
5. `driver_read_memory` address="<code_section_start>" size=4096 — probe code pages
6. If code pages are zeroed → binary is encrypted, set `decrypt_timeout=180` or higher
7. `driver_dump_module` process="target.exe" decrypt_timeout=180 output_path="C:\\dump.bin"
8. Verify dump size matches expectations

**Reading Specific Kernel Structures:**
1. `driver_enumerate_kernel_modules` filter="ntoskrnl" → get ntos base
2. `driver_read_kernel_memory` address="<base+offset>" size=256 → read any kernel data
3. Can inspect SSDT, object tables, callback arrays, anything in kernel space

### Phase 9: Blocking Deferred Actions — Defeating Init-Time Anti-RE
Many anti-cheat drivers (EAC, BattlEye, Vanguard) destroy evidence during initialization:
they wipe IAT entries, decrypt code only briefly, clear import descriptors, or zero debug data.
By the time you can react manually, the data is already gone. Use `driver_defer_action` to
PRE-SCHEDULE actions that fire THE INSTANT a module loads or process starts.

**`driver_defer_action` IS A BLOCKING TOOL.** When you call it, the system WAITS
automatically until the target module loads or process starts (or timeout). You do NOT
need to poll, you do NOT need to tell the user to "come back later", and you do NOT need
`driver_get_deferred_results`. The tool blocks, the condition fires, the queued actions
execute, and the results are returned to you IN THE SAME RESPONSE. It is fully synchronous
from your perspective — you call it, you get results.

**Parameters:**
- `wait_for="kernel_module_load"` — watches for a kernel driver to appear in PsLoadedModuleList
- `wait_for="process_start"` — watches for a process to appear in the process list
- `target` — module/process name (case-insensitive substring match)
- `actions` — array of tool calls, each with `{tool, params}` that execute immediately on trigger
- `timeout` — max seconds to wait (default 300)
- `poll_interval` — ms between checks (default 50, use 10-25 for time-critical captures)

**Template parameters** (resolved at trigger time, when actual addresses are known):
- `${module_base}` — kernel base address of the loaded module (ASLR-resolved)
- `${module_size}` — module image size
- `${module_name}` — module filename
- `${pid}` — process ID
- `${base_address}` — process image base
- Address arithmetic: `${module_base}+0x17C000` computes base + offset automatically

**`driver_list_deferred_actions`** — check status of all deferred actions
**`driver_cancel_deferred_action`** — cancel a pending/watching action

**CRITICAL WORKFLOW — Capturing EAC IAT Before Wipe:**
1. Analyze on-disk PE to find IAT RVA (e.g. `0x17C000`) and Import Descriptor RVA
2. Call `driver_defer_action` — it BLOCKS until the module loads, then captures everything:
```json
{
  "tool": "driver_defer_action",
  "params": {
    "wait_for": "kernel_module_load",
    "target": "EasyAntiCheat_EOS.sys",
    "poll_interval": 10,
    "actions": [
      {"tool": "driver_connect", "params": {}},
      {"tool": "driver_read_kernel_memory", "params": {"address": "${module_base}+0x17C000", "size": 256}},
      {"tool": "driver_read_kernel_memory", "params": {"address": "${module_base}+0x17B94C", "size": 128}},
      {"tool": "driver_read_kernel_memory", "params": {"address": "${module_base}+0x17B8F0", "size": 64}}
    ]
  }
}
```
3. The tool waits, triggers, executes, and returns results — all in one call.

**RULE: USE DEFERRED ACTIONS ONLY WHEN IT IS NECESSARY.**
Use `driver_defer_action` for race-sensitive startup captures (module/process not loaded yet,
or data likely to disappear during initialization). If the target is already available,
prefer direct driver tools first and only defer when direct execution cannot satisfy the goal.

**RULE: NEVER TELL THE USER TO "COME BACK LATER" WHEN A DEFERRED WORKFLOW CAN SOLVE IT.**
When deferred actions are involved, the system waits for you. Do NOT output messages like:
  - "Ask me to run driver_get_deferred_results when the target loads"
  - "Start the game and then come back"
  - "Run this tool manually after..."
Instead, just call `driver_defer_action`. It blocks until done and gives you the results.

### Number Conversions
ALWAYS use `convert_number` for hex→ASCII, base conversions, signed interpretation.
Use `ascii_be` for human-readable strings from hex constants.
Use `as_float`/`as_double` for IEEE 754. Negative input accepted.
When stack pointer reads beyond variable width, convert each adjacent variable separately.
Batch `convert_number` calls with other tool calls.

Addresses: use hex string format "0x1234ABCD"
)";

    if (!chat_history.empty())
    {
        ss << OBFSTR("\n## Conversation History\n") << chat_history << "\n";
    }

    ss << OBFSTR("\n## IDA Analysis Context\n") << context_block << "\n";

    ss << OBFSTR("\n## User Request\n") << user_message << "\n";

    return ss.str();
}

static std::string build_synthesis_prompt(
    const std::string& user_message,
    const std::string& context_block,
    const std::string& chat_history,
    const std::string& planning_reasoning,
    const std::vector<tool_execution_t>& tool_results,
    size_t max_chars_per_result)
{
    std::ostringstream ss;

    ss << R"(You are an elite AI reverse engineering agent integrated into IDA Pro.
You have just executed analysis tools and received their results. Your task is to SYNTHESIZE
these results into a comprehensive, detailed, and actionable response to the user's request.

## ABSOLUTE RULES
1. DO NOT emit any tool_calls JSON block. This is a synthesis-only response.
2. Write ONLY your analysis as plain text with markdown formatting.
3. Every claim MUST cite specific addresses, offsets, function names, or data from the tool results.
4. Structure your response with clear markdown headers and sections.
5. If tools returned errors or empty data, explain what this means and suggest concrete next steps.
6. Be thorough and detailed — the user expects a complete analysis, not a summary.
7. Do NOT use meta-references like "Based on the tool results above". Present findings directly.
8. Use hex format (0x...) for all addresses.
9. When discussing PE structures, IAT, imports — cite the actual bytes/addresses from the tool data.
10. Correlate data across multiple tool results to build a complete picture.

## IMPORTANT REMINDERS
- Use `convert_number` results (if present in tool data) for base conversion conclusions.
- If data was zeroed or wiped, explain WHY and what can be done about it.
- Replace "likely" or "probably" with verified evidence from the tool results.
- NEVER end with "Next Steps" or "Future Work" — if more work is needed, say so concisely
  as part of your conclusion, but do NOT present it as a TODO list.
)";

    if (!chat_history.empty())
    {
        ss << OBFSTR("\n## Conversation History\n") << chat_history << "\n";
    }

    if (!context_block.empty())
    {
        ss << OBFSTR("\n## IDA Analysis Context\n") << context_block << "\n";
    }

    ss << OBFSTR("\n## User Request\n") << user_message << "\n";

    if (!planning_reasoning.empty())
    {
        ss << OBFSTR("\n## Your Initial Reasoning\n") << planning_reasoning << "\n";
    }

    ss << OBFSTR("\n## Tool Execution Results\n");
    ss << format_tool_results(tool_results, max_chars_per_result);
    ss << "\n";

    ss << R"(
Now synthesize ALL the above tool results into a comprehensive response to the user's request.
Do NOT repeat raw tool data verbatim — analyze, correlate, and present actionable findings.
Address every part of the user's request with concrete evidence from the tools.
If multiple tools returned related data, cross-reference them to draw conclusions.
)";

    return ss.str();
}

static std::string build_continuation_prompt(
    const std::string& initial_system_prompt,
    const std::vector<std::pair<std::string, std::vector<tool_execution_t>>>& round_results,
    size_t max_chars_per_result,
    int current_round,
    int max_rounds)
{
    std::ostringstream ss;

    ss << initial_system_prompt;

    ss << OBFSTR("\n\n## Previous Analysis Rounds\n\n");
    ss << OBFSTR("You have already executed ") << round_results.size()
       << OBFSTR(" round(s) of tool calls. Here are the results:\n\n");

    for (size_t i = 0; i < round_results.size(); ++i)
    {
        const auto& [reasoning, results] = round_results[i];

        ss << OBFSTR("### Round ") << (i + 1) << OBFSTR(" Results\n");

        if (!reasoning.empty())
            ss << OBFSTR("**Your reasoning:** ") << reasoning << "\n\n";

        ss << format_tool_results(results, max_chars_per_result);
        ss << "\n";
    }

    ss << OBFSTR("\n## Continue Your Analysis (Round ") << current_round << " of " << max_rounds << OBFSTR(")\n\n");

    ss << R"(You have received the results of your previous tool calls above.
Analyze them carefully. Based on these results, you MUST do one of the following:

**OPTION A — Call more tools:** If you need MORE information to fully answer the user's request,
emit another tool_calls JSON block. Follow up on leads from the previous results:
- Decompile functions you discovered in call chains
- Trace xrefs to structures you identified
- Read memory at addresses you found
- Rename/comment things you've now identified
Do NOT re-call tools with the same parameters — those results are already above.

**OPTION B — Write your final answer:** If you have gathered ALL the information needed to
comprehensively answer the user's request, write your complete analysis as plain text.
Your final answer must be thorough, cite specific addresses and data from the tool results,
and address EVERY part of the user's original request. Do NOT include any tool_calls JSON.

IMPORTANT: Do NOT write "I need to check X" or "Let me investigate Y" as text — instead,
just emit the tool_calls to actually DO IT. Action, not narration.
)";

    return ss.str();
}

struct tool_exec_request_t : public exec_request_t
{
    std::string tool_name;
    json params;
    tool_execution_t result;

    ssize_t idaapi execute() override
    {
        auto& registry = agent_tools::ToolRegistry::instance();
        result.tool_name = tool_name;
        result.params = params;

        try
        {
            auto tool_result = registry.execute_tool(tool_name, params);
            result.success = tool_result.success;
            result.message = sanitize_utf8(tool_result.output);
            result.data = tool_result.data;
            sanitize_json_utf8_inplace(result.data);
        }
        catch (const std::exception& e)
        {
            result.success = false;
            result.message = sanitize_utf8(std::string("Exception: ") + e.what());
            result.data = json::object();
        }

        return 0;
    }
};

result_t run(
    AIClient* client,
    const std::string& initial_prompt,
    const config_t& config,
    std::atomic<bool>* cancelled,
    progress_fn on_progress,
    status_fn on_status,
    stream_fn on_stream)
{
    result_t result;
    std::unordered_map<std::string, tool_execution_t> tool_cache;

    client->set_max_output_tokens(config.agentic_output_tokens);

    if (cancelled && cancelled->load())
    {
        result.was_cancelled = true;
        result.final_response = OBFSTR("Operation cancelled by user.");
        client->set_max_output_tokens(16384);
        return result;
    }

    const int max_rounds = config.max_rounds > 0 ? config.max_rounds : 25;

    auto stop_predicate = [](const std::string& accumulated) -> bool
    {
        size_t tc_pos = accumulated.find("\"tool_calls\"");
        if (tc_pos == std::string::npos)
            return false;

        size_t brace_start = std::string::npos;
        for (size_t i = tc_pos; i > 0; --i)
        {
            if (accumulated[i - 1] == '{')
            {
                brace_start = i - 1;
                break;
            }
        }
        if (brace_start == std::string::npos)
            return false;

        std::string json_block = extract_json_by_bracket_match(accumulated, brace_start);
        if (json_block.empty())
            return false;

        try
        {
            auto j = json::parse(json_block);
            if (j.contains("tool_calls") && j["tool_calls"].is_array()
                && !j["tool_calls"].empty())
                return true;
        }
        catch (const json::parse_error&) {}

        return false;
    };

    std::vector<std::pair<std::string, std::vector<tool_execution_t>>> all_round_results;
    std::string current_prompt = initial_prompt;
    std::string last_ai_response;
    std::string last_reasoning;
    bool finished = false;

    for (int current_round = 1; current_round <= max_rounds && !finished; ++current_round)
    {
        if (cancelled && cancelled->load())
        {
            result.was_cancelled = true;
            result.final_response = OBFSTR("Operation cancelled by user.");
            break;
        }

        if (current_round > 1 && on_status)
        {
            status_update_t status;
            status.type = status_type_t::new_round;
            status.round = current_round;
            status.message = OBFSTR("Round ") + std::to_string(current_round)
                + OBFSTR(" of ") + std::to_string(max_rounds);
            on_status(status);
        }

        if (on_progress)
            on_progress(current_round, OBFSTR("Calling AI (round ")
                + std::to_string(current_round) + OBFSTR(")..."));

        if (on_status)
        {
            status_update_t status;
            status.type = status_type_t::calling_ai;
            status.round = current_round;
            status.message = OBFSTR("Calling AI (round ")
                + std::to_string(current_round) + OBFSTR(")...");
            on_status(status);
        }

        if (config.verbose_logging)
            msg(OBFSTR_C("AiDA Agent: Calling AI (round %d/%d)...\n"), current_round, max_rounds);

        std::string ai_response = client->streaming_blocking_generate(
            current_prompt, config.temperature, on_stream, stop_predicate);

        if (ai_response.substr(0, 6) == "Error:")
        {
            result.final_response = ai_response;
            break;
        }

        if (cancelled && cancelled->load())
        {
            result.was_cancelled = true;
            result.final_response = OBFSTR("Operation cancelled by user.");
            break;
        }

        {
            static const std::string TRUNC_MARKER = OBFSTR("\n\n[RESPONSE_TRUNCATED]");
            size_t trunc_pos = ai_response.rfind(TRUNC_MARKER);
            if (trunc_pos != std::string::npos)
            {
                ai_response = ai_response.substr(0, trunc_pos);
                if (config.verbose_logging)
                    msg(OBFSTR_C("AiDA Agent: Response was truncated by API.\n"));
            }
        }

        last_ai_response = ai_response;

        if (!has_tool_calls(ai_response))
        {
            std::string cleaned = strip_tool_artifacts(ai_response);
            result.final_response = cleaned.empty() ? ai_response : cleaned;

            if (config.verbose_logging)
                msg(OBFSTR_C("AiDA Agent: Round %d — final answer (no tool calls).\n"), current_round);

            finished = true;
            break;
        }

        json parsed = extract_tool_calls(ai_response);
        if (!parsed.contains(OBFSTR_C("tool_calls")) || parsed[OBFSTR_C("tool_calls")].empty())
        {
            std::string cleaned = strip_tool_artifacts(ai_response);
            result.final_response = cleaned.empty()
                ? OBFSTR("The AI agent's response could not be parsed. Please try again.")
                : cleaned;

            if (config.verbose_logging)
                msg(OBFSTR_C("AiDA Agent: Round %d — tool call parse failed, using cleaned response.\n"), current_round);

            finished = true;
            break;
        }

        std::string reasoning = json_str(parsed, "reasoning");
        last_reasoning = reasoning;

        std::vector<std::string> pending_tool_names;
        for (const auto& tc : parsed[OBFSTR_C("tool_calls")])
            pending_tool_names.push_back(json_str(tc, "tool", "?"));

        if (on_status)
        {
            status_update_t status;
            status.type = status_type_t::thinking;
            status.round = current_round;
            status.reasoning = reasoning;
            status.pending_tools = pending_tool_names;
            status.message = OBFSTR("Round ") + std::to_string(current_round) + OBFSTR(": ")
                + (reasoning.empty() ? OBFSTR("(no reasoning provided)") : reasoning);
            on_status(status);
        }

        size_t num_calls = parsed[OBFSTR_C("tool_calls")].size();

        if (config.verbose_logging)
        {
            msg(OBFSTR_C("AiDA Agent: Round %d — AI requested %zu tool call(s): %s\n"),
                current_round, num_calls, reasoning.c_str());
            for (const auto& tc : parsed[OBFSTR_C("tool_calls")])
                msg(OBFSTR_C("  \xe2\x86\x92 %s\n"), json_str(tc, "tool", "?").c_str());
        }

        if (on_progress)
            on_progress(current_round, OBFSTR("Round ") + std::to_string(current_round)
                + OBFSTR(": Executing ") + std::to_string(num_calls) + OBFSTR(" tool(s)..."));

        std::vector<tool_execution_t> round_tool_results;

        for (size_t tool_idx = 0; tool_idx < num_calls; ++tool_idx)
        {
            if (cancelled && cancelled->load())
                break;

            const auto& tc = parsed[OBFSTR_C("tool_calls")][tool_idx];
            if (!tc.contains(OBFSTR_C("tool")) || !tc[OBFSTR_C("tool")].is_string())
                continue;

            std::string tool_name = tc[OBFSTR_C("tool")].get<std::string>();
            json params = tc.contains(OBFSTR_C("params")) && !tc[OBFSTR_C("params")].is_null()
                ? tc[OBFSTR_C("params")] : json::object();

            auto& registry = agent_tools::ToolRegistry::instance();
            const auto* tool_def = registry.get_tool(tool_name);

            std::string cache_key = tool_name + "|" + params.dump(-1, ' ', false, json::error_handler_t::replace);
            if (tool_def && tool_def->read_only)
            {
                auto cache_it = tool_cache.find(cache_key);
                if (cache_it != tool_cache.end())
                {
                    if (config.verbose_logging)
                        msg(OBFSTR_C("AiDA Agent: Skipping duplicate tool call: %s (cached)\n"), tool_name.c_str());

                    round_tool_results.push_back(cache_it->second);

                    if (on_status)
                    {
                        status_update_t status;
                        status.type = status_type_t::tool_complete;
                        status.round = current_round;
                        status.tool_name = cache_it->second.tool_name;
                        status.tool_success = cache_it->second.success;
                        status.message = cache_it->second.message + OBFSTR(" (cached)");
                        on_status(status);
                    }
                    continue;
                }
            }

            if (on_status)
            {
                status_update_t status;
                status.type = status_type_t::executing_tool;
                status.round = current_round;
                status.tool_name = tool_name;
                status.message = OBFSTR("Executing: ") + tool_name;
                status.pending_tools = pending_tool_names;
                on_status(status);
            }

            tool_exec_request_t exec_req;
            exec_req.tool_name = tool_name;
            exec_req.params = params;

            int mff_flag = (tool_def && tool_def->read_only) ? MFF_READ : MFF_WRITE;

            execute_sync(exec_req, mff_flag);

            if (tool_def && tool_def->read_only && exec_req.result.success)
                tool_cache[cache_key] = exec_req.result;

            if (on_status)
            {
                status_update_t status;
                status.type = status_type_t::tool_complete;
                status.round = current_round;
                status.tool_name = exec_req.result.tool_name;
                status.tool_success = exec_req.result.success;
                status.message = exec_req.result.message;
                on_status(status);
            }

            round_tool_results.push_back(std::move(exec_req.result));
        }

        for (auto& tr : round_tool_results)
        {
            if (tr.tool_name != OBFSTR_C("driver_defer_action"))
                continue;
            if (!tr.success || !tr.data.contains("action_id"))
                continue;

            int action_id = tr.data["action_id"].get<int>();

            if (config.verbose_logging)
                msg(OBFSTR_C("AiDA Agent: Waiting for deferred action #%d to complete...\n"), action_id);

            if (on_status)
            {
                status_update_t status;
                status.type = status_type_t::executing_tool;
                status.round = current_round;
                status.tool_name = OBFSTR("driver_defer_action");
                status.message = OBFSTR("Waiting for deferred action #") + std::to_string(action_id)
                    + OBFSTR(" (target: ") + tr.data.value("target", "?") + OBFSTR(")...");
                on_status(status);
            }

            if (on_progress)
                on_progress(current_round, OBFSTR("Waiting for deferred action #") + std::to_string(action_id) + "...");

            auto wait_start = std::chrono::steady_clock::now();

            while (true)
            {
                if (cancelled && cancelled->load())
                {
                    agent_tools::driver_tools::DeferredActionManager::instance().cancel_action(action_id);
                    break;
                }

                const auto* action = agent_tools::driver_tools::DeferredActionManager::instance().get_action(action_id);
                if (!action)
                    break;

                auto st = action->status.load();
                if (st == agent_tools::driver_tools::deferred_status::completed
                    || st == agent_tools::driver_tools::deferred_status::failed
                    || st == agent_tools::driver_tools::deferred_status::timed_out
                    || st == agent_tools::driver_tools::deferred_status::cancelled)
                {
                    json deferred_results = json::object();
                    deferred_results["action_id"] = action_id;
                    deferred_results["final_status"] = (st == agent_tools::driver_tools::deferred_status::completed) ? "completed"
                        : (st == agent_tools::driver_tools::deferred_status::failed) ? "failed"
                        : (st == agent_tools::driver_tools::deferred_status::timed_out) ? "timed_out"
                        : "cancelled";

                    if (!action->trigger_info.empty())
                    {
                        try { deferred_results["trigger_info"] = json::parse(action->trigger_info); }
                        catch (...) { deferred_results["trigger_info"] = action->trigger_info; }
                    }

                    if (!action->error.empty())
                        deferred_results["error"] = action->error;

                    json results_arr = json::array();
                    int succeeded = 0;
                    for (const auto& r : action->results)
                    {
                        json rj;
                        rj["tool"] = r.action_type;
                        rj["success"] = r.success;
                        rj["message"] = r.message;
                        if (!r.data.is_null() && !r.data.empty())
                            rj["data"] = r.data;
                        results_arr.push_back(rj);
                        if (r.success) succeeded++;
                    }
                    deferred_results["tool_results"] = results_arr;
                    deferred_results["succeeded"] = succeeded;
                    deferred_results["failed"] = static_cast<int>(action->results.size()) - succeeded;

                    tr.data["deferred_results"] = deferred_results;
                    tr.success = (st == agent_tools::driver_tools::deferred_status::completed);
                    tr.message = OBFSTR("Deferred action #") + std::to_string(action_id) + OBFSTR(": ")
                        + deferred_results["final_status"].get<std::string>()
                        + OBFSTR(" (") + std::to_string(succeeded) + "/" + std::to_string(action->results.size())
                        + OBFSTR(" tools succeeded)");

                    if (config.verbose_logging)
                        msg(OBFSTR_C("AiDA Agent: Deferred action #%d %s.\n"), action_id,
                            deferred_results["final_status"].get<std::string>().c_str());

                    if (on_status)
                    {
                        status_update_t status;
                        status.type = status_type_t::tool_complete;
                        status.round = current_round;
                        status.tool_name = OBFSTR("driver_defer_action");
                        status.tool_success = tr.success;
                        status.message = tr.message;
                        on_status(status);
                    }
                    break;
                }

                auto elapsed = std::chrono::steady_clock::now() - wait_start;
                auto elapsed_secs = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();

                if (elapsed_secs % 10 == 0 && elapsed_secs > 0)
                {
                    if (on_status)
                    {
                        status_update_t status;
                        status.type = status_type_t::executing_tool;
                        status.round = current_round;
                        status.tool_name = OBFSTR("driver_defer_action");
                        status.message = OBFSTR("Still waiting for deferred action #")
                            + std::to_string(action_id) + OBFSTR(" (")
                            + std::to_string(elapsed_secs) + OBFSTR("s elapsed)...");
                        on_status(status);
                    }
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }

        if (config.verbose_logging)
        {
            msg(OBFSTR_C("AiDA Agent: Round %d — %zu tool(s) executed:\n"), current_round, round_tool_results.size());
            for (const auto& r : round_tool_results)
            {
                msg(OBFSTR_C("  \xe2\x86\x90 %s: %s \xe2\x80\x94 %s\n"), r.tool_name.c_str(),
                    r.success ? OBFSTR_C("OK") : OBFSTR_C("FAIL"), r.message.c_str());
            }
        }

        for (auto& tr : round_tool_results)
            result.tool_results.push_back(tr);

        all_round_results.push_back({reasoning, std::move(round_tool_results)});

        if (current_round < max_rounds)
        {
            current_prompt = build_continuation_prompt(
                initial_prompt, all_round_results,
                static_cast<size_t>(config.max_tool_result_chars),
                current_round + 1, max_rounds);


            context_manager::config_t ctx_cfg;
            ctx_cfg.max_context_tokens = config.max_context_tokens;
            ctx_cfg.output_reserve     = config.output_token_reserve;
            context_manager::ContextWindowManager ctx_mgr(ctx_cfg);

            size_t prompt_tokens = ctx_mgr.estimate_tokens(current_prompt);
            size_t budget = static_cast<size_t>(ctx_cfg.max_context_tokens - ctx_cfg.output_reserve);
            if (prompt_tokens > budget)
            {
                if (config.verbose_logging)
                    msg(OBFSTR_C("AiDA Agent: Context window pressure (%zu tokens > %zu budget), trimming older rounds...\n"),
                        prompt_tokens, budget);


                while (all_round_results.size() > 2 && prompt_tokens > budget)
                {
                    all_round_results.erase(all_round_results.begin());
                    current_prompt = build_continuation_prompt(
                        initial_prompt, all_round_results,
                        static_cast<size_t>(config.max_tool_result_chars),
                        current_round + 1, max_rounds);
                    prompt_tokens = ctx_mgr.estimate_tokens(current_prompt);
                }


                if (prompt_tokens > budget)
                    current_prompt = ctx_mgr.fit_to_budget(current_prompt, budget);
            }
        }
    }

    if (!finished && !result.was_cancelled && result.final_response.empty())
    {
        if (config.verbose_logging)
            msg(OBFSTR_C("AiDA Agent: Max rounds (%d) reached, forcing synthesis...\n"), max_rounds);

        if (on_progress)
            on_progress(max_rounds + 1, OBFSTR("Synthesizing final response..."));

        if (on_status)
        {
            status_update_t status;
            status.type = status_type_t::new_round;
            status.round = max_rounds + 1;
            status.message = OBFSTR("Synthesizing final response...");
            on_status(status);
        }

        if (on_status)
        {
            status_update_t status;
            status.type = status_type_t::calling_ai;
            status.round = max_rounds + 1;
            status.message = OBFSTR("Synthesizing final response from all tool results...");
            on_status(status);
        }

        std::string planning_reasoning = last_reasoning;
        std::string cleaned_pre_text = strip_tool_artifacts(last_ai_response);
        if (!cleaned_pre_text.empty())
            planning_reasoning = cleaned_pre_text;

        std::string synthesis_prompt = build_synthesis_prompt(
            config.user_message, config.context_block, config.chat_history,
            planning_reasoning, result.tool_results,
            static_cast<size_t>(config.max_tool_result_chars));

        client->set_max_output_tokens(config.synthesis_output_tokens);

        std::string synthesis_response = client->streaming_blocking_generate(
            synthesis_prompt, config.temperature, on_stream, nullptr);

        if (cancelled && cancelled->load())
        {
            result.was_cancelled = true;
            result.final_response = OBFSTR("Operation cancelled by user.");
        }
        else if (synthesis_response.substr(0, 6) == "Error:")
        {
            if (config.verbose_logging)
                msg(OBFSTR_C("AiDA Agent: Synthesis call failed: %s\n"), synthesis_response.c_str());

            std::string fallback = strip_tool_artifacts(last_ai_response);
            result.final_response = fallback.empty() ? last_reasoning : fallback;
            if (result.final_response.empty())
                result.final_response = OBFSTR("Tool execution complete but synthesis failed. See agent actions above for results.");
        }
        else
        {
            std::string cleaned_synthesis = strip_tool_artifacts(synthesis_response);
            result.final_response = cleaned_synthesis.empty() ? synthesis_response : cleaned_synthesis;

            if (config.verbose_logging)
                msg(OBFSTR_C("AiDA Agent: Synthesis complete (%zu chars).\n"), result.final_response.size());
        }
    }

    if (result.final_response.empty() && !result.was_cancelled)
    {
        result.final_response = OBFSTR("Tool execution complete. See agent actions above for results.");
    }

    if (config.verbose_logging)
        msg(OBFSTR_C("AiDA Agent: Agent cycle complete. %d round(s), %zu total tool(s) executed.\n"),
            static_cast<int>(all_round_results.size()), result.tool_results.size());

    client->set_max_output_tokens(16384);

    return result;
}

}
