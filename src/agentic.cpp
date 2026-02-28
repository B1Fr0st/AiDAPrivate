#include "aida_pro.hpp"

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
    static const std::regex md_json_re("```(?:json)?\\s*([\\s\\S]*?)\\s*```");
    std::smatch match;
    if (std::regex_search(response, match, md_json_re) && match.size() > 1)
    {
        std::string code_block = match[1].str();
        try
        {
            json j = json::parse(code_block);
            if (j.contains(OBFSTR_C("tool_calls")) && j[OBFSTR_C("tool_calls")].is_array())
                return j;
        }
        catch (const json::parse_error&) {}
    }

    size_t tc_pos = response.find("\"tool_calls\"");
    if (tc_pos != std::string::npos)
    {
        size_t brace_start = std::string::npos;
        for (size_t i = tc_pos; i > 0; --i)
        {
            if (response[i - 1] == '{')
            {
                brace_start = i - 1;
                break;
            }
        }

        if (brace_start != std::string::npos)
        {
            std::string json_block = extract_json_by_bracket_match(response, brace_start);
            if (!json_block.empty())
            {
                try
                {
                    json j = json::parse(json_block);
                    if (j.contains(OBFSTR_C("tool_calls")) && j[OBFSTR_C("tool_calls")].is_array())
                        return j;
                }
                catch (const json::parse_error&) {}
            }
        }
    }

    try
    {
        json j = json::parse(response);
        if (j.contains(OBFSTR_C("tool_calls")) && j[OBFSTR_C("tool_calls")].is_array())
            return j;
    }
    catch (const json::parse_error&) {}

    return json::object();
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
            std::string data_str = json_dump_fast(r.data);
            if (data_str.length() > max_chars_per_result)
                data_str = data_str.substr(0, max_chars_per_result) + OBFSTR("\n... (truncated, ") + std::to_string(data_str.length()) + OBFSTR(" bytes total)");
            ss << OBFSTR("Data: ") << data_str << "\n";
        }
        ss << "\n";
    }
    
    ss << OBFSTR("[End Tool Results]\n");
    return ss.str();
}

std::string summarize_turn(const conversation_turn_t& turn)
{
    std::ostringstream ss;
    ss << OBFSTR("[Compacted Iteration Summary]\n");

    std::string reasoning = turn.ai_response;
    if (reasoning.size() > 300)
        reasoning = reasoning.substr(0, 300) + "...";
    ss << OBFSTR("AI reasoning: ") << reasoning << "\n";

    for (const auto& tr : turn.tool_results)
    {
        ss << "- " << tr.tool_name << ": "
           << (tr.success ? "OK" : "FAIL") << " — " << tr.message;
        if (!tr.data.is_null() && !tr.data.empty())
        {
            if (tr.data.is_array())
            {
                ss << " (" << tr.data.size() << " items";
                if (tr.data.size() > 0 && tr.data[0].is_object())
                {
                    std::string preview = json_dump_safe(tr.data[0]);
                    if (preview.size() > 150) preview = preview.substr(0, 150) + "...";
                    ss << ", first: " << preview;
                }
                ss << ")";
            }
            else if (tr.data.is_object())
            {
                int count = 0;
                for (auto it = tr.data.begin(); it != tr.data.end() && count < 6; ++it, ++count)
                {
                    std::string val;
                    if (it.value().is_string())
                        val = it.value().get<std::string>();
                    else
                        val = json_dump_safe(it.value());
                    if (val.size() > 120) val = val.substr(0, 120) + "...";
                    ss << "\n    " << it.key() << ": " << val;
                }
                if (static_cast<int>(tr.data.size()) > 6)
                    ss << "\n    ... and " << (tr.data.size() - 6) << " more fields";
            }
        }
        ss << "\n";
    }
    ss << OBFSTR("[End Summary]\n");
    return ss.str();
}

static bool looks_incomplete(const std::string& text)
{
    static const char* const markers[] = {
        "Next Steps", "next steps", "Next steps",
        "next phase", "Next Phase", "Next phase",
        "future work", "Future Work", "Future work",
        "further analysis", "Further analysis", "Further Analysis",
        "remains to be", "remaining work", "Remaining Work",
        "I plan to", "I will now", "I would recommend",
        "should focus on", "could not be completed", "was not completed",
        "### Next", "## Next", "**Next Steps",
        "additional investigation", "Additional investigation",
        "need to investigate", "needs further",
        "haven't yet", "have not yet"
    };
    for (const auto& marker : markers)
    {
        if (text.find(marker) != std::string::npos)
            return true;
    }
    return false;
}

std::string build_conversation(
    const std::string& initial_prompt,
    const std::vector<conversation_turn_t>& turns,
    size_t max_chars_per_result)
{
    std::string conversation;
    conversation.reserve(initial_prompt.size() + turns.size() * 8192 + 4096);
    conversation = initial_prompt;

    for (size_t turn_idx = 0; turn_idx < turns.size(); ++turn_idx)
    {
        const auto& turn = turns[turn_idx];
        bool is_last_turn = (turn_idx == turns.size() - 1);
        int turn_number = static_cast<int>(turn_idx) + 1;

        if (turn.compacted)
        {
            conversation += "\n\n" + turn.compact_summary;
        }
        else
        {
            json parsed = extract_tool_calls(turn.ai_response);
            std::string reasoning = json_str(parsed, "reasoning");

            if (turn.tool_results.empty())
            {
                conversation += OBFSTR("\n\n[Assistant attempted to provide a final answer prematurely]\n");
                conversation += turn.ai_response;
                conversation += OBFSTR("\n\n[REJECTED] Premature answer — re-read user request, check each objective. "
                                "If ANY unresolved, emit tool_calls now. No summaries. EMIT TOOL CALLS.");
            }
            else
            {
                conversation += OBFSTR("\n\n[Assistant Action]\n");
                if (!reasoning.empty())
                    conversation += OBFSTR("Reasoning: ") + reasoning + "\n";

                conversation += OBFSTR("Tools called: ");
                for (size_t i = 0; i < turn.tool_results.size(); ++i)
                {
                    if (i > 0) conversation += ", ";
                    conversation += turn.tool_results[i].tool_name;
                }
                conversation += "\n\n";

                conversation += format_tool_results(turn.tool_results, max_chars_per_result);

                if (is_last_turn)
                {
                    conversation += OBFSTR("\n\n[ITER ") + std::to_string(turn_number)
                        + OBFSTR("] Emit tool_calls JSON now. Batch 5-10 calls min. "
                          "Decompile, trace xrefs, follow pointers, apply renames/types. "
                          "Final answer ONLY when ALL user objectives verified.");

                    if (turn_number <= 3)
                        conversation += OBFSTR(" [EARLY — need 8-15+ iters, keep going]");
                    else if (turn_number <= 6)
                        conversation += OBFSTR(" [MID — re-check all user objectives]");
                }
                else
                {
                    conversation += OBFSTR("\n\n[Continue — emit more tool_calls]");
                }
            }
        }
    }

    return conversation;
}

bool compact_if_needed(
    const std::string& initial_prompt,
    std::vector<conversation_turn_t>& turns,
    const config_t& config)
{
    int budget_i = config.max_context_tokens - config.output_token_reserve;
    if (budget_i < 1024)
        budget_i = 1024;
    size_t budget = static_cast<size_t>(budget_i);

    std::string full = build_conversation(initial_prompt, turns,
        static_cast<size_t>(config.max_tool_result_chars));
    size_t estimated = estimate_tokens(full);

    if (estimated <= budget)
        return false;

    if (config.verbose_logging)
        msg(OBFSTR_C("AiDA Agent: Context size ~%zu tokens exceeds budget ~%zu, compacting...\n"),
            estimated, budget);

    int keep_start = std::max(0, static_cast<int>(turns.size()) - config.compact_keep_turns);

    bool compacted_any = false;
    for (int i = 0; i < keep_start; ++i)
    {
        if (turns[i].compacted)
            continue;
        turns[i].compact_summary = summarize_turn(turns[i]);
        turns[i].compacted = true;
        compacted_any = true;
    }

    if (!compacted_any)
        return false;

    full = build_conversation(initial_prompt, turns,
        static_cast<size_t>(config.max_tool_result_chars));
    estimated = estimate_tokens(full);

    if (estimated > budget)
    {
        size_t reduced_limit = static_cast<size_t>(config.max_tool_result_chars) / 2;
        if (reduced_limit < 512) reduced_limit = 512;

        full = build_conversation(initial_prompt, turns, reduced_limit);
        estimated = estimate_tokens(full);

        if (estimated > budget)
        {
            for (auto& turn : turns)
            {
                if (!turn.compacted)
                {
                    turn.compact_summary = summarize_turn(turn);
                    turn.compacted = true;
                }
            }
        }
    }

    if (config.verbose_logging)
    {
        full = build_conversation(initial_prompt, turns,
            static_cast<size_t>(config.max_tool_result_chars));
        estimated = estimate_tokens(full);
        msg(OBFSTR_C("AiDA Agent: After compaction: ~%zu tokens\n"), estimated);
    }

    return true;
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
interpretation. Batch these calls efficiently — do NOT waste multiple iterations on them.
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

**RULE 2: NEVER STOP BEFORE THE JOB IS DONE.**
You have up to 25 iterations. Use them ALL if needed. If you have used fewer than 8 iterations,
you have almost certainly NOT done enough work. The user is paying for thorough, exhaustive
analysis. Surface-level results are unacceptable. If you found interesting offsets, pointers,
or functions — you MUST decompile and trace them IN THIS SESSION, not describe them for later.

**RULE 3: ALWAYS BATCH 5-10 TOOL CALLS PER TURN.**
Every time you emit tool_calls, include 5-10 calls. For example, if you found 5 interesting
callees, decompile ALL 5 in one turn. If you need to check xrefs for 4 addresses, batch them.
Single tool calls per turn are wasteful and lazy. Maximize throughput.

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

CRITICAL: Include 5-10 tool calls per turn. Batch aggressively.

When you have gathered ALL necessary information and completed ALL requested actions,
respond with plain text (NO JSON wrapping, no tool_calls key). Your plain text final
answer must be detailed, structured, and contain every finding with specific addresses.

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

### Phase 1: Reconnaissance (batch 6-8 calls in ONE turn)
`get_binary_info`, `decompile_function`, `get_callers`, `get_callees`, `search_strings`

### Phase 2: Deep Exploration (5-10 calls each turn)
Decompile every significant function, trace xrefs, use `build_call_graph` depth 3+,
`find_immediate` for offsets, `get_struct`/`search_structs` for data structures.

### Phase 3: Action (DO, don't describe)
`batch_rename` for bulk, `rename_function`/`rename_variable`/`rename_address` for targeted,
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

**Kernel Module to IDB — UNIVERSAL Analysis Pipeline (requires driver):**
`driver_kernel_dump_module` — complete dump-and-analyze workflow for ANY kernel driver.
Finds module → reads ALL sections from LIVE kernel memory → creates IDA segments →
patches runtime bytes into database → runs FULL 6-STEP ANALYSIS PIPELINE:
  Step 1: Initial IDA auto-analysis pass
  Step 2: PE export/entry point parsing — creates functions at all exports + DriverEntry
  Step 3: Linear sweep code creation — forces disassembly across all executable sections
          (automatically SKIPS high-entropy sections like BattlEye .be0 VM bytecode)
  Step 4: Aggressive 18-pattern x64 function prologue scanning with 3-instruction validation
  Step 5: CALL/JMP xref target function creation — catches non-standard prologues
  Step 6: Final auto-analysis pass

Returns detailed statistics: initial vs final function count, exports created, code coverage,
prologue functions found, xref functions created.

Works on ANY kernel driver: BattlEye (BEDaisy.sys), EasyAntiCheat (EasyAntiCheat.sys),
Vanguard (vgk.sys), ACE, ntkrnlmp.exe, etc. ALWAYS use this tool for kernel module analysis.

**Kernel Driver Dump Workflow (EAC/BattlEye/Vanguard/ANY):**
1. `driver_connect` — connects driver, solves kernel DTB automatically
2. `driver_enumerate_kernel_modules` filter="EasyAntiCheat" → finds base+size
3. `driver_kernel_dump_module` module="EasyAntiCheat.sys" → full dump + 6-step analysis
   AUTOMATICALLY discovers hundreds of functions, parses exports, creates code regions.
   Reports before/after stats like "Functions: 3 → 847". No manual recovery needed.
4. Optionally also save to disk: output_path="C:\\dumps\\eac_live.sys"
5. Use `list_functions` limit=0 to review all discovered functions
6. Decompile key functions for quality check
7. If more functions needed: use Phase 9 advanced tools for targeted recovery

**Reading Specific Kernel Structures:**
1. `driver_enumerate_kernel_modules` filter="ntoskrnl" → get ntos base
2. `driver_read_kernel_memory` address="<base+offset>" size=256 → read any kernel data
3. Can inspect SSDT, object tables, callback arrays, anything in kernel space

### Phase 9: Advanced Binary Recovery — Targeted Second-Pass Analysis
NOTE: `driver_kernel_dump_module` already runs the full 6-step analysis pipeline automatically.
Phase 9 tools are for TARGETED SECOND-PASS recovery when the automatic pipeline isn't enough,
or for analyzing non-kernel binaries (usermode dumps, unpacked executables, etc.).

When IDA auto-analysis produces poor results (few functions, mostly unexplored bytes, missing
imports), use these ADVANCED ANALYSIS tools on any binary where standard analysis fails.

**Use `deep_analysis_sweep` for non-kernel binaries that need full recovery.** It runs the full
5-step pipeline automatically:
1. PE header parsing (creates segments, exports, entry point)
2. Force code creation (linear sweep all executable segments)
3. Aggressive prologue scanning (18+ x64 patterns with instruction validation)
4. Deep import reconstruction (all segments, kernel APIs, named resolution)
5. Final auto-analysis pass

**Individual tools for targeted recovery:**
- `aggressive_function_discovery` — Scans for 18+ x64 function prologue patterns:
  push rbp/mov rbp,rsp, sub rsp, MS x64 ABI saves (mov [rsp+8],rcx), REX-prefixed
  pushes, mov rax,rsp/sub rsp (kernel-style), register save pairs. Validates each
  candidate by decoding 3+ subsequent instructions. Use when IDA finds <10 functions
  in a large code section.

- `force_create_code_region` — Linear sweep disassembly across a region. Forces creation
  of instructions where IDA left unexplored bytes. Detects function boundaries from
  INT3 padding and RET instructions. Use on large unexplored regions in dumped modules.

- `deep_reconstruct_imports` — Scans ALL segments (not just .idata) for IAT entries.
  Resolves kernel imports (Ke/Ex/Mm/Ps/Zw/Ob/Io/Rtl APIs), propagates __imp_ names,
  identifies MmGetSystemRoutineAddress dynamic resolution patterns, finds call thunks.
  Use when reconstruct_imports from deobfuscation_tools returns 0 results.

- `analyze_pe_header` — Parses PE header at any address in the IDB. Extracts sections
  with permissions, export directory, import directory, entry point. Creates functions
  at all exports. Essential when IDA's loader didn't parse the PE (dumped modules).

- `create_functions_from_xrefs` — Finds all CALL/JMP targets in existing code that
  aren't defined as functions and creates them. Catches non-standard prologues that
  the prologue scanner misses. Run AFTER force_create_code_region.

- `signature_scan_and_define` — User-defined byte patterns with ?? wildcards.
  Scan the database for a specific pattern and create functions at every match.
  Use when you identify a protector-specific function prologue pattern.

**Recovery workflow for heavily protected binaries:**
1. `deep_analysis_sweep` with default options → check before/after function counts
2. If still < 100 functions: `force_create_code_region` on each large unexplored area
3. `create_functions_from_xrefs` to catch remaining call targets
4. `signature_scan_and_define` if protector uses identifiable patterns
5. `deep_reconstruct_imports` to resolve remaining import gaps
6. Use `list_functions` with limit=0 to verify the final function count
7. Decompile key functions to check quality

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
    std::vector<conversation_turn_t> turns;
    int compact_retry_count = 0;
    size_t dynamic_tool_result_chars = static_cast<size_t>(config.max_tool_result_chars);

    client->set_max_output_tokens(config.agentic_output_tokens);

    for (int iter = 0; iter < config.max_iterations; iter++)
    {
        if (cancelled && cancelled->load())
        {
            result.was_cancelled = true;
            result.final_response = OBFSTR("Operation cancelled by user.");
            break;
        }

        if (on_progress)
            on_progress(iter + 1, OBFSTR("Calling AI (iteration ") + std::to_string(iter + 1) + ")...");
        
        if (on_status)
        {
            status_update_t status;
            status.type = status_type_t::calling_ai;
            status.iteration = iter + 1;
            status.message = OBFSTR("Calling AI (iteration ") + std::to_string(iter + 1) + ")...";
            status.reasoning = status.message;
            on_status(status);
        }

        if (config.verbose_logging)
            msg(OBFSTR_C("AiDA Agent: Iteration %d/%d — calling AI...\n"), iter + 1, config.max_iterations);

        compact_if_needed(initial_prompt, turns, config);

        std::string conversation = build_conversation(initial_prompt, turns, dynamic_tool_result_chars);

        size_t estimated_tokens = estimate_tokens(conversation);
        int token_budget_i = config.max_context_tokens - config.output_token_reserve;
        if (token_budget_i < 1024)
            token_budget_i = 1024;
        size_t token_budget = static_cast<size_t>(token_budget_i);

        if (estimated_tokens > token_budget * 95 / 100)
        {
            conversation += OBFSTR("\n\n[SYSTEM OVERRIDE — CONTEXT LIMIT] You are at the context length limit. "
                           "You MUST provide your final answer RIGHT NOW as plain text. Do NOT emit "
                           "tool_calls JSON. Synthesize ALL findings into a single detailed response. "
                           "Include: every address you found, every function you decompiled, every "
                           "struct offset you identified, every rename you performed. If you were asked "
                           "to DO something and haven't finished, state exactly what was done and what "
                           "remains with specific addresses. Be EXHAUSTIVE — this is your LAST chance to respond.");
        }

        if (iter == config.max_iterations - 1)
        {
            conversation += OBFSTR("\n\n[SYSTEM OVERRIDE — FINAL ITERATION] This is iteration ")
                           + std::to_string(iter + 1) + OBFSTR(" of ") + std::to_string(config.max_iterations) +
                           OBFSTR(". You have NO more tool calls available. Provide your COMPLETE final answer "
                           "as plain text NOW. Do NOT emit tool_calls JSON — it will be ignored. "
                           "Your answer must include: (1) every concrete finding with specific addresses, "
                           "(2) all actions you performed (renames, type changes, comments), "
                           "(3) reconstructed structs or data layouts if applicable, "
                           "(4) any remaining work that could not be completed, with exact addresses to check.");
        }

        std::string ai_response = client->streaming_blocking_generate(conversation, config.temperature, on_stream);

        if (ai_response.substr(0, 6) == "Error:")
        {
            result.final_response = ai_response;
            result.total_iterations = iter + 1;
            break;
        }

        if (cancelled && cancelled->load())
        {
            result.was_cancelled = true;
            result.final_response = OBFSTR("Operation cancelled by user.");
            break;
        }

        bool response_truncated = false;
        {
            static const std::string TRUNC_MARKER = OBFSTR("\n\n[RESPONSE_TRUNCATED]");
            size_t trunc_pos = ai_response.rfind(TRUNC_MARKER);
            if (trunc_pos != std::string::npos)
            {
                response_truncated = true;
                ai_response = ai_response.substr(0, trunc_pos);
                dynamic_tool_result_chars = std::max(static_cast<size_t>(512), dynamic_tool_result_chars / 2);
                for (auto& t : turns)
                {
                    if (!t.compacted)
                    {
                        t.compact_summary = summarize_turn(t);
                        t.compacted = true;
                    }
                }
                if (config.verbose_logging)
                    msg(OBFSTR_C("AiDA Agent: Response was truncated by API. Reducing context (tool_result_chars=%zu). Attempting recovery...\n"), dynamic_tool_result_chars);
            }
        }

        if (response_truncated)
        {
            if (has_tool_calls(ai_response))
            {
                json trunc_parsed = extract_tool_calls(ai_response);
                if (!trunc_parsed.contains(OBFSTR_C("tool_calls")) || trunc_parsed[OBFSTR_C("tool_calls")].empty())
                {
                    if (compact_retry_count < 2)
                    {
                        compact_retry_count++;
                        for (auto& t : turns)
                        {
                            if (!t.compacted)
                            {
                                t.compact_summary = summarize_turn(t);
                                t.compacted = true;
                            }
                        }
                        if (config.verbose_logging)
                            msg(OBFSTR_C("AiDA Agent: Incomplete tool call from truncation. Compact retry %d...\n"), compact_retry_count);
                        continue;
                    }
                }
            }

            if (!has_tool_calls(ai_response))
            {
                result.final_response = ai_response + OBFSTR("\n\n*(Response was truncated due to context length limit)*");
                result.total_iterations = iter + 1;
                if (config.verbose_logging)
                    msg(OBFSTR_C("AiDA Agent: Using truncated response as final answer.\n"));
                break;
            }
        }

        if (!has_tool_calls(ai_response))
        {
            result.final_response = strip_tool_artifacts(ai_response);
            if (result.final_response.empty())
                result.final_response = ai_response;

            bool has_incomplete_markers = looks_incomplete(result.final_response);
            bool is_premature = false;
            if (iter < 2 && result.final_response.size() < 2000)
                is_premature = true;
            else if (has_incomplete_markers && iter < config.max_iterations - 2)
                is_premature = true;

            if (is_premature && iter < config.max_iterations - 1)
            {
                if (config.verbose_logging)
                    msg(OBFSTR_C("AiDA Agent: Premature/incomplete answer detected at iteration %d (%zu chars, incomplete_markers=%d). Pushing AI to continue...\n"),
                        iter + 1, result.final_response.size(), has_incomplete_markers ? 1 : 0);

                conversation_turn_t push_turn;
                push_turn.ai_response = ai_response;
                push_turn.tool_results = {};
                turns.push_back(std::move(push_turn));
                result.final_response.clear();
                continue;
            }

            result.total_iterations = iter + 1;

            if (config.verbose_logging)
                msg(OBFSTR_C("AiDA Agent: Final answer received after %d iteration(s).\n"), iter + 1);
            break;
        }

        json parsed = extract_tool_calls(ai_response);
        if (!parsed.contains(OBFSTR_C("tool_calls")) || parsed[OBFSTR_C("tool_calls")].empty())
        {
            std::string cleaned = strip_tool_artifacts(ai_response);
            if (!cleaned.empty())
            {
                result.final_response = cleaned;
                result.total_iterations = iter + 1;
                if (config.verbose_logging)
                    msg(OBFSTR_C("AiDA Agent: Tool call parse failed, using cleaned response as final answer.\n"));
                break;
            }

            if (config.verbose_logging)
                msg(OBFSTR_C("AiDA Agent: Tool call parse failed and no clean text found. Forcing final answer...\n"));

            std::string force_prompt = conversation +
                OBFSTR("\n\n[SYSTEM OVERRIDE — PARSE ERROR] Your previous response was malformed. "
                "Respond ONLY with plain text — no JSON, no tool_calls. Provide your complete "
                "analysis including all addresses, findings, and actions performed so far.");

            std::string forced_response = client->blocking_generate(force_prompt, config.temperature);
            if (!forced_response.empty() && forced_response.substr(0, 6) != "Error:")
            {
                cleaned = strip_tool_artifacts(forced_response);
                if (!cleaned.empty() && !has_tool_calls(cleaned))
                {
                    result.final_response = cleaned;
                    result.total_iterations = iter + 1;
                    break;
                }
            }

            result.final_response = OBFSTR("The AI agent was unable to produce a final answer after ")
                + std::to_string(iter + 1) + OBFSTR(" iteration(s). Please try again with a more specific question.");
            result.total_iterations = iter + 1;
            break;
        }

        std::string reasoning = json_str(parsed, "reasoning");

        std::vector<std::string> pending_tool_names;
        for (const auto& tc : parsed[OBFSTR_C("tool_calls")])
        {
            pending_tool_names.push_back(json_str(tc, "tool", "?"));
        }

        if (on_status)
        {
            status_update_t status;
            status.type = status_type_t::thinking;
            status.iteration = iter + 1;
            status.reasoning = reasoning;
            status.pending_tools = pending_tool_names;
            status.message = OBFSTR("Reasoning: ") + (reasoning.empty() ? OBFSTR("(no reasoning provided)") : reasoning);
            on_status(status);
        }

        if (config.verbose_logging)
        {
            size_t num_calls = parsed[OBFSTR_C("tool_calls")].size();
            msg(OBFSTR_C("AiDA Agent: AI requested %zu tool call(s): %s\n"),
                num_calls, reasoning.c_str());
            for (const auto& tc : parsed[OBFSTR_C("tool_calls")])
            {
                std::string nm = json_str(tc, "tool", "?");
                msg(OBFSTR_C("  → %s\n"), nm.c_str());
            }
        }

        if (on_progress)
        {
            size_t num_calls = parsed[OBFSTR_C("tool_calls")].size();
            on_progress(iter + 1, OBFSTR("Executing ") + std::to_string(num_calls) + OBFSTR(" tool(s)..."));
        }

        std::vector<tool_execution_t> all_tool_results;

        for (size_t tool_idx = 0; tool_idx < parsed[OBFSTR_C("tool_calls")].size(); ++tool_idx)
        {
            if (cancelled && cancelled->load())
                break;

            const auto& tc = parsed[OBFSTR_C("tool_calls")][tool_idx];
            if (!tc.contains(OBFSTR_C("tool")) || !tc[OBFSTR_C("tool")].is_string())
                continue;

            std::string tool_name = tc[OBFSTR_C("tool")].get<std::string>();
            json params = tc.contains(OBFSTR_C("params")) && !tc[OBFSTR_C("params")].is_null() ? tc[OBFSTR_C("params")] : json::object();

            if (on_status)
            {
                status_update_t status;
                status.type = status_type_t::executing_tool;
                status.iteration = iter + 1;
                status.tool_name = tool_name;
                status.message = OBFSTR("Executing: ") + tool_name;
                status.pending_tools = pending_tool_names;
                on_status(status);
            }

            tool_exec_request_t exec_req;
            exec_req.tool_name = tool_name;
            exec_req.params = params;

            auto& registry = agent_tools::ToolRegistry::instance();
            const auto* tool_def = registry.get_tool(tool_name);
            int mff_flag = (tool_def && tool_def->read_only) ? MFF_READ : MFF_WRITE;

            execute_sync(exec_req, mff_flag);

            if (on_status)
            {
                status_update_t status;
                status.type = status_type_t::tool_complete;
                status.iteration = iter + 1;
                status.tool_name = exec_req.result.tool_name;
                status.tool_success = exec_req.result.success;
                status.message = exec_req.result.message;
                on_status(status);
            }

            all_tool_results.push_back(std::move(exec_req.result));
        }

        if (config.verbose_logging)
        {
            for (const auto& r : all_tool_results)
            {
                msg(OBFSTR_C("  ← %s: %s — %s\n"), r.tool_name.c_str(),
                    r.success ? OBFSTR_C("OK") : OBFSTR_C("FAIL"), r.message.c_str());
            }
        }

        iteration_t iteration;
        iteration.number = iter + 1;
        iteration.ai_reasoning = reasoning;
        iteration.tool_results = all_tool_results;
        result.iterations.push_back(std::move(iteration));

        conversation_turn_t turn;
        turn.ai_response = ai_response;
        turn.tool_results = all_tool_results;
        turns.push_back(std::move(turn));
    }

    if (result.final_response.empty())
    {
        if (config.verbose_logging)
            msg(OBFSTR_C("AiDA Agent: Max iterations reached. Attempting forced summarization...\n"));

        std::string summary_prompt = build_conversation(initial_prompt, turns, dynamic_tool_result_chars);
        summary_prompt += OBFSTR("\n\n[SYSTEM OVERRIDE — MAX ITERATIONS EXHAUSTED] You have used all ")
                         + std::to_string(config.max_iterations) + OBFSTR(" iterations. Provide your COMPLETE "
                         "final answer NOW as plain text. Do NOT emit tool_calls JSON. Include: "
                         "(1) every address, offset, and function you discovered, "
                         "(2) all renames, type changes, and comments you applied, "
                         "(3) reconstructed data structures with field offsets, "
                         "(4) specific addresses for any remaining uninvestigated leads. "
                         "Present findings in a structured format with code blocks and hex addresses.");

        if (!(cancelled && cancelled->load()))
        {
            std::string summary_response = client->blocking_generate(summary_prompt, config.temperature);
            if (!summary_response.empty() && summary_response.substr(0, 6) != "Error:")
            {
                std::string cleaned = strip_tool_artifacts(summary_response);
                if (!cleaned.empty())
                {
                    result.final_response = cleaned;
                    result.total_iterations = config.max_iterations;
                    return result;
                }
            }
        }

        result.hit_max_iterations = true;
        result.total_iterations = config.max_iterations;
        result.final_response = OBFSTR("I reached the maximum number of iterations (") +
            std::to_string(config.max_iterations) + OBFSTR(") without completing the analysis. "
            "Here's a summary of what I found so far:\n\n");

        for (const auto& it : result.iterations)
        {
            result.final_response += OBFSTR("Iteration ") + std::to_string(it.number) + ": " + it.ai_reasoning + "\n";
            for (const auto& tr : it.tool_results)
            {
                result.final_response += "  " + tr.tool_name + ": " + (tr.success ? "OK" : "FAIL") + " — " + tr.message + "\n";
            }
        }
    }

    client->set_max_output_tokens(16384);

    return result;
}

}