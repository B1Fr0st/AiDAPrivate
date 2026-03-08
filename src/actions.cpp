#include "aida_pro.hpp"
#include <regex>
#include "chat_widget.hpp"
#include "anti_re.hpp"

static bool ensure_licensed_and_ready(aida_plugin_t* plugin)
{
    if (!anti_re::guard())
    {
        warning(OBFSTR_C("AiDA: runtime attestation failed. AI actions are disabled for this session."));
        return false;
    }
    VERIFY_LICENSE_INLINE();

    if (ida_utils::is_self_target_database())
    {
        warning(OBFSTR_C("AiDA: self-analysis is blocked for this database."));
        return false;
    }

    auto& license = license_manager_t::instance();
    if (!license.is_valid())
    {
        warning(OBFSTR_C("AiDA: License validation failed. Please restart IDA with a valid license."));
        return false;
    }

    uint64_t nonce = license.get_runtime_nonce();

    static const uint64_t bad_nonces[] = {
        0x0000000000000000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xDEADBEEFCAFEBABEULL,
        0x0000000000000001ULL,
        0x9090909090909090ULL,
        0xCCCCCCCCCCCCCCCCULL,
        0xEBFEEBFEEBFEEBFEULL,
    };
    for (uint64_t bad : bad_nonces)
    {
        if (nonce == bad)
        {
            return false;
        }
    }

    if (!license.verify_integrity_inline())
    {
        return false;
    }

    {
        uint64_t ck = license.compute_integrity_checksum();
        if (ck == 0 || ck == 0xFFFFFFFFFFFFFFFFULL || ck == nonce)
        {
            return false;
        }
    }

    if (!license.verify_function_prologues())
    {
        return false;
    }

    {
        if (!license.verify_nonce_consistency())
        {
            return false;
        }
    }

#ifdef __NT__
    {
        unsigned int aux;
        uint64_t tsc_begin = __rdtscp(&aux);
        volatile uint64_t probe = license.get_runtime_nonce();
        (void)probe;
        uint64_t tsc_end = __rdtscp(&aux);
        if ((tsc_end - tsc_begin) > 50000000ULL)
        {
            return false;
        }
    }
#endif

    if (!plugin || !plugin->ai_client || !plugin->ai_client->is_available())
    {
        warning(OBFSTR_C("AiDA: No AI client is available. Please configure a provider in Settings."));
        return false;
    }

    return true;
}

bool can_use_ai(aida_plugin_t* plugin)
{
    return ensure_licensed_and_ready(plugin);
}

int idaapi action_handler::activate(action_activation_ctx_t* ctx)
{
    action_func(ctx, plugin);
    return 1;
}

action_state_t idaapi action_handler::update(action_update_ctx_t* ctx)
{
    if (action_func == handle_toggle_mcp)
    {
        bool is_running = plugin->mcp_server && plugin->mcp_server->is_running();
        update_action_label(OBFSTR_C("ai_assistant:toggle_mcp"),
            is_running ? OBFSTR_C("Stop MCP Server") : OBFSTR_C("Start MCP Server"));
        return AST_ENABLE_ALWAYS;
    }

    if (action_func == handle_show_settings || action_func == handle_scan_for_offsets
        || action_func == handle_check_for_updates || action_func == handle_open_chat
        || action_func == handle_cancel_request || action_func == handle_save_database_context)
        return AST_ENABLE_ALWAYS;

    return (ctx->widget_type == BWN_PSEUDOCODE || ctx->widget_type == BWN_DISASM)
        ? AST_ENABLE : AST_DISABLE;
}

void handle_analyze_function(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!can_use_ai(plugin)) return;
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& analysis) {
        action_helpers::handle_ai_response(analysis, OBFSTR_C("AI Analysis for 0x%a"),
            [func_ea](const std::string& content) {
                qstring title;
                title.sprnt(OBFSTR_C("AI Analysis for 0x%a"), func_ea);
                show_text_in_viewer(title.c_str(), content);
            });
    };
    plugin->ai_client->analyze_function(func_ea, on_complete);
}

void handle_auto_comment(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!can_use_ai(plugin)) return;
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& json_comments) {
        action_helpers::handle_ai_response(json_comments, OBFSTR_C("AI Comments"),
            [func_ea](const std::string& content) {
                std::string json_str = content;
                static const std::regex md_json_re("```(?:json)?\\s*([\\s\\S]*?)\\s*```");
                std::smatch match;
                if (std::regex_search(content, match, md_json_re) && match.size() > 1)
                {
                    json_str = match[1].str();
                }

                try
                {
                    cfuncptr_t cfunc(nullptr);
                    if (init_hexrays_plugin())
                    {
                        func_t* pfn_for_decomp = get_func(func_ea);
                        if (pfn_for_decomp != nullptr)
                        {
                            try { cfunc = decompile(pfn_for_decomp); }
                            catch (const vd_failure_t&)
                            {
                                msg(OBFSTR_C("AiDA: Decompilation failed for 0x%a, comments will only be added to disassembly.\n"), func_ea);
                            }
                        }
                    }

                    auto comments = nlohmann::json::parse(json_str);
                    if (!comments.is_array())
                    {
                        warning(OBFSTR_C("AiDA: AI response for comments is not a JSON array."));
                        return;
                    }

                    int count = 0;
                    for (const auto& item : comments)
                    {
                        if (!item.is_object() || !item.contains(OBFSTR_C("address")) || !item.contains(OBFSTR_C("comment")))
                            continue;

                        std::string addr_str = item[OBFSTR_C("address")];
                        std::string comment_str = item[OBFSTR_C("comment")];

                        ea_t ea;
                        if (sscanf(addr_str.c_str(), "0x%llX", &ea) != 1 && sscanf(addr_str.c_str(), "%llX", &ea) != 1)
                            continue;

                        if (!is_mapped(ea))
                            continue;

                        qstring q_comment = comment_str.c_str();
                        q_comment.trim2();
                        if (q_comment.empty())
                            continue;

                        qstring existing_comment;
                        get_cmt(&existing_comment, ea, false);

                        qstring new_comment;
                        if (existing_comment.empty())
                        {
                            new_comment = q_comment;
                        }
                        else
                        {
                            new_comment.sprnt("%s\n%s", q_comment.c_str(), existing_comment.c_str());
                        }

                        set_cmt(ea, new_comment.c_str(), false);
                        count++;

                        if (cfunc != nullptr)
                        {
                            treeloc_t loc;
                            loc.ea = ea;
                            loc.itp = ITP_BLOCK1;

                            const char* existing_pcomment = cfunc->get_user_cmt(loc, RETRIEVE_ALWAYS);
                            qstring new_pcomment;
                            if (existing_pcomment == nullptr || *existing_pcomment == '\0')
                            {
                                new_pcomment = q_comment;
                            }
                            else
                            {
                                new_pcomment.sprnt("%s\n%s", q_comment.c_str(), existing_pcomment);
                            }
                            cfunc->set_user_cmt(loc, new_pcomment.c_str());
                        }
                    }

                    if (count > 0)
                    {
                        msg(OBFSTR_C("AiDA: Added %d comments to function at 0x%a.\n"), count, func_ea);
                        if (cfunc != nullptr)
                        {
                            cfunc->save_user_cmts();
                            cfunc->refresh_func_ctext();
                        }
                        mark_builtin_widgets(IWID_DISASM);
                    }
                    else
                    {
                        msg(OBFSTR_C("AiDA: AI did not provide any valid comments.\n"));
                    }
                }
                catch (const nlohmann::json::parse_error& e)
                {
                    warning(OBFSTR_C("AiDA: Failed to parse AI response as JSON: %s"), e.what());
                }
            });
    };
    plugin->ai_client->generate_comments(func_ea, on_complete);
}

void handle_generate_struct(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!can_use_ai(plugin)) return;
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& struct_cpp) {
        action_helpers::handle_ai_response(struct_cpp, OBFSTR_C("Generated Struct"),
            [func_ea](const std::string& content) {
                std::string target_param;
                static const std::regex apply_to_re("//\\s*APPLY_TO:\\s*(\\S+)");
                std::smatch apply_match;
                if (std::regex_search(content, apply_match, apply_to_re) && apply_match.size() > 1)
                {
                    target_param = apply_match[1].str();
                    msg(OBFSTR_C("AiDA: AI suggests applying type to parameter '%s'.\n"), target_param.c_str());
                }
                ida_utils::apply_struct_from_cpp_ex(content, func_ea, target_param);
            });
    };
    plugin->ai_client->generate_struct(func_ea, on_complete);
}

void handle_generate_hook(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!can_use_ai(plugin)) return;
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& hook_code) {
        action_helpers::handle_ai_response(hook_code, OBFSTR_C("Generated Hook"),
            [func_ea](const std::string& content) {
                qstring func_name;
                get_func_name(&func_name, func_ea);
                qstring title;
                title.sprnt(OBFSTR_C("MinHook Snippet for %s"), func_name.c_str());
                show_text_in_viewer(title.c_str(), content);
            });
    };
    plugin->ai_client->generate_hook(func_ea, on_complete);
}

void handle_copy_context(action_activation_ctx_t* ctx, aida_plugin_t*)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    nlohmann::json context = ida_utils::get_context_for_prompt(func_ea, true);

    if (!(context.contains(OBFSTR_C("ok")) && context[OBFSTR_C("ok")].is_boolean() && context[OBFSTR_C("ok")].get<bool>()))
    {
        warning(OBFSTR_C("AiDA: Failed to gather context: %s"), json_str(context, OBFSTR_C("message"), OBFSTR_C("Unknown error")).c_str());
        return;
    }

    std::string clipboard_text = ida_utils::format_context_for_clipboard(context);

    if (ida_utils::set_clipboard_text(clipboard_text.c_str()))
    {
        qstring func_name;
        get_func_name(&func_name, func_ea);
        msg(OBFSTR_C("AiDA: Context for function '%s' (0x%a) copied to clipboard.\n"), func_name.c_str(), func_ea);
    }
    else
    {
        warning(OBFSTR_C("AiDA: Failed to copy context to clipboard."));
    }
}

void handle_rename_all(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!can_use_ai(plugin)) return;
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& rename_suggestions) {
        action_helpers::handle_ai_response(rename_suggestions, OBFSTR_C("Rename Suggestions"),
            [func_ea](const std::string& content) {
                qstring summary = ida_utils::apply_renames_from_ai(func_ea, content);
                if (summary.empty())
                {
                    msg(OBFSTR_C("AiDA: No valid renames suggested by AI or nothing to rename.\n"));
                    return;
                }

                qstring title;
                title.sprnt(OBFSTR_C("Renaming summary for 0x%a"), func_ea);
                show_text_in_viewer(title.c_str(), summary.c_str());

                if (init_hexrays_plugin())
                {
                    mark_cfunc_dirty(func_ea, true);
                }
                mark_builtin_widgets(IWID_DISASM | IWID_PSEUDOCODE);
            });
    };
    plugin->ai_client->rename_all(func_ea, on_complete);
}

void handle_scan_for_offsets(action_activation_ctx_t*, aida_plugin_t*)
{
    msg(OBFSTR_C("====================================================\n"));
    msg(OBFSTR_C("--- Starting Unreal Engine Pointer Scan ---\n"));
    warning(OBFSTR_C("Scan for Engine Pointers is not yet implemented in the C++ version."));
}

void handle_show_settings(action_activation_ctx_t*, aida_plugin_t* plugin)
{
    SettingsForm::show_and_apply(plugin);
}

void handle_save_database_context(action_activation_ctx_t*, aida_plugin_t*)
{
    char* file_path = ask_file(true, OBFSTR_C("*.txt"), OBFSTR_C("Save database context to..."));
    if (file_path == nullptr)
    {
        msg(OBFSTR_C("AiDA: Operation cancelled.\n"));
        return;
    }

    FILE* fp = qfopen(file_path, "w");
    if (fp == nullptr)
    {
        warning(OBFSTR_C("AiDA: Could not open file for writing: %s"), file_path);
        return;
    }
    file_janitor_t fj(fp);

    show_wait_box(OBFSTR_C("HIDECANCEL\nExporting database context..."));

    const size_t func_qty = get_func_qty();
    bool hexrays_available = init_hexrays_plugin();

    for (size_t i = 0; i < func_qty; ++i)
    {
        if (user_cancelled())
        {
            msg(OBFSTR_C("AiDA: Database export cancelled by user.\n"));
            break;
        }

        replace_wait_box(OBFSTR_C("Exporting function %zu of %zu..."), i + 1, func_qty);

        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;

        qstring func_name;
        get_func_name(&func_name, pfn->start_ea);

        qfprintf(fp, OBFSTR_C("==================================================\n"));
        qfprintf(fp, OBFSTR_C("Function: %s (0x%a)\n"), func_name.c_str(), pfn->start_ea);
        qfprintf(fp, OBFSTR_C("==================================================\n\n"));

        qfprintf(fp, OBFSTR_C("--- Decompiled C/C++ Code ---\n"));
        if (hexrays_available)
        {
            try
            {
                cfuncptr_t cfunc = decompile(pfn);
                if (cfunc != nullptr)
                {
                    qstring code_qstr;
                    qstring_printer_t printer(cfunc.operator->(), code_qstr, false);
                    cfunc->print_func(printer);
                    tag_remove(&code_qstr, code_qstr.c_str());
                    qfprintf(fp, "%s\n", code_qstr.c_str());
                }
                else
                {
                    qfprintf(fp, OBFSTR_C("// Decompilation failed.\n\n"));
                }
            }
            catch (const vd_failure_t&)
            {
                qfprintf(fp, OBFSTR_C("// Decompilation failed.\n\n"));
            }
        }
        else
        {
            qfprintf(fp, OBFSTR_C("// Hex-Rays decompiler not available.\n\n"));
        }

        qfprintf(fp, OBFSTR_C("--- Disassembly ---\n"));
        text_t disasm_text;
        gen_disasm_text(disasm_text, pfn->start_ea, pfn->end_ea, false);
        for (const twinline_t& tw_line : disasm_text)
        {
            qstring clean_line;
            tag_remove(&clean_line, tw_line.line.c_str());
            qfprintf(fp, "%s\n", clean_line.c_str());
        }
        qfprintf(fp, "\n");

        qfprintf(fp, OBFSTR_C("--- Referenced Strings ---\n"));
        std::set<qstring> found_strings;
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            xrefblk_t xb;
            for (bool ok_ref = xb.first_from(fii.current(), XREF_DATA); ok_ref; ok_ref = xb.next_from())
            {
                flags64_t s_flags = get_flags(xb.to);
                if (is_strlit(s_flags))
                {
                    int32 strtype = get_str_type(xb.to);
                    qstring s;
                    if (get_strlit_contents(&s, xb.to, -1, strtype) > 0)
                    {
                        found_strings.insert(s);
                    }
                }
            }
        }

        if (found_strings.empty())
        {
            qfprintf(fp, OBFSTR_C("// No string literals referenced.\n"));
        }
        else
        {
            for (const auto& s : found_strings)
            {
                qfprintf(fp, "\"%s\"\n", s.c_str());
            }
        }
        qfprintf(fp, "\n\n");
    }

    hide_wait_box();
    msg(OBFSTR_C("AiDA: Successfully saved database context to %s\n"), file_path);
}

namespace action_helpers {
void handle_ai_response(const std::string& result, const qstring& title_prefix,
                        std::function<void(const std::string&)> success_action)
{
    if (!result.empty() && result.find(OBFSTR_C("Error:")) == std::string::npos)
    {
        success_action(result);
    }
    else if (!result.empty())
    {
        warning(OBFSTR_C("AiDA: %s"), result.c_str());
    }
}
}

namespace tool_executor {

std::vector<tool_call_t> parse_tool_calls(const std::string& json_response)
{
    std::vector<tool_call_t> calls;

    std::string json_text = json_response;
    static const std::regex md_json_re("```(?:json)?\\s*([\\s\\S]*?)\\s*```");
    std::smatch match;
    if (std::regex_search(json_response, match, md_json_re) && match.size() > 1)
    {
        json_text = match[1].str();
    }

    try
    {
        auto j = nlohmann::json::parse(json_text);

        if (!j.contains(OBFSTR_C("actions")) || !j[OBFSTR_C("actions")].is_array())
        {
            msg(OBFSTR_C("AiDA: AI response does not contain an 'actions' array.\n"));
            return calls;
        }

        for (const auto& action : j[OBFSTR_C("actions")])
        {
            if (!action.is_object() || !action.contains(OBFSTR_C("type")))
                continue;

            tool_call_t tc;
            tc.type = action[OBFSTR_C("type")].get<std::string>();
            tc.reasoning = json_str(action, OBFSTR_C("reasoning"));
            tc.params = (action.contains(OBFSTR_C("params")) && action[OBFSTR_C("params")].is_object()) ? action[OBFSTR_C("params")] : nlohmann::json::object();
            calls.push_back(std::move(tc));
        }
    }
    catch (const nlohmann::json::parse_error& e)
    {
        msg(OBFSTR_C("AiDA: Failed to parse tool calls JSON: %s\n"), e.what());
    }

    return calls;
}

std::string format_tool_calls_for_review(const std::vector<tool_call_t>& calls)
{
    std::stringstream ss;
    ss << OBFSTR_C("=== Proposed AI Actions ===\n\n");

    for (size_t i = 0; i < calls.size(); ++i)
    {
        const auto& tc = calls[i];
        ss << OBFSTR_C("[") << (i + 1) << OBFSTR_C("] ") << tc.type << OBFSTR_C("\n");
        if (!tc.reasoning.empty())
            ss << OBFSTR_C("    Reason: ") << tc.reasoning << OBFSTR_C("\n");

        if (tc.type == OBFSTR_C("rename_function"))
        {
            ss << OBFSTR_C("    Address: ") << json_str(tc.params, OBFSTR_C("address"), "??") << "\n";
            ss << OBFSTR_C("    New name: ") << json_str(tc.params, OBFSTR_C("new_name"), "??") << "\n";
        }
        else if (tc.type == OBFSTR_C("rename_variable"))
        {
            ss << OBFSTR_C("    Original: ") << json_str(tc.params, OBFSTR_C("original_name"), "??") << "\n";
            ss << OBFSTR_C("    New name: ") << json_str(tc.params, OBFSTR_C("new_name"), "??") << "\n";
        }
        else if (tc.type == OBFSTR_C("set_comment"))
        {
            ss << OBFSTR_C("    Address: ") << json_str(tc.params, OBFSTR_C("address"), "??") << "\n";
            ss << OBFSTR_C("    Comment: ") << json_str(tc.params, OBFSTR_C("comment"), "??") << "\n";
        }
        else if (tc.type == OBFSTR_C("create_type"))
        {
            std::string def = json_str(tc.params, OBFSTR_C("definition"));
            if (def.length() > 200) def = def.substr(0, 200) + "...";
            ss << OBFSTR_C("    Definition: ") << def << "\n";
        }
        else if (tc.type == OBFSTR_C("apply_type"))
        {
            ss << OBFSTR_C("    Param: ") << json_str(tc.params, OBFSTR_C("param_name"), "??") << "\n";
            ss << OBFSTR_C("    Type: ") << json_str(tc.params, OBFSTR_C("type_name"), "??") << "\n";
        }
        else if (tc.type == OBFSTR_C("rename_global"))
        {
            ss << OBFSTR_C("    Address: ") << json_str(tc.params, OBFSTR_C("address"), "??") << "\n";
            ss << OBFSTR_C("    New name: ") << json_str(tc.params, OBFSTR_C("new_name"), "??") << "\n";
        }
        ss << "\n";
    }
    return ss.str();
}

qstring execute_tool_calls(ea_t func_ea, const std::vector<tool_call_t>& calls)
{
    qstring summary;
    int success_count = 0;
    int fail_count = 0;

    func_t* pfn = get_func(func_ea);
    cfuncptr_t cfunc(nullptr);

    if (pfn && init_hexrays_plugin())
    {
        try { cfunc = decompile(pfn); }
        catch (const vd_failure_t&) {}
    }

    for (const auto& tc : calls)
    {
        if (tc.type == OBFSTR_C("rename_function"))
        {
            std::string addr_str = json_str(tc.params, OBFSTR_C("address"));
            std::string new_name = json_str(tc.params, OBFSTR_C("new_name"));
            ea_t target_ea = func_ea;

            if (!addr_str.empty())
            {
                try { target_ea = std::stoull(addr_str, nullptr, 16); }
                catch (...) {}
            }

            if (!new_name.empty() && set_name(target_ea, new_name.c_str(), SN_FORCE | SN_NODUMMY))
            {
                summary.cat_sprnt(OBFSTR_C("Renamed function at 0x%llx to '%s'\n"), target_ea, new_name.c_str());
                success_count++;
            }
            else
            {
                summary.cat_sprnt(OBFSTR_C("FAILED: Rename function to '%s'\n"), new_name.c_str());
                fail_count++;
            }
        }
        else if (tc.type == OBFSTR_C("rename_variable"))
        {
            std::string original = json_str(tc.params, OBFSTR_C("original_name"));
            std::string new_name = json_str(tc.params, OBFSTR_C("new_name"));

            if (!original.empty() && !new_name.empty())
            {
                if (rename_lvar(func_ea, original.c_str(), new_name.c_str()))
                {
                    summary.cat_sprnt(OBFSTR_C("Renamed variable: %s -> %s\n"), original.c_str(), new_name.c_str());
                    success_count++;
                }
                else
                {
                    summary.cat_sprnt(OBFSTR_C("FAILED: Rename variable '%s' -> '%s'\n"), original.c_str(), new_name.c_str());
                    fail_count++;
                }
            }
        }
        else if (tc.type == OBFSTR_C("set_comment"))
        {
            std::string addr_str = json_str(tc.params, OBFSTR_C("address"));
            std::string comment = json_str(tc.params, OBFSTR_C("comment"));
            ea_t target_ea = BADADDR;

            if (!addr_str.empty())
            {
                try { target_ea = std::stoull(addr_str, nullptr, 16); }
                catch (...) {}
            }

            if (target_ea != BADADDR && is_mapped(target_ea) && !comment.empty())
            {
                set_cmt(target_ea, comment.c_str(), false);
                summary.cat_sprnt(OBFSTR_C("Comment at 0x%llx: %s\n"), target_ea, comment.substr(0, 60).c_str());
                success_count++;

                if (cfunc)
                {
                    treeloc_t loc;
                    loc.ea = target_ea;
                    loc.itp = ITP_BLOCK1;
                    cfunc->set_user_cmt(loc, comment.c_str());
                }
            }
            else
            {
                summary.cat_sprnt(OBFSTR_C("FAILED: Set comment at '%s'\n"), addr_str.c_str());
                fail_count++;
            }
        }
        else if (tc.type == OBFSTR_C("create_type"))
        {
            std::string definition = json_str(tc.params, OBFSTR_C("definition"));
            if (!definition.empty())
            {
                til_t* idati = get_idati();
                if (parse_decls(idati, definition.c_str(), msg, HTI_DCL) == 0)
                {
                    summary.cat_sprnt(OBFSTR_C("Created type from definition\n"));
                    success_count++;
                }
                else
                {
                    summary.cat_sprnt(OBFSTR_C("FAILED: Create type (parse error)\n"));
                    fail_count++;
                }
            }
        }
        else if (tc.type == OBFSTR_C("apply_type"))
        {
            std::string param_name = json_str(tc.params, OBFSTR_C("param_name"));
            std::string type_name = json_str(tc.params, OBFSTR_C("type_name"));

            if (!param_name.empty() && !type_name.empty() && cfunc && pfn)
            {
                lvars_t* lvars = cfunc->get_lvars();
                bool done = false;
                if (lvars)
                {
                    for (lvar_t& lv : *lvars)
                    {
                        if (lv.name == param_name.c_str())
                        {
                            tinfo_t tif;
                            if (tif.parse(type_name.c_str()))
                            {
                                lvar_saved_info_t lsi;
                                lsi.ll = lv;
                                lsi.type = tif;
                                if (modify_user_lvar_info(func_ea, MLI_TYPE, lsi))
                                {
                                    summary.cat_sprnt(OBFSTR_C("Applied type '%s' to '%s'\n"), type_name.c_str(), param_name.c_str());
                                    success_count++;
                                    done = true;
                                }
                            }
                            break;
                        }
                    }
                }
                if (!done)
                {
                    summary.cat_sprnt(OBFSTR_C("FAILED: Apply type '%s' to '%s'\n"), type_name.c_str(), param_name.c_str());
                    fail_count++;
                }
            }
        }
        else if (tc.type == OBFSTR_C("rename_global"))
        {
            std::string addr_str = json_str(tc.params, OBFSTR_C("address"));
            std::string new_name = json_str(tc.params, OBFSTR_C("new_name"));
            ea_t target_ea = BADADDR;

            if (!addr_str.empty())
            {
                try { target_ea = std::stoull(addr_str, nullptr, 16); }
                catch (...) {}
            }

            if (target_ea != BADADDR && !new_name.empty())
            {
                if (set_name(target_ea, new_name.c_str(), SN_FORCE | SN_NODUMMY))
                {
                    summary.cat_sprnt(OBFSTR_C("Renamed global at 0x%llx to '%s'\n"), target_ea, new_name.c_str());
                    success_count++;
                }
                else
                {
                    summary.cat_sprnt(OBFSTR_C("FAILED: Rename global to '%s'\n"), new_name.c_str());
                    fail_count++;
                }
            }
        }
    }

    if (cfunc)
    {
        cfunc->save_user_cmts();
        cfunc->refresh_func_ctext();
    }

    if (success_count > 0 || fail_count > 0)
    {
        if (pfn && init_hexrays_plugin())
            mark_cfunc_dirty(func_ea, true);
        mark_builtin_widgets(IWID_DISASM | IWID_PSEUDOCODE);
    }

    summary.cat_sprnt(OBFSTR_C("\n--- Results: %d succeeded, %d failed ---\n"), success_count, fail_count);
    return summary;
}

}

void handle_check_for_updates(action_activation_ctx_t*, aida_plugin_t* plugin)
{
    if (plugin)
    {
        msg(OBFSTR_C("AiDA: Checking for updates...\n"));
        plugin->check_for_updates();
    }
}

void handle_open_chat(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    chat_widget::open_chat(ctx, plugin);
}

void handle_fix_analysis(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!can_use_ai(plugin)) return;
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    auto on_complete = [func_ea](const std::string& fix_response) {
        action_helpers::handle_ai_response(fix_response, OBFSTR_C("Analysis Correction"),
            [func_ea](const std::string& content) {
                auto calls = tool_executor::parse_tool_calls(content);

                if (!calls.empty())
                {

                    std::string cleaned_code;
                    try
                    {
                        std::string json_text = content;
                        static const std::regex md_json_re("```(?:json)?\\s*([\\s\\S]*?)\\s*```");
                        std::smatch match;
                        if (std::regex_search(content, match, md_json_re) && match.size() > 1)
                            json_text = match[1].str();

                        auto j = nlohmann::json::parse(json_text);
                        cleaned_code = json_str(j, OBFSTR_C("cleaned_code"));
                    }
                    catch (...) {}


                    std::string review = tool_executor::format_tool_calls_for_review(calls);

                    qstring display_text;
                    if (!cleaned_code.empty())
                    {
                        display_text.sprnt(OBFSTR_C("=== Cleaned Code ===\n\n%s\n\n=== Proposed Actions ===\n\n%s"),
                            cleaned_code.c_str(), review.c_str());
                    }
                    else
                    {
                        display_text = review.c_str();
                    }

                    qstring title;
                    title.sprnt(OBFSTR_C("Analysis Corrections for 0x%a"), func_ea);
                    show_text_in_viewer(title.c_str(), display_text.c_str());

                    qstring confirm_msg;
                    confirm_msg.sprnt(OBFSTR_C("Proposes %zu correction(s). Apply all?"), calls.size());
                    if (ask_yn(ASKBTN_YES, confirm_msg.c_str()) == ASKBTN_YES)
                    {
                        qstring summary = tool_executor::execute_tool_calls(func_ea, calls);
                        msg(OBFSTR_C("AiDA: Analysis corrections applied.\n%s"), summary.c_str());
                    }
                    else
                    {
                        msg(OBFSTR_C("AiDA: Analysis corrections cancelled.\n"));
                    }
                }
                else
                {

                    qstring title;
                    title.sprnt(OBFSTR_C("Analysis Corrections for 0x%a"), func_ea);
                    show_text_in_viewer(title.c_str(), content);
                }
            });
    };
    plugin->ai_client->fix_analysis(func_ea, on_complete);
}

void handle_cancel_request(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (plugin && plugin->ai_client)
    {
        plugin->ai_client->cancel_current_request();
        msg(OBFSTR_C("AiDA: Cancel requested.\n"));
    }
}

void handle_toggle_mcp(action_activation_ctx_t*, aida_plugin_t* plugin)
{
    if (!plugin)
        return;
    plugin->toggle_mcp_server();
}

void handle_debug_analyze(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!ensure_licensed_and_ready(plugin) || !can_use_ai(plugin))
    {
        return;
    }

    ea_t ea = ctx->cur_ea;
    if (ea == BADADDR)
    {
        warning(OBFSTR_C("Place cursor on an address to analyze in debugger context."));
        return;
    }

    std::string addr_str = agent_tools::helpers::format_address(ea);

    std::string prompt =
        OBFSTR("I need you to perform a deep AI-assisted debugger analysis at address ") + addr_str + OBFSTR(".\n\n")
        + OBFSTR("Follow this workflow:\n")
        + OBFSTR("1. Use `analyze_breakpoint_context` with address ") + addr_str + OBFSTR(" to gather the full execution context.\n")
        + OBFSTR("2. Use `get_debugger_event_log` to check recent debugger events for relevant context.\n")
        + OBFSTR("3. Use `decompile_function` on the function containing this address.\n")
        + OBFSTR("4. Use `get_call_stack` to understand the execution path that led here.\n")
        + OBFSTR("5. Use `get_registers` with mode 'all_current' to see the full register state.\n")
        + OBFSTR("6. Analyze all gathered data and provide:\n")
        + OBFSTR("   - What the code is doing at this exact point\n")
        + OBFSTR("   - The values of key variables based on register/stack state\n")
        + OBFSTR("   - Any suspicious patterns (anti-debug, VM handlers, obfuscation)\n")
        + OBFSTR("   - Recommended next debugging steps (breakpoints to set, memory to watch)\n")
        + OBFSTR("   - If virtualized code is detected, identify the VM dispatcher and handler table\n");

    plugin->ai_client->agentic_chat(
        ea,
        prompt,
        {},
        [](const std::string& result) {
            action_helpers::handle_ai_response(result,
                "Debugger Analysis",
                [](const std::string&) {});
        });
}

void handle_debug_devirtualize(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!ensure_licensed_and_ready(plugin) || !can_use_ai(plugin))
    {
        return;
    }

    ea_t ea = ctx->cur_ea;
    if (ea == BADADDR)
    {
        warning(OBFSTR_C("Place cursor on a virtualized function or VM entry point."));
        return;
    }

    std::string addr_str = agent_tools::helpers::format_address(ea);

    std::string prompt =
        OBFSTR("I need you to devirtualize the code at address ") + addr_str + OBFSTR(".\n\n")
        + OBFSTR("Follow this systematic devirtualization workflow:\n\n")
        + OBFSTR("**Phase 1: VM Detection**\n")
        + OBFSTR("1. Use `detect_vm_handler_pattern` at ") + addr_str + OBFSTR(" with scan_size=8192 to identify VM patterns.\n")
        + OBFSTR("2. Use `decompile_function` to see the high-level structure.\n")
        + OBFSTR("3. Use `get_basic_blocks` to understand the control flow.\n\n")
        + OBFSTR("**Phase 2: Handler Table Discovery**\n")
        + OBFSTR("4. If an indirect jump table is found, use `map_vm_handler_table` to enumerate all handlers.\n")
        + OBFSTR("5. For each unique handler, use `decompile_function` to understand its operation.\n\n")
        + OBFSTR("**Phase 3: Dynamic Analysis (if debugger is active)**\n")
        + OBFSTR("6. Use `get_debugger_state` to check if debugger is running.\n")
        + OBFSTR("7. If active, use `snapshot_execution_state` with label 'vm_entry' at the VM entry.\n")
        + OBFSTR("8. Use `trace_virtual_dispatch` on the dispatch instruction to capture runtime targets.\n")
        + OBFSTR("9. Use `snapshot_execution_state` with label 'vm_exit' after the VM exits.\n")
        + OBFSTR("10. Use `compare_execution_states` to understand what the VM bytecode accomplished.\n\n")
        + OBFSTR("**Phase 4: Reconstruction**\n")
        + OBFSTR("11. Based on all gathered data, reconstruct the original logic:\n")
        + OBFSTR("    - Map each VM opcode to its semantic operation\n")
        + OBFSTR("    - Identify the virtual registers and their mappings to real registers\n")
        + OBFSTR("    - Reconstruct the control flow (branches, loops, calls)\n")
        + OBFSTR("    - Produce equivalent C pseudocode for the devirtualized function\n")
        + OBFSTR("12. Add comments to the IDB using `set_comment` and `set_function_comment` to document findings.\n")
        + OBFSTR("13. Rename the VM handlers using `rename_function` with descriptive names (e.g., vm_add, vm_push, vm_jmp).\n");

    plugin->ai_client->agentic_chat(
        ea,
        prompt,
        {},
        [](const std::string& result) {
            action_helpers::handle_ai_response(result,
                "Devirtualization",
                [](const std::string&) {});
        });
}

void handle_debug_trace_dispatch(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!ensure_licensed_and_ready(plugin) || !can_use_ai(plugin))
    {
        return;
    }

    ea_t ea = ctx->cur_ea;
    if (ea == BADADDR)
    {
        warning(OBFSTR_C("Place cursor on an indirect call/jump instruction."));
        return;
    }

    std::string addr_str = agent_tools::helpers::format_address(ea);

    std::string prompt =
        OBFSTR("Trace the virtual/indirect dispatch at address ") + addr_str + OBFSTR(".\n\n")
        + OBFSTR("1. Use `trace_virtual_dispatch` at ") + addr_str + OBFSTR(" with depth=8 to discover runtime targets.\n")
        + OBFSTR("2. For each discovered target, use `decompile_function` to understand what it does.\n")
        + OBFSTR("3. Use `get_xrefs_to` on each target to find other callers.\n")
        + OBFSTR("4. Summarize the dispatch table: which targets are called, what each does, and the likely vtable/interface being used.\n")
        + OBFSTR("5. If this looks like a VM dispatcher, use `detect_vm_handler_pattern` to confirm.\n")
        + OBFSTR("6. Add comments documenting the dispatch targets using `set_comment`.\n");

    plugin->ai_client->agentic_chat(
        ea,
        prompt,
        {},
        [](const std::string& result) {
            action_helpers::handle_ai_response(result,
                "Dispatch Trace",
                [](const std::string&) {});
        });
}
