#include "aida_pro.hpp"
#include "ida_utils.hpp"

namespace analysis_fixer
{
namespace
{
class cleanup_optinsn_t final : public optinsn_t
{
public:
    int idaapi func(mblock_t* blk, minsn_t* ins, int) override
    {
        if (blk == nullptr || ins == nullptr)
            return 0;

        int changes = 0;

        if (ins->is_mov() && ins->l.equal_mops(ins->d, EQ_IGNSIZE))
        {
            blk->make_nop(ins);
            ++changes;
        }

        if (ins->opcode == m_goto && ins->l.is_mblock(blk->serial))
        {
            blk->make_nop(ins);
            ++changes;
        }

        return changes;
    }
};

class cleanup_optblock_t final : public optblock_t
{
public:
    int idaapi func(mblock_t* blk) override
    {
        if (blk == nullptr)
            return 0;

        int changes = blk->optimize_useless_jump();
        if (blk->tail != nullptr && blk->tail->is_noret_call(NORET_FORBID_ANALYSIS))
        {
            if (blk->type != BLT_0WAY)
            {
                blk->type = BLT_0WAY;
                ++changes;
            }
            if ((blk->flags & MBL_NORET) == 0)
            {
                blk->flags |= MBL_NORET;
                ++changes;
            }
        }

        if (changes > 0)
        {
            blk->mark_lists_dirty();
            if (blk->mba != nullptr)
                blk->mba->remove_empty_and_unreachable_blocks();
        }

        return changes;
    }
};

cleanup_optinsn_t g_cleanup_optinsn;
cleanup_optblock_t g_cleanup_optblock;
int g_fixup_refcount = 0;
bool g_fixups_installed = false;
}

bool install_hexrays_fixups()
{
    if (g_fixups_installed)
    {
        ++g_fixup_refcount;
        return true;
    }

    if (!init_hexrays_plugin())
        return false;

    install_optinsn_handler(&g_cleanup_optinsn);
    install_optblock_handler(&g_cleanup_optblock);
    g_fixups_installed = true;
    g_fixup_refcount = 1;
    return true;
}

void uninstall_hexrays_fixups()
{
    if (!g_fixups_installed)
        return;

    if (g_fixup_refcount > 1)
    {
        --g_fixup_refcount;
        return;
    }

    g_fixup_refcount = 0;
    if (init_hexrays_plugin())
    {
        remove_optinsn_handler(&g_cleanup_optinsn);
        remove_optblock_handler(&g_cleanup_optblock);
    }
    g_fixups_installed = false;
}

void refresh_decompilation(ea_t func_ea)
{
    if (func_ea != BADADDR && init_hexrays_plugin())
        mark_cfunc_dirty(func_ea, true);
    mark_builtin_widgets(IWID_DISASM | IWID_PSEUDOCODE);
}
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

    if (action_func == handle_save_database_context)
        return AST_ENABLE_ALWAYS;

    return (ctx->widget_type == BWN_PSEUDOCODE || ctx->widget_type == BWN_DISASM)
        ? AST_ENABLE : AST_DISABLE;
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
        if (hexrays_available && ida_utils::is_safely_decompilable(pfn))
        {
            try
            {
                hexrays_failure_t hf;
                cfuncptr_t cfunc = decompile(pfn, &hf, DECOMP_NO_WAIT);
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
            catch (...)
            {
                qfprintf(fp, OBFSTR_C("// Decompilation crashed (access violation) – skipped.\n\n"));
            }
        }
        else if (!hexrays_available)
        {
            qfprintf(fp, OBFSTR_C("// Hex-Rays decompiler not available.\n\n"));
        }
        else
        {
            qfprintf(fp, OBFSTR_C("// Non-decompilable function (thunk/extern/tail) – skipped.\n\n"));
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

void handle_fix_analysis(action_activation_ctx_t* ctx, aida_plugin_t*)
{
    func_t* pfn = ida_utils::get_function_for_item(ctx->cur_ea);
    if (pfn == nullptr)
        return;
    const ea_t func_ea = pfn->start_ea;

    analysis_fixer::install_hexrays_fixups();
    analysis_fixer::refresh_decompilation(func_ea);

    qstring func_name;
    get_func_name(&func_name, func_ea);
    msg(OBFSTR_C("AiDA: Cleaned decompilation for %s (0x%a).\n"), func_name.c_str(), func_ea);
}

void handle_toggle_mcp(action_activation_ctx_t*, aida_plugin_t* plugin)
{
    if (!plugin)
        return;
    plugin->toggle_mcp_server();
}
