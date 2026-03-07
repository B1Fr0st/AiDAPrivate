#ifndef QT_NO_EMIT
#define QT_NO_EMIT
#endif

#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:5219)
#pragma warning(disable:5240)
#endif
#include <QtWidgets>
#ifdef __NT__
#pragma warning(pop)
#endif

#ifdef emit
#undef emit
#endif

#include "aida_pro.hpp"
#include "chat_widget.hpp"
#include "workbench.hpp"

struct chat_state_t
{
    aida_plugin_t*      plugin         = nullptr;
    TWidget*            widget         = nullptr;
    AiDAWorkbenchPanel* workbench      = nullptr;
    ea_t                context_ea     = BADADDR;
    qstring             context_func_name;
};

static chat_state_t g_chat;

struct chat_event_listener_t : public event_listener_t
{
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

static chat_event_listener_t g_chat_evt_listener;
static bool g_chat_listener_hooked = false;

static void update_context_for_ea(ea_t ea)
{
    func_t* pfn = get_func(ea);
    if (pfn != nullptr)
    {
        g_chat.context_ea = pfn->start_ea;
        get_func_name(&g_chat.context_func_name, pfn->start_ea);
    }
    else
    {
        g_chat.context_ea = BADADDR;
        g_chat.context_func_name.clear();
    }

    if (g_chat.workbench != nullptr)
    {
        g_chat.workbench->set_context_function(
            g_chat.context_ea,
            QString::fromLatin1(g_chat.context_func_name.c_str()));
    }
}

ssize_t idaapi chat_event_listener_t::on_event(ssize_t code, va_list va)
{
    if (code == ui_widget_visible)
    {
        TWidget* w = va_arg(va, TWidget*);
        if (w == g_chat.widget && g_chat.workbench == nullptr)
        {
            QWidget* parent = (QWidget*)w;

            QVBoxLayout* layout = new QVBoxLayout();
            layout->setContentsMargins(0, 0, 0, 0);
            layout->setSpacing(0);

            g_chat.workbench = new AiDAWorkbenchPanel(
                parent,
                g_chat.plugin,
                g_chat.context_ea,
                QString::fromLatin1(g_chat.context_func_name.c_str()));

            layout->addWidget(g_chat.workbench);
            parent->setLayout(layout);
        }
    }
    else if (code == ui_screen_ea_changed)
    {
        ea_t ea = va_arg(va, ea_t);
        qnotused(va_arg(va, ea_t));
        update_context_for_ea(ea);
    }
    else if (code == ui_widget_invisible)
    {
        TWidget* w = va_arg(va, TWidget*);
        if (w == g_chat.widget)
        {
            g_chat.workbench = nullptr;
            g_chat.widget = nullptr;
        }
    }
    else if (code == ui_desktop_applied)
    {
        if (g_chat.widget != nullptr)
        {
            activate_widget(g_chat.widget, true);
        }
        else
        {
            TWidget* w = find_widget(OBFSTR_C("AiDA"));
            if (w != nullptr)
                activate_widget(w, true);
        }
    }
    return 0;
}

namespace chat_widget
{

void open_chat(action_activation_ctx_t* ctx, aida_plugin_t* plugin)
{
    if (!g_chat_listener_hooked)
    {
        ::hook_event_listener(HT_UI, &g_chat_evt_listener, nullptr);
        g_chat_listener_hooked = true;
    }

    g_chat.plugin = plugin;

    ea_t current_ea = ctx != nullptr ? ctx->cur_ea : get_screen_ea();
    update_context_for_ea(current_ea);

    TWidget* existing = find_widget(OBFSTR_C("AiDA"));
    if (existing != nullptr)
    {
        activate_widget(existing, true);
        return;
    }

    g_chat.widget = create_empty_widget(OBFSTR_C("AiDA"));

    display_widget(g_chat.widget, WOPN_DP_TAB | WOPN_DP_SZHINT | WOPN_PERSIST);
    set_dock_pos(OBFSTR_C("AiDA"), nullptr, DP_RIGHT);
}

void close_chat()
{
    TWidget* existing = find_widget(OBFSTR_C("AiDA"));
    if (existing != nullptr)
    {
        close_widget(existing, WCLS_SAVE);
    }
    g_chat.widget = nullptr;
    g_chat.workbench = nullptr;
}

AiDAChatPanel* get_panel()
{
    return g_chat.workbench != nullptr ? g_chat.workbench->query_panel() : nullptr;
}

AiDAWorkbenchPanel* get_workbench()
{
    return g_chat.workbench;
}

}
