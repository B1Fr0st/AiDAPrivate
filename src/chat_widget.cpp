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
#include "chat_widget_ui.hpp"

struct chat_state_t
{
    aida_plugin_t* plugin  = nullptr;
    TWidget*       widget  = nullptr;
    AiDAChatPanel* panel   = nullptr;
    ea_t           context_ea = BADADDR;
    qstring        context_func_name;
    std::vector<std::pair<std::string, std::string>> history;
};

static chat_state_t g_chat;

struct chat_event_listener_t : public event_listener_t
{
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

static chat_event_listener_t g_chat_evt_listener;
static bool g_chat_listener_hooked = false;

ssize_t idaapi chat_event_listener_t::on_event(ssize_t code, va_list va)
{
    if (code == ui_widget_visible)
    {
        TWidget* w = va_arg(va, TWidget*);
        if (w == g_chat.widget && g_chat.panel == nullptr)
        {
            QWidget* parent = (QWidget*)w;

            QVBoxLayout* layout = new QVBoxLayout();
            layout->setContentsMargins(0, 0, 0, 0);
            layout->setSpacing(0);

            g_chat.panel = new AiDAChatPanel(
                parent,
                g_chat.plugin,
                g_chat.context_ea,
                QString::fromLatin1(g_chat.context_func_name.c_str()));

            if (!g_chat.history.empty())
                g_chat.panel->setHistory(g_chat.history);

            layout->addWidget(g_chat.panel);
            parent->setLayout(layout);
        }
    }
    else if (code == ui_widget_invisible)
    {
        TWidget* w = va_arg(va, TWidget*);
        if (w == g_chat.widget)
        {
            if (g_chat.panel != nullptr)
                g_chat.history = g_chat.panel->getHistory();

            g_chat.panel  = nullptr;
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
            TWidget* w = find_widget(OBFSTR_C("AiDA Chat"));
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
    func_t* pfn = get_func(current_ea);
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

    TWidget* existing = find_widget(OBFSTR_C("AiDA Chat"));
    if (existing != nullptr)
    {
        activate_widget(existing, true);

        if (g_chat.panel != nullptr)
        {
            g_chat.panel->setContextFunction(
                g_chat.context_ea,
                QString::fromLatin1(g_chat.context_func_name.c_str()));
        }
        return;
    }

    g_chat.widget = create_empty_widget(OBFSTR_C("AiDA Chat"));

    display_widget(g_chat.widget, WOPN_DP_TAB | WOPN_DP_SZHINT | WOPN_PERSIST);
    set_dock_pos(OBFSTR_C("AiDA Chat"), nullptr, DP_RIGHT);
}

void close_chat()
{
    TWidget* existing = find_widget(OBFSTR_C("AiDA Chat"));
    if (existing != nullptr)
    {
        close_widget(existing, WCLS_SAVE);
    }
    g_chat.widget = nullptr;
    g_chat.panel  = nullptr;
}

AiDAChatPanel* get_panel()
{
    return g_chat.panel;
}

}
