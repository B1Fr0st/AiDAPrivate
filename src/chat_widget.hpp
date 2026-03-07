#pragma once

#include <ida.hpp>
#include <kernwin.hpp>

class aida_plugin_t;
class AiDAChatPanel;
class AiDAWorkbenchPanel;

namespace chat_widget
{
    void open_chat(action_activation_ctx_t* ctx, aida_plugin_t* plugin);

    void close_chat();

    AiDAChatPanel* get_panel();
    AiDAWorkbenchPanel* get_workbench();
}
