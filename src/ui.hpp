#pragma once

#include <ida.hpp>
#include <kernwin.hpp>
#include <memory>

class aida_plugin_t;

typedef TWidget simplecustviewer_t;

class SettingsForm
{
public:
    static void show_and_apply(aida_plugin_t* plugin_instance);
};

void handle_manage_prompts(action_activation_ctx_t* ctx, aida_plugin_t* plugin);

void show_text_in_viewer(const char* title, const std::string& text_content);
void show_prompt_manager_dialog();