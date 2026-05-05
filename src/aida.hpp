#pragma once

#include <memory>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

#ifdef __NT__
#include <windows.h>
#endif

class mcp_server_t;

struct ui_event_listener_t : public event_listener_t
{
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

class aida_plugin_t : public plugmod_t
{
public:
    qstrvec_t actions_list;
    ui_event_listener_t ui_listener;
    std::unique_ptr<mcp_server_t> mcp_server;

    aida_plugin_t();
    ~aida_plugin_t() override;

    bool idaapi run(size_t arg) override;
    void start_mcp_server();
    void stop_mcp_server();
    void toggle_mcp_server();

private:
    void register_actions();
    void unregister_actions();
};
