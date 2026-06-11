#pragma once

#include <memory>
#include <string>
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

    aida_plugin_t(bool standalone_verified, const std::string& standalone_failure);
    ~aida_plugin_t() override;

    bool idaapi run(size_t arg) override;
    bool start_mcp_server();
    void stop_mcp_server();
    bool ensure_operational(bool interactive);
    bool is_operational() const;
    const std::string& disabled_reason() const;

private:
    void register_actions();
    void unregister_actions();
    void set_disabled(const std::string& reason);
    bool initialize_operational(bool interactive);

    bool features_initialized = false;
    bool ui_listener_hooked = false;
    bool actions_registered = false;
    std::string disabled_detail;
};
