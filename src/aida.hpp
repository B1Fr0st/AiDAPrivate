#pragma once

#include <memory>
#include <string>
#include <vector>

#ifdef __NT__
#include <thread>
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>

#ifdef __NT__
#include <windows.h>
#endif

class mcp_server_t;

namespace aida
{
namespace vuln
{
class chain_verifier_service_t;
enum class chain_verify_action_kind_t : unsigned;
}
}

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
    void activate_chain_verify_action(aida::vuln::chain_verify_action_kind_t kind, action_activation_ctx_t* ctx);
    action_state_t update_chain_verify_action(aida::vuln::chain_verify_action_kind_t kind, const action_update_ctx_t* ctx) const;

private:
    void register_actions();
    void unregister_actions();
    void set_disabled(const std::string& reason);
    bool initialize_operational(bool interactive);

    bool features_initialized = false;
    bool ui_listener_hooked = false;
    bool actions_registered = false;
    std::unique_ptr<aida::vuln::chain_verifier_service_t> chain_verifier_service;
    std::string disabled_detail;
#ifdef __NT__
    std::thread graphrag_load_thread;
#endif
};
