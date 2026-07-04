#pragma once

#include <cstdint>
#include <memory>

#include <kernwin.hpp>

namespace aida
{
namespace vuln
{

enum class chain_verify_action_kind_t : unsigned
{
    open_panel,
    current_function_as_link,
    start,
    cancel,
    copy_result_json
};

class chain_verifier_service_t
{
public:
    chain_verifier_service_t();
    ~chain_verifier_service_t();

    chain_verifier_service_t(const chain_verifier_service_t&) = delete;
    chain_verifier_service_t& operator=(const chain_verifier_service_t&) = delete;

    struct impl_t;

    bool start();
    void stop(std::uint32_t join_timeout_ms);
    bool started() const;
    action_state_t action_state(chain_verify_action_kind_t kind, const action_update_ctx_t* ctx) const;
    void activate(chain_verify_action_kind_t kind, action_activation_ctx_t* ctx);
    int timer_tick();

private:
    std::shared_ptr<impl_t> m_impl;
};

}
}
