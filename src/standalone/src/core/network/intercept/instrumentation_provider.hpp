#pragma once

#include "diagnostics.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace cert_intercept {

enum class provider_state_t {
    not_applicable,
    available,
    needs_user_launch,
    attached,
    failed,
    detached
};

struct provider_descriptor_t {
    std::string provider_id;
    std::string display_name;
    std::string intent;
    std::string behavior;
    bool forces_certificate_success = false;
    bool requires_explicit_target = true;
    bool supports_attach = false;
};

struct provider_status_t {
    provider_descriptor_t descriptor;
    uint32_t pid = 0;
    provider_state_t state = provider_state_t::not_applicable;
    bool active = false;
    std::string reason;
    std::vector<std::string> evidence;
};

std::string to_string(provider_state_t value);

class instrumentation_provider_t {
public:
    virtual ~instrumentation_provider_t() = default;
    virtual provider_descriptor_t descriptor() const = 0;
    virtual provider_status_t query(uint32_t pid, const process_diagnostics_t& diagnostics) const = 0;
    virtual provider_status_t attach(uint32_t pid, const process_diagnostics_t& diagnostics) = 0;
    virtual provider_status_t detach(uint32_t pid) = 0;
};

class provider_registry_t {
public:
    static provider_registry_t& instance();

    void register_provider(std::shared_ptr<instrumentation_provider_t> provider);
    void ensure_default_providers();
    std::vector<provider_descriptor_t> providers();
    std::vector<provider_status_t> evaluate(uint32_t pid, const process_diagnostics_t& diagnostics);
    std::vector<provider_status_t> status_for_process(uint32_t pid);
    provider_status_t attach(const std::string& provider_id, uint32_t pid, const process_diagnostics_t& diagnostics);
    provider_status_t detach(const std::string& provider_id, uint32_t pid);
    void clear_process(uint32_t pid);

private:
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<instrumentation_provider_t>> providers_;
    std::map<uint32_t, std::map<std::string, provider_status_t>> statuses_;
};

std::vector<std::shared_ptr<instrumentation_provider_t>> make_default_providers();

}
