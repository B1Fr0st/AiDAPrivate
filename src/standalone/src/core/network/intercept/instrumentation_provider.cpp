#include "instrumentation_provider.hpp"

#include <algorithm>
#include <utility>

namespace cert_intercept {
namespace {

bool has_module_flag(const process_diagnostics_t& diagnostics, bool module_summary_t::*member) {
    for (const auto& module : diagnostics.modules) {
        if (module.*member) return true;
    }
    return false;
}

bool has_stable_export_candidate(const process_diagnostics_t& diagnostics) {
    return has_module_flag(diagnostics, &module_summary_t::stable_export_candidate);
}

class descriptor_provider_t final : public instrumentation_provider_t {
public:
    descriptor_provider_t(provider_descriptor_t descriptor, classification_t classification)
        : descriptor_(std::move(descriptor)), classification_(classification) {}

    provider_descriptor_t descriptor() const override {
        return descriptor_;
    }

    provider_status_t query(uint32_t pid, const process_diagnostics_t& diagnostics) const override {
        provider_status_t status;
        status.descriptor = descriptor_;
        status.pid = pid;

        if (descriptor_.provider_id == "windows_proxy_adapter") {
            if (diagnostics.primary == classification_t::no_proxy_route || diagnostics.primary == classification_t::ca_not_trusted) {
                status.state = provider_state_t::needs_user_launch;
                status.reason = "Proxy route or CA trust needs user action";
            } else {
                status.state = provider_state_t::available;
                status.reason = "Proxy and trust readiness can be represented without target patching";
            }
            status.evidence.push_back(to_string(diagnostics.primary));
            return status;
        }

        if (descriptor_.provider_id == "openssl_export_adapter") {
            if (!has_stable_export_candidate(diagnostics)) {
                status.state = provider_state_t::not_applicable;
                status.reason = "No stable exported TLS verification API was identified from module metadata";
                return status;
            }
            status.state = provider_state_t::available;
            status.reason = "Export-level handoff can observe verification flow without forcing success";
            status.evidence.push_back("stable_export_candidate");
            return status;
        }

        if (descriptor_.provider_id == "dotnet_adapter") {
            if (!has_module_flag(diagnostics, &module_summary_t::managed_runtime)) {
                status.state = provider_state_t::not_applicable;
                status.reason = "No managed network runtime was identified";
                return status;
            }
            status.state = provider_state_t::available;
            status.reason = "Managed TLS callback diagnostics are available for explicit user-guided handoff";
            status.evidence.push_back("managed_runtime");
            return status;
        }

        status.state = classification_ == diagnostics.primary ? provider_state_t::available : provider_state_t::not_applicable;
        status.reason = status.state == provider_state_t::available ? "Provider applies to the current classification" : "Provider does not apply to the current classification";
        return status;
    }

    provider_status_t attach(uint32_t pid, const process_diagnostics_t& diagnostics) override {
        provider_status_t status = query(pid, diagnostics);
        if (status.state == provider_state_t::not_applicable) return status;
        status.state = provider_state_t::needs_user_launch;
        status.active = false;
        status.reason = "Live target attach is not supported by this non-patching provider; use the recommended controlled launch or handoff action";
        status.evidence.push_back("no_live_attach");
        return status;
    }

    provider_status_t detach(uint32_t pid) override {
        provider_status_t status;
        status.descriptor = descriptor_;
        status.pid = pid;
        status.state = provider_state_t::detached;
        status.active = false;
        status.reason = "Provider state cleared for target";
        return status;
    }

private:
    provider_descriptor_t descriptor_;
    classification_t classification_;
};

provider_status_t missing_provider_status(const std::string& provider_id, uint32_t pid) {
    provider_status_t status;
    status.descriptor.provider_id = provider_id;
    status.descriptor.display_name = provider_id;
    status.pid = pid;
    status.state = provider_state_t::failed;
    status.reason = "Provider is not registered";
    return status;
}

}

std::string to_string(provider_state_t value) {
    switch (value) {
    case provider_state_t::available: return "available";
    case provider_state_t::needs_user_launch: return "needs_user_launch";
    case provider_state_t::attached: return "attached";
    case provider_state_t::failed: return "failed";
    case provider_state_t::detached: return "detached";
    default: return "not_applicable";
    }
}

provider_registry_t& provider_registry_t::instance() {
    static provider_registry_t registry;
    return registry;
}

void provider_registry_t::register_provider(std::shared_ptr<instrumentation_provider_t> provider) {
    if (!provider) return;
    std::lock_guard<std::mutex> lock(mutex_);
    providers_[provider->descriptor().provider_id] = std::move(provider);
}

void provider_registry_t::ensure_default_providers() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!providers_.empty()) return;
    for (auto& provider : make_default_providers()) {
        providers_[provider->descriptor().provider_id] = std::move(provider);
    }
}

std::vector<provider_descriptor_t> provider_registry_t::providers() {
    ensure_default_providers();
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<provider_descriptor_t> out;
    out.reserve(providers_.size());
    for (const auto& entry : providers_) out.push_back(entry.second->descriptor());
    return out;
}

std::vector<provider_status_t> provider_registry_t::evaluate(uint32_t pid, const process_diagnostics_t& diagnostics) {
    ensure_default_providers();
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<provider_status_t> out;
    auto& process_status = statuses_[pid];
    for (const auto& entry : providers_) {
        provider_status_t status = entry.second->query(pid, diagnostics);
        process_status[entry.first] = status;
        out.push_back(std::move(status));
    }
    return out;
}

std::vector<provider_status_t> provider_registry_t::status_for_process(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<provider_status_t> out;
    auto it = statuses_.find(pid);
    if (it == statuses_.end()) return out;
    for (const auto& entry : it->second) out.push_back(entry.second);
    return out;
}

provider_status_t provider_registry_t::attach(const std::string& provider_id, uint32_t pid, const process_diagnostics_t& diagnostics) {
    ensure_default_providers();
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = providers_.find(provider_id);
    if (it == providers_.end()) return missing_provider_status(provider_id, pid);
    provider_status_t status = it->second->attach(pid, diagnostics);
    statuses_[pid][provider_id] = status;
    return status;
}

provider_status_t provider_registry_t::detach(const std::string& provider_id, uint32_t pid) {
    ensure_default_providers();
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = providers_.find(provider_id);
    if (it == providers_.end()) return missing_provider_status(provider_id, pid);
    provider_status_t status = it->second->detach(pid);
    statuses_[pid][provider_id] = status;
    return status;
}

void provider_registry_t::clear_process(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    statuses_.erase(pid);
}

std::vector<std::shared_ptr<instrumentation_provider_t>> make_default_providers() {
    provider_descriptor_t windows_proxy;
    windows_proxy.provider_id = "windows_proxy_adapter";
    windows_proxy.display_name = "Windows proxy readiness";
    windows_proxy.intent = "Report proxy route and CA trust readiness";
    windows_proxy.behavior = "Uses controlled routing and trust state; never changes certificate verification results in target code";
    windows_proxy.forces_certificate_success = false;
    windows_proxy.requires_explicit_target = false;
    windows_proxy.supports_attach = false;

    provider_descriptor_t export_adapter;
    export_adapter.provider_id = "openssl_export_adapter";
    export_adapter.display_name = "OpenSSL export diagnostics";
    export_adapter.intent = "Prepare explicit handoff only for stable exported TLS APIs";
    export_adapter.behavior = "Reports export-level observability and script handoff readiness without returning forced success";
    export_adapter.forces_certificate_success = false;
    export_adapter.requires_explicit_target = true;
    export_adapter.supports_attach = false;

    provider_descriptor_t dotnet;
    dotnet.provider_id = "dotnet_adapter";
    dotnet.display_name = ".NET diagnostics";
    dotnet.intent = "Diagnose managed certificate validation callbacks";
    dotnet.behavior = "Reports managed runtime readiness for user-guided handoff without CLR patching";
    dotnet.forces_certificate_success = false;
    dotnet.requires_explicit_target = true;
    dotnet.supports_attach = false;

    return {
        std::make_shared<descriptor_provider_t>(windows_proxy, classification_t::ready),
        std::make_shared<descriptor_provider_t>(export_adapter, classification_t::app_specific_tls_stack),
        std::make_shared<descriptor_provider_t>(dotnet, classification_t::app_specific_tls_stack)
    };
}

}
