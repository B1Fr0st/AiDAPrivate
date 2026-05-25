#pragma once

#include "standalone_driver.hpp"
#include "intercept/diagnostics.hpp"

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#ifndef AIDA_CERT_PIN_BYPASS_LEGACY_LAB
#define AIDA_CERT_PIN_BYPASS_LEGACY_LAB 0
#endif

namespace cert_pin_bypass {

struct bypass_signature {
    std::string name;
    std::string module_name;
    std::string description;
    std::vector<uint8_t> pattern;
    std::vector<uint8_t> mask;
    std::vector<uint8_t> patch;
    bool return_success = false;
    std::vector<std::string> string_hints;
    std::string export_name;
};

struct applied_bypass {
    std::string signature_name;
    std::string module_name;
    uint64_t address = 0;
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> patch_bytes;
    bool active = false;
};

struct state_t {
    uint32_t target_pid = 0;
    std::string target_process;
    bool attached = false;
    std::mutex mutex;
    std::vector<applied_bypass> active_bypasses;
    std::vector<bypass_signature> signatures;
    std::string last_disabled_reason;
    cert_intercept::process_diagnostics_t last_diagnostics;
};

inline state_t g_state;

inline bypass_signature make_disabled_descriptor() {
    bypass_signature sig;
    sig.name = "Stable intercept migration";
    sig.module_name = "intercept";
    sig.description = "Non-patching compatibility descriptor";
    sig.return_success = false;
    return sig;
}

inline void init_signature_database() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.signatures.clear();
    g_state.signatures.push_back(make_disabled_descriptor());
}

inline bool pattern_match(const uint8_t* data, size_t data_size,
                          const uint8_t* pattern, const uint8_t* mask, size_t pattern_size) {
    if (!data || !pattern || !mask) return false;
    if (data_size < pattern_size) return false;
    for (size_t i = 0; i < pattern_size; i++) {
        if ((data[i] & mask[i]) != (pattern[i] & mask[i])) return false;
    }
    return true;
}

inline int scan_and_bypass(uint32_t target_pid) {
    cert_intercept::diagnostic_context_t context;
    context.proxy_running = false;
    context.ca_trusted = false;
    context.interception_still_failing = true;

    cert_intercept::process_diagnostics_t diagnostics;
    if (target_pid != 0 && driver_bridge::is_loaded()) {
        diagnostics = cert_intercept::diagnose_process(target_pid, context);
    } else {
        diagnostics.pid = target_pid;
        diagnostics.primary = cert_intercept::classification_t::unsupported_target;
        diagnostics.summary = "Interception diagnostics require a live target and module enumeration";
        diagnostics.read_only = true;
    }

    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.target_pid = target_pid;
    g_state.attached = false;
    g_state.last_disabled_reason = "Code patching is disabled; use stable interception diagnostics and provider handoff";
    g_state.last_diagnostics = std::move(diagnostics);
    g_state.active_bypasses.erase(
        std::remove_if(g_state.active_bypasses.begin(), g_state.active_bypasses.end(),
            [](const applied_bypass& bypass) { return !bypass.active; }),
        g_state.active_bypasses.end());
    if (g_state.signatures.empty()) {
        g_state.signatures.push_back(make_disabled_descriptor());
    }
    return 0;
}

inline int revert_all_bypasses() {
    uint32_t target_pid = 0;
    std::vector<applied_bypass> snapshot;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        if (g_state.active_bypasses.empty()) {
            g_state.target_pid = 0;
            g_state.attached = false;
            return 0;
        }
        target_pid = g_state.target_pid;
        for (const auto& bypass : g_state.active_bypasses) {
            if (bypass.active && bypass.address != 0 && !bypass.original_bytes.empty())
                snapshot.push_back(bypass);
        }
    }
    if (!driver_bridge::using_kernel_driver()) return -1;
    if (target_pid == 0 || snapshot.empty()) return 0;

    const uint32_t original_pid = driver_bridge::attached_pid();
    if (!driver_bridge::attach(target_pid)) {
        if (original_pid) driver_bridge::attach(original_pid);
        return -1;
    }

    int reverted = 0;
    std::vector<uint64_t> reverted_addresses;
    for (const auto& bypass : snapshot) {
        if (driver_bridge::write_memory(bypass.address, bypass.original_bytes)) {
            reverted_addresses.push_back(bypass.address);
            reverted++;
        }
    }

    driver_bridge::detach();
    if (original_pid) driver_bridge::attach(original_pid);

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (auto& bypass : g_state.active_bypasses) {
            if (std::find(reverted_addresses.begin(), reverted_addresses.end(), bypass.address) != reverted_addresses.end()) {
                bypass.active = false;
                bypass.patch_bytes.clear();
                bypass.original_bytes.clear();
            }
        }
        g_state.active_bypasses.erase(
            std::remove_if(g_state.active_bypasses.begin(), g_state.active_bypasses.end(),
                [](const applied_bypass& bypass) { return !bypass.active; }),
            g_state.active_bypasses.end());
        if (g_state.active_bypasses.empty()) {
            g_state.target_pid = 0;
            g_state.attached = false;
        }
    }
    return reverted;
}

inline std::vector<applied_bypass> get_active_bypasses() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    std::vector<applied_bypass> active;
    for (const auto& bypass : g_state.active_bypasses) {
        if (bypass.active) active.push_back(bypass);
    }
    return active;
}

inline bool is_bypass_active() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (const auto& bypass : g_state.active_bypasses) {
        if (bypass.active) return true;
    }
    return false;
}

inline cert_intercept::process_diagnostics_t get_last_diagnostics() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.last_diagnostics;
}

inline std::string get_disabled_reason() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.last_disabled_reason;
}

inline void add_custom_signature(bypass_signature sig) {
#if AIDA_CERT_PIN_BYPASS_LEGACY_LAB
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.signatures.push_back(std::move(sig));
#else
    (void)sig;
#endif
}

}
