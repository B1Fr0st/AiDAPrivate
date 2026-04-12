#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <thread>
#include <algorithm>
#include <cctype>

#include "standalone_driver.hpp"

namespace pre_encrypt_hook {

struct hook_target_t {
    std::string library_name;
    std::string function_name;
    uint64_t address = 0;
    uint32_t buffer_reg = 1;
    uint32_t size_reg = 2;
    bool active = false;
    uint32_t bp_index = 0;
};

struct plaintext_capture_t {
    uint64_t timestamp = 0;
    uint32_t tid = 0;
    std::string function_name;
    std::vector<uint8_t> buffer;
    uint64_t rip = 0;
    std::string module_name;
    uint64_t module_offset = 0;
};

struct state_t {
    std::vector<hook_target_t> targets;
    std::deque<plaintext_capture_t> captures;
    std::mutex mutex;
    std::atomic<bool> active{false};
    std::atomic<bool> polling{false};
    size_t max_captures = 4096;
    uint32_t attached_pid = 0;
    std::vector<driver_bridge::module_info_t> cached_modules;
    std::thread poll_thread;
};

inline state_t g_state;

struct known_target_t {
    const char* module_pattern;
    const char* export_name;
    uint32_t buffer_reg;
    uint32_t size_reg;
};

inline const known_target_t g_known_targets[] = {
    { "libssl",    "SSL_write",        1, 2 },
    { "ssleay32",  "SSL_write",        1, 2 },
    { "nss3",      "PR_Write",         1, 2 },
    { "sspicli",   "EncryptMessage",   1, 2 },
    { "secur32",   "EncryptMessage",   1, 2 },
    { "ncrypt",    "SslEncryptPacket", 1, 2 },
    { "ws2_32",    "send",             1, 2 },
    { "ws2_32",    "WSASend",          1, 2 },
};

inline bool ci_contains(const std::string& haystack, const char* needle) {
    std::string lower_h = haystack;
    std::string lower_n = needle;
    std::transform(lower_h.begin(), lower_h.end(), lower_h.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(lower_n.begin(), lower_n.end(), lower_n.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower_h.find(lower_n) != std::string::npos;
}

inline std::string resolve_module_from_rip(uint64_t rip, uint64_t& offset_out) {
    offset_out = 0;
    for (const auto& mod : g_state.cached_modules) {
        if (rip >= mod.base && rip < mod.base + mod.size) {
            offset_out = rip - mod.base;
            return mod.name;
        }
    }
    return {};
}

inline bool hook_address(uint64_t address, const std::string& name,
                         uint32_t buffer_reg, uint32_t size_reg) {
    if (!driver_bridge::using_kernel_driver())
        return false;

    std::lock_guard<std::mutex> lock(g_state.mutex);

    uint32_t bp_slot = 0;
    bool found_slot = false;
    for (uint32_t i = 0; i < 4; ++i) {
        bool used = false;
        for (const auto& t : g_state.targets) {
            if (t.active && t.bp_index == i) {
                used = true;
                break;
            }
        }
        if (!used) {
            bp_slot = i;
            found_slot = true;
            break;
        }
    }
    if (!found_slot)
        return false;

    for (const auto& t : g_state.targets) {
        if (t.active && t.address == address)
            return true;
    }

    if (!driver_bridge::sniff_net_buffers_start(address, buffer_reg, size_reg, 16, 0, bp_slot))
        return false;

    hook_target_t target;
    target.library_name = {};
    target.function_name = name;
    target.address = address;
    target.buffer_reg = buffer_reg;
    target.size_reg = size_reg;
    target.active = true;
    target.bp_index = bp_slot;
    g_state.targets.push_back(std::move(target));
    g_state.active.store(true);

    return true;
}

inline bool auto_hook(uint32_t pid) {
    if (!driver_bridge::using_kernel_driver())
        return false;

    if (!driver_bridge::is_loaded())
        return false;

    if (driver_bridge::attached_pid() != pid) {
        if (!driver_bridge::attach(pid))
            return false;
    }

    auto modules = driver_bridge::enumerate_modules();
    if (modules.empty())
        return false;

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.cached_modules = modules;
        g_state.attached_pid = pid;
    }

    uint32_t hooked = 0;
    constexpr uint32_t max_hooks = 4;

    for (const auto& known : g_known_targets) {
        if (hooked >= max_hooks)
            break;

        for (const auto& mod : modules) {
            if (hooked >= max_hooks)
                break;

            if (!ci_contains(mod.name, known.module_pattern))
                continue;

            uint64_t func_addr = driver_bridge::resolve_export(mod.base, known.export_name);
            if (func_addr == 0)
                continue;

            std::string hook_name = mod.name + "!" + known.export_name;
            if (hook_address(func_addr, hook_name, known.buffer_reg, known.size_reg))
                ++hooked;
        }
    }

    return hooked > 0;
}

inline void unhook_all() {
    g_state.polling.store(false);

    if (g_state.poll_thread.joinable())
        g_state.poll_thread.join();

    std::lock_guard<std::mutex> lock(g_state.mutex);

    if (driver_bridge::using_kernel_driver()) {
        for (auto& t : g_state.targets) {
            if (t.active) {
                driver_bridge::sniff_net_buffers_stop();
                t.active = false;
            }
        }
    }

    g_state.targets.clear();
    g_state.active.store(false);
}

inline void poll_captures() {
    if (!driver_bridge::using_kernel_driver())
        return;

    bool active = false;
    auto results = driver_bridge::sniff_net_buffers_get(active);

    if (results.empty())
        return;

    std::lock_guard<std::mutex> lock(g_state.mutex);

    for (auto& r : results) {
        plaintext_capture_t cap;
        cap.timestamp = r.timestamp;
        cap.tid = static_cast<uint32_t>(r.thread_id);
        cap.buffer = std::move(r.buffer);
        cap.rip = 0;

        if (!g_state.targets.empty())
            cap.function_name = g_state.targets[0].function_name;

        uint64_t mod_offset = 0;
        cap.module_name = resolve_module_from_rip(cap.rip, mod_offset);
        cap.module_offset = mod_offset;

        g_state.captures.push_back(std::move(cap));
    }

    while (g_state.captures.size() > g_state.max_captures)
        g_state.captures.pop_front();
}

inline void start_polling() {
    if (g_state.polling.load())
        return;

    g_state.polling.store(true);

    g_state.poll_thread = std::thread([]() {
        while (g_state.polling.load()) {
            poll_captures();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}

inline void stop_polling() {
    g_state.polling.store(false);
    if (g_state.poll_thread.joinable())
        g_state.poll_thread.join();
}

inline std::vector<plaintext_capture_t> get_captures(size_t max_count = 64) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    std::vector<plaintext_capture_t> result;

    size_t count = (std::min)(max_count, g_state.captures.size());
    auto it = g_state.captures.end();
    if (count <= g_state.captures.size())
        it = g_state.captures.end() - static_cast<ptrdiff_t>(count);
    else
        it = g_state.captures.begin();

    for (; it != g_state.captures.end(); ++it)
        result.push_back(*it);

    return result;
}

inline void clear_captures() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.captures.clear();
}

inline bool is_active() {
    return g_state.active.load();
}

}
