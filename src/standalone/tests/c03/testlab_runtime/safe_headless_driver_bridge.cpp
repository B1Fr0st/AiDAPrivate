#if !defined(AIDA_C03_SAFE_HEADLESS_RUNTIME) || AIDA_C03_SAFE_HEADLESS_RUNTIME != 1
#error AIDA_C03_SAFE_HEADLESS_RUNTIME_must_equal_1
#endif

#include "../../../src/core/runtime/standalone_driver.hpp"
#include "../../../src/core/runtime/standalone_driver_identity.hpp"

namespace driver_bridge {

bool is_loaded()
{
    return false;
}

bool using_kernel_driver()
{
    return false;
}

bool attach(uint32_t)
{
    return false;
}

bool attach_additional(uint32_t)
{
    return false;
}

bool set_active_pid(uint32_t)
{
    return false;
}

bool detach_one(uint32_t)
{
    return false;
}

bool clear_active_pid()
{
    return false;
}

std::vector<uint32_t> attached_pids()
{
    return {};
}

std::string last_error()
{
    return "Safe headless runtime prohibits driver and process access";
}

uint32_t attached_pid()
{
    return 0;
}

std::vector<module_info_t> enumerate_modules()
{
    return {};
}

std::vector<thread_info_t> enumerate_threads()
{
    return {};
}

bool read_memory(uint64_t, size_t, std::vector<uint8_t>& out)
{
    out.clear();
    return false;
}

bool write_memory(uint64_t, const std::vector<uint8_t>&)
{
    return false;
}

bool read_memory_for(uint32_t, uint64_t, size_t, std::vector<uint8_t>& out)
{
    out.clear();
    return false;
}

std::vector<module_info_t> enumerate_modules_for(uint32_t)
{
    return {};
}

bool verify_cross_ring_evidence(const uint8_t*, uint32_t)
{
    return false;
}

uint64_t allocate_memory(size_t)
{
    return 0;
}

bool free_memory(uint64_t)
{
    return false;
}

bool protect_memory(uint64_t, uint64_t, uint32_t, uint32_t* old_protect)
{
    if (old_protect)
        *old_protect = 0;
    return false;
}

bool get_thread_context(uint32_t, thread_context_t& context)
{
    context = {};
    return false;
}

bool set_thread_context(uint32_t, const thread_context_t&, uint64_t)
{
    return false;
}

bool spoof_debug_flags(uint32_t* result_flags)
{
    if (result_flags)
        *result_flags = 0;
    return false;
}

bool trigger_kernel_bsod(uint32_t, uint64_t)
{
    return false;
}

}

namespace driver_bridge::identity {

const char* staleness_code(staleness_t value) noexcept
{
    switch (value) {
    case staleness_t::none: return "NONE";
    case staleness_t::self_target_refused: return "SELF_TARGET_REFUSED";
    case staleness_t::process_unavailable: return "TARGET_PROCESS_UNAVAILABLE";
    case staleness_t::process_exited: return "TARGET_PROCESS_EXITED";
    case staleness_t::process_identity_changed: return "TARGET_PROCESS_IDENTITY_CHANGED";
    case staleness_t::module_unavailable: return "TARGET_MODULE_UNAVAILABLE";
    case staleness_t::module_identity_changed: return "TARGET_MODULE_IDENTITY_CHANGED";
    }
    return "TARGET_IDENTITY_UNKNOWN";
}

bool capture_live_target_identity(std::uint32_t, std::uint64_t,
    live_target_identity_t& out, std::string* out_error)
{
    out = {};
    if (out_error)
        *out_error = "TARGET_PROCESS_UNAVAILABLE: safe headless runtime prohibits process identity capture";
    return false;
}

validation_result_t validate_live_target_identity(const live_target_identity_t&)
{
    validation_result_t result;
    result.matches = false;
    result.staleness = staleness_t::process_unavailable;
    result.detail = "Safe headless runtime prohibits process identity validation";
    return result;
}

validation_result_t validate_attached_target_identity(const live_target_identity_t&)
{
    validation_result_t result;
    result.matches = false;
    result.staleness = staleness_t::process_unavailable;
    result.detail = "Safe headless runtime has no attached target identity";
    return result;
}

bool refresh_attached_target_identity(const live_target_identity_t&, std::string* out_error)
{
    if (out_error)
        *out_error = "TARGET_PROCESS_UNAVAILABLE: safe headless runtime has no attached target identity";
    return false;
}

}
