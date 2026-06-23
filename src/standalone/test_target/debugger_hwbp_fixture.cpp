#include "debugger_hwbp_fixture.h"

#include <cstdarg>
#include <cstdio>

namespace test_target {
namespace hwbp_fixture {

namespace {

constexpr std::uint32_t kMagic = 0x48574250u;
constexpr std::uint32_t kVersion = 1u;

static HANDLE s_thread = nullptr;
static HANDLE s_wake_event = nullptr;
static std::atomic<bool>* s_running = nullptr;
static bool s_verbose = false;
static volatile LONG64 s_watch_qword = 0x1122334455667788ll;
static volatile LONG64 s_hit_counter = 0;
static volatile LONG64 s_heartbeat = 0;

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::printf("[HWBP] ");
    std::vprintf(fmt, ap);
    std::printf("\n");
    std::fflush(stdout);
    va_end(ap);
}

static DWORD WINAPI fixture_thread(LPVOID) {
    aida_test_hwbp_descriptor.thread_id = GetCurrentThreadId();
    aida_test_hwbp_descriptor.thread_entry_va = reinterpret_cast<std::uint64_t>(&fixture_thread);
    aida_test_hwbp_descriptor.ready = 1u;
    aida_test_hwbp_descriptor.state = 1u;
    log("fixture thread started tid=%lu execute=0x%llX data=0x%llX",
        GetCurrentThreadId(),
        static_cast<unsigned long long>(aida_test_hwbp_descriptor.execute_fn_va),
        static_cast<unsigned long long>(aida_test_hwbp_descriptor.data_va));

    while (s_running && s_running->load(std::memory_order_acquire)) {
        InterlockedIncrement64(&s_heartbeat);
        WaitForSingleObject(s_wake_event, 50);
        ResetEvent(s_wake_event);
    }

    aida_test_hwbp_descriptor.state = 2u;
    log("fixture thread stopped tid=%lu heartbeat=%lld hits=%lld",
        GetCurrentThreadId(),
        static_cast<long long>(s_heartbeat),
        static_cast<long long>(s_hit_counter));
    return 0;
}

static void publish_descriptor() {
    aida_test_hwbp_descriptor.magic = kMagic;
    aida_test_hwbp_descriptor.version = kVersion;
    aida_test_hwbp_descriptor.size = sizeof(aida_test_hwbp_descriptor);
    aida_test_hwbp_descriptor.thread_id = 0;
    aida_test_hwbp_descriptor.ready = 0;
    aida_test_hwbp_descriptor.state = 0;
    aida_test_hwbp_descriptor.generation += 1u;
    aida_test_hwbp_descriptor.reserved = 0;
    aida_test_hwbp_descriptor.descriptor_va = reinterpret_cast<std::uint64_t>(&aida_test_hwbp_descriptor);
    aida_test_hwbp_descriptor.execute_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_hwbp_execute_probe);
    aida_test_hwbp_descriptor.data_va = reinterpret_cast<std::uint64_t>(&s_watch_qword);
    aida_test_hwbp_descriptor.data_size = sizeof(s_watch_qword);
    aida_test_hwbp_descriptor.hit_counter_va = reinterpret_cast<std::uint64_t>(&s_hit_counter);
    aida_test_hwbp_descriptor.heartbeat_va = reinterpret_cast<std::uint64_t>(&s_heartbeat);
    aida_test_hwbp_descriptor.thread_entry_va = reinterpret_cast<std::uint64_t>(&fixture_thread);
}

}

void init(const config_t& cfg, std::atomic<bool>& running) {
    if (s_thread)
        return;

    s_verbose = cfg.verbose;
    s_running = &running;
    publish_descriptor();
    s_wake_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!s_wake_event) {
        aida_test_hwbp_descriptor.state = 3u;
        log("fixture event create failed gle=%lu", GetLastError());
        return;
    }

    DWORD tid = 0;
    s_thread = CreateThread(nullptr, 0, fixture_thread, nullptr, 0, &tid);
    if (!s_thread) {
        aida_test_hwbp_descriptor.state = 4u;
        log("fixture thread create failed gle=%lu", GetLastError());
        CloseHandle(s_wake_event);
        s_wake_event = nullptr;
        return;
    }

    for (int i = 0; i < 40 && aida_test_hwbp_descriptor.ready == 0; ++i)
        Sleep(25);

    if (s_verbose || aida_test_hwbp_descriptor.ready == 0) {
        log("fixture init ready=%u tid=%u thread_handle=%p generation=%u",
            aida_test_hwbp_descriptor.ready,
            aida_test_hwbp_descriptor.thread_id,
            s_thread,
            aida_test_hwbp_descriptor.generation);
    }
}

void shutdown_all() {
    if (s_wake_event)
        SetEvent(s_wake_event);

    if (s_thread) {
        DWORD wr = WaitForSingleObject(s_thread, 2000);
        log("fixture shutdown wait=0x%08lX gle=%lu tid=%u heartbeat=%lld",
            wr,
            wr == WAIT_FAILED ? GetLastError() : 0,
            aida_test_hwbp_descriptor.thread_id,
            static_cast<long long>(s_heartbeat));
        CloseHandle(s_thread);
        s_thread = nullptr;
    }

    if (s_wake_event) {
        CloseHandle(s_wake_event);
        s_wake_event = nullptr;
    }

    aida_test_hwbp_descriptor.ready = 0;
    aida_test_hwbp_descriptor.state = 0;
    aida_test_hwbp_descriptor.thread_id = 0;
    s_running = nullptr;
}

std::uint64_t execute_probe_impl(std::uint64_t seed) noexcept {
    InterlockedIncrement64(&s_hit_counter);
    s_watch_qword ^= static_cast<LONG64>(seed | 1ull);
    return static_cast<std::uint64_t>(s_watch_qword) ^
        static_cast<std::uint64_t>(s_hit_counter);
}

}
}

extern "C" AIDA_TEST_TARGET_HWBP_API test_target::hwbp_fixture::descriptor_t aida_test_hwbp_descriptor = {
    0x48574250u,
    1u,
    sizeof(test_target::hwbp_fixture::descriptor_t),
    0u,
    0u,
    0u,
    0u,
    0u,
    0ull,
    0ull,
    0ull,
    0ull,
    0ull,
    0ull,
    0ull
};

extern "C" AIDA_TEST_TARGET_HWBP_API __declspec(noinline) const test_target::hwbp_fixture::descriptor_t* aida_test_hwbp_get_descriptor() noexcept {
    return &aida_test_hwbp_descriptor;
}

extern "C" AIDA_TEST_TARGET_HWBP_API __declspec(noinline) std::uint64_t aida_test_hwbp_execute_probe(std::uint64_t seed) noexcept {
    return test_target::hwbp_fixture::execute_probe_impl(seed);
}
