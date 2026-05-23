#include "thread_tests.h"
#include "test_log.h"
#include <cstdio>
#include <cstring>

namespace test_target {
namespace threads {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[THR] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static constexpr int kMaxWorkers = 8;

struct worker_context_t {
    int                id;
    DWORD              sleep_ms;
    std::atomic<bool>* running;
    bool               verbose;
    HANDLE             thread_handle;
    HANDLE             event_handle;
    volatile LONG      counter;
};

static CRITICAL_SECTION s_mutex;
static HANDLE           s_shared_event = nullptr;
static worker_context_t s_workers[kMaxWorkers]{};
static int              s_worker_count = 0;
static bool             s_initialized = false;

static DWORD WINAPI fast_counter_worker(LPVOID param) {
    worker_context_t* ctx = (worker_context_t*)param;
    log("Worker %d started (fast counter, sleep=%dms)", ctx->id, ctx->sleep_ms);

    while (ctx->running->load()) {
        InterlockedIncrement(&ctx->counter);
        Sleep(ctx->sleep_ms);
    }

    log("Worker %d stopped (counter=%ld)", ctx->id, ctx->counter);
    return 0;
}

static DWORD WINAPI event_waiter_worker(LPVOID param) {
    worker_context_t* ctx = (worker_context_t*)param;
    log("Worker %d started (event waiter)", ctx->id);

    while (ctx->running->load()) {
        DWORD wait = WaitForSingleObject(ctx->event_handle, 500);
        if (wait == WAIT_OBJECT_0) {
            EnterCriticalSection(&s_mutex);
            InterlockedIncrement(&ctx->counter);
            if (ctx->verbose) {
                log("Worker %d event signaled (count=%ld)", ctx->id, ctx->counter);
            }
            LeaveCriticalSection(&s_mutex);
        }
    }

    log("Worker %d stopped (events received=%ld)", ctx->id, ctx->counter);
    return 0;
}

static DWORD WINAPI mutex_contention_worker(LPVOID param) {
    worker_context_t* ctx = (worker_context_t*)param;
    log("Worker %d started (mutex contention, sleep=%dms)", ctx->id, ctx->sleep_ms);

    while (ctx->running->load()) {
        EnterCriticalSection(&s_mutex);
        InterlockedIncrement(&ctx->counter);
        Sleep(1);
        LeaveCriticalSection(&s_mutex);
        Sleep(ctx->sleep_ms);
    }

    log("Worker %d stopped (lock acquisitions=%ld)", ctx->id, ctx->counter);
    return 0;
}

static DWORD WINAPI busy_spin_worker(LPVOID param) {
    worker_context_t* ctx = (worker_context_t*)param;
    log("Worker %d started (busy spin, yield every 1000 iterations)", ctx->id);

    while (ctx->running->load()) {
        for (int i = 0; i < 1000 && ctx->running->load(); ++i) {
            InterlockedIncrement(&ctx->counter);
        }
        SwitchToThread();
        Sleep(ctx->sleep_ms);
    }

    log("Worker %d stopped (iterations=%ld)", ctx->id, ctx->counter);
    return 0;
}

static DWORD WINAPI event_producer_worker(LPVOID param) {
    worker_context_t* ctx = (worker_context_t*)param;
    log("Worker %d started (event producer, interval=%dms)", ctx->id, ctx->sleep_ms);

    while (ctx->running->load()) {
        if (s_shared_event) {
            SetEvent(s_shared_event);
            InterlockedIncrement(&ctx->counter);
        }
        Sleep(ctx->sleep_ms);
    }

    log("Worker %d stopped (events produced=%ld)", ctx->id, ctx->counter);
    return 0;
}

static DWORD WINAPI io_simulator_worker(LPVOID param) {
    worker_context_t* ctx = (worker_context_t*)param;
    log("Worker %d started (I/O simulator, sleep=%dms)", ctx->id, ctx->sleep_ms);

    HANDLE timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    if (!timer) {
        log("Worker %d failed to create waitable timer: %lu", ctx->id, GetLastError());
        return 1;
    }

    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)(ctx->sleep_ms * 10000LL);
    SetWaitableTimer(timer, &due, ctx->sleep_ms, nullptr, nullptr, FALSE);

    while (ctx->running->load()) {
        DWORD wait = WaitForSingleObject(timer, ctx->sleep_ms * 2);
        if (wait == WAIT_OBJECT_0) {
            InterlockedIncrement(&ctx->counter);
        }
    }

    CancelWaitableTimer(timer);
    CloseHandle(timer);
    log("Worker %d stopped (timer ticks=%ld)", ctx->id, ctx->counter);
    return 0;
}

static DWORD WINAPI priority_worker(LPVOID param) {
    worker_context_t* ctx = (worker_context_t*)param;

    int priority = THREAD_PRIORITY_NORMAL;
    const char* priority_name = "NORMAL";
    switch (ctx->id % 3) {
        case 0: priority = THREAD_PRIORITY_BELOW_NORMAL; priority_name = "BELOW_NORMAL"; break;
        case 1: priority = THREAD_PRIORITY_NORMAL;       priority_name = "NORMAL";       break;
        case 2: priority = THREAD_PRIORITY_ABOVE_NORMAL; priority_name = "ABOVE_NORMAL"; break;
    }
    SetThreadPriority(GetCurrentThread(), priority);
    log("Worker %d started (priority=%s, sleep=%dms)", ctx->id, priority_name, ctx->sleep_ms);

    while (ctx->running->load()) {
        InterlockedIncrement(&ctx->counter);
        Sleep(ctx->sleep_ms);
    }

    log("Worker %d stopped (counter=%ld)", ctx->id, ctx->counter);
    return 0;
}

static DWORD WINAPI suspended_resume_worker(LPVOID param) {
    worker_context_t* ctx = (worker_context_t*)param;
    log("Worker %d started (suspend/resume cycle)", ctx->id);

    while (ctx->running->load()) {
        InterlockedIncrement(&ctx->counter);
        Sleep(ctx->sleep_ms);
    }

    log("Worker %d stopped (cycles=%ld)", ctx->id, ctx->counter);
    return 0;
}

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== Thread tests starting ===");

    if (!s_initialized) {
        InitializeCriticalSection(&s_mutex);
        s_shared_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        s_initialized = true;
    }

    struct worker_def {
        LPTHREAD_START_ROUTINE fn;
        DWORD sleep_ms;
        const char* desc;
    };

    worker_def defs[] = {
        { fast_counter_worker,      50,  "fast counter (50ms)" },
        { fast_counter_worker,      200, "fast counter (200ms)" },
        { event_waiter_worker,      0,   "event waiter" },
        { mutex_contention_worker,  100, "mutex contention (100ms)" },
        { busy_spin_worker,         150, "busy spin (150ms)" },
        { event_producer_worker,    300, "event producer (300ms)" },
        { io_simulator_worker,      500, "I/O simulator (500ms)" },
        { priority_worker,          250, "priority thread (250ms)" },
    };

    s_worker_count = kMaxWorkers;

    for (int i = 0; i < s_worker_count; ++i) {
        s_workers[i].id = i;
        s_workers[i].sleep_ms = defs[i].sleep_ms;
        s_workers[i].running = &running;
        s_workers[i].verbose = cfg.verbose;
        s_workers[i].counter = 0;
        s_workers[i].event_handle = s_shared_event;

        DWORD tid = 0;
        DWORD flags = (i == s_worker_count - 1) ? CREATE_SUSPENDED : 0;
        s_workers[i].thread_handle = CreateThread(
            nullptr, 0, defs[i].fn, &s_workers[i], flags, &tid);

        if (s_workers[i].thread_handle) {
            log("Spawned worker %d (tid=%lu): %s", i, tid, defs[i].desc);

            if (flags & CREATE_SUSPENDED) {
                Sleep(100);
                ResumeThread(s_workers[i].thread_handle);
                log("Resumed suspended worker %d", i);
            }
        }
    }

    log("=== %d worker threads spawned ===", s_worker_count);
}

void shutdown_all() {
    log("Shutting down worker threads...");

    HANDLE handles[kMaxWorkers];
    int valid = 0;
    for (int i = 0; i < s_worker_count; ++i) {
        if (s_workers[i].thread_handle) {
            handles[valid++] = s_workers[i].thread_handle;
        }
    }

    if (valid > 0) {
        if (s_shared_event) SetEvent(s_shared_event);
        WaitForMultipleObjects(valid, handles, TRUE, 5000);
    }

    for (int i = 0; i < s_worker_count; ++i) {
        if (s_workers[i].thread_handle) {
            CloseHandle(s_workers[i].thread_handle);
            s_workers[i].thread_handle = nullptr;
        }
    }

    if (s_shared_event) {
        CloseHandle(s_shared_event);
        s_shared_event = nullptr;
    }

    if (s_initialized) {
        DeleteCriticalSection(&s_mutex);
        s_initialized = false;
    }

    log("All worker threads shut down");
}

}
}
