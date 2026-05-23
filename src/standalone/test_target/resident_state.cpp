#include "resident_state.h"
#include "test_log.h"

#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>

namespace test_target {
namespace resident {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[res] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

struct list_node_t {
    uint32_t     id;
    uint64_t     value;
    char         label[24];
    list_node_t* next;
};

static uint64_t          g_magic_u64 = 0xCAFEBABE00000001ULL;
static uint8_t           g_blob16[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};
static std::string       g_ascii_text = "AiDA_Resident_Ascii_Marker";
static std::wstring      g_wide_text = L"AiDA_Resident_Wide_Marker";
static list_node_t*      g_list_root = nullptr;

static std::atomic<bool>* g_running = nullptr;
static config_t           g_cfg{};

static constexpr int kWorkerCount = 4;
static HANDLE s_updater_thread = nullptr;
static HANDLE s_worker_threads[kWorkerCount] = { nullptr };
static int    s_worker_used = 0;

static HANDLE s_temp_file = INVALID_HANDLE_VALUE;
static HANDLE s_named_event = nullptr;
static HANDLE s_named_mutex = nullptr;
static wchar_t s_temp_path[MAX_PATH] = { 0 };

struct worker_context_t {
    int               id;
    uint32_t          interval_ms;
    const char*       name;
    volatile uint64_t accumulator;
};

static worker_context_t s_worker_ctx[kWorkerCount]{};

static bool running_now() {
    return g_running && g_running->load();
}

static void interruptible_sleep(uint32_t ms) {
    uint32_t slept = 0;
    while (slept < ms && running_now()) {
        uint32_t step = ms - slept;
        if (step > 200) step = 200;
        Sleep(step);
        slept += step;
    }
}

uint64_t __declspec(noinline) resident_mix_leaf(uint64_t seed, uint32_t salt) {
    uint64_t r = seed ^ ((uint64_t)salt << 32);
    r ^= r >> 33;
    r *= 0xFF51AFD7ED558CCDULL;
    r ^= r >> 33;
    r *= 0xC4CEB9FE1A85EC53ULL;
    r ^= r >> 33;
    return r;
}

uint64_t __declspec(noinline) resident_mix_mid(uint64_t seed) {
    uint64_t a = resident_mix_leaf(seed, 0x1001);
    uint64_t b = resident_mix_leaf(seed + 1, 0x2002);
    return a + (b << 1);
}

uint64_t __declspec(noinline) resident_mix_outer(uint64_t seed, int rounds) {
    uint64_t acc = seed;
    for (int i = 0; i < rounds; ++i) {
        acc = resident_mix_mid(acc + (uint64_t)i);
    }
    return acc;
}

static void build_list() {
    list_node_t* head = nullptr;
    for (int i = 3; i >= 0; --i) {
        list_node_t* node = new list_node_t();
        node->id = (uint32_t)i;
        node->value = resident_mix_outer(0xA5A5A5A5ULL + (uint64_t)i, 3);
        sprintf_s(node->label, sizeof(node->label), "node_%d", i);
        node->next = head;
        head = node;
    }
    g_list_root = head;
}

static void free_list() {
    list_node_t* cur = g_list_root;
    while (cur) {
        list_node_t* next = cur->next;
        delete cur;
        cur = next;
    }
    g_list_root = nullptr;
}

static DWORD WINAPI state_updater_thread(LPVOID param) {
    (void)param;
    log("state-updater thread started");

    uint64_t tick = 0;
    while (running_now()) {
        g_magic_u64 = 0xCAFEBABE00000001ULL + tick;
        for (int i = 0; i < 16; ++i) {
            g_blob16[i] = (uint8_t)(g_blob16[i] + (uint8_t)(tick + i));
        }
        for (list_node_t* cur = g_list_root; cur; cur = cur->next) {
            cur->value = resident_mix_mid(cur->value + tick);
        }
        if (s_named_event) {
            SetEvent(s_named_event);
        }
        if (g_cfg.verbose && (tick % 20 == 0)) {
            log("state-updater tick=%llu magic=0x%016llX blob0=0x%02X node_root_value=0x%016llX",
                tick, g_magic_u64, g_blob16[0], g_list_root ? g_list_root->value : 0ULL);
        }
        tick++;
        interruptible_sleep(500);
    }

    log("state-updater thread stopped (ticks=%llu)", tick);
    return 0;
}

static DWORD WINAPI arithmetic_worker_thread(LPVOID param) {
    worker_context_t* ctx = (worker_context_t*)param;
    log("worker '%s' (id=%d) started interval=%ums", ctx->name, ctx->id, ctx->interval_ms);

    uint64_t iterations = 0;
    while (running_now()) {
        uint64_t v = resident_mix_outer(ctx->accumulator + iterations, 2 + ctx->id);
        ctx->accumulator += (v & 0xFFFF);
        iterations++;
        interruptible_sleep(ctx->interval_ms);
    }

    log("worker '%s' (id=%d) stopped iterations=%llu accumulator=0x%016llX",
        ctx->name, ctx->id, iterations, (uint64_t)ctx->accumulator);
    return 0;
}

static void open_handles() {
    wchar_t dir[MAX_PATH] = { 0 };
    DWORD dlen = GetTempPathW(MAX_PATH, dir);
    if (dlen == 0 || dlen > MAX_PATH) {
        wcscpy_s(dir, MAX_PATH, L".\\");
    }
    swprintf_s(s_temp_path, MAX_PATH, L"%saida_testtarget_%lu.dat", dir, GetCurrentProcessId());

    s_temp_file = CreateFileW(
        s_temp_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY,
        nullptr);
    if (s_temp_file != INVALID_HANDLE_VALUE) {
        const char* seed = "AIDA_TEST_TARGET_RESIDENT_FILE";
        DWORD written = 0;
        WriteFile(s_temp_file, seed, (DWORD)strlen(seed), &written, nullptr);
        FlushFileBuffers(s_temp_file);
        log("opened temp file handle=%p path=%ls", (void*)s_temp_file, s_temp_path);
    } else {
        log("temp file open FAILED (err=%lu)", GetLastError());
    }

    wchar_t event_name[128];
    swprintf_s(event_name, 128, L"Local\\AiDATestTargetResident_%lu", GetCurrentProcessId());
    s_named_event = CreateEventW(nullptr, FALSE, FALSE, event_name);
    if (s_named_event) {
        log("opened named event handle=%p name=%ls", (void*)s_named_event, event_name);
    } else {
        log("named event open FAILED (err=%lu)", GetLastError());
    }

    wchar_t mutex_name[128];
    swprintf_s(mutex_name, 128, L"Local\\AiDATestTargetResidentMutex_%lu", GetCurrentProcessId());
    s_named_mutex = CreateMutexW(nullptr, FALSE, mutex_name);
    if (s_named_mutex) {
        log("opened named mutex handle=%p name=%ls", (void*)s_named_mutex, mutex_name);
    } else {
        log("named mutex open FAILED (err=%lu)", GetLastError());
    }
}

static void close_handles() {
    if (s_temp_file != INVALID_HANDLE_VALUE) {
        CloseHandle(s_temp_file);
        s_temp_file = INVALID_HANDLE_VALUE;
        DeleteFileW(s_temp_path);
        log("closed temp file handle and removed %ls", s_temp_path);
    }
    if (s_named_event) {
        CloseHandle(s_named_event);
        s_named_event = nullptr;
        log("closed named event handle");
    }
    if (s_named_mutex) {
        CloseHandle(s_named_mutex);
        s_named_mutex = nullptr;
        log("closed named mutex handle");
    }
}

void init(const config_t& cfg, std::atomic<bool>& running) {
    g_cfg = cfg;
    g_running = &running;

    log("=== resident state init ===");

    build_list();

    log("g_magic_u64       @ %p = 0x%016llX", (void*)&g_magic_u64, g_magic_u64);
    log("g_blob16          @ %p (16 bytes)", (void*)g_blob16);
    log("g_ascii_text      @ %p data@ %p = \"%s\"", (void*)&g_ascii_text, (void*)g_ascii_text.data(), g_ascii_text.c_str());
    log("g_wide_text       @ %p data@ %p = \"%ls\"", (void*)&g_wide_text, (void*)g_wide_text.data(), g_wide_text.c_str());
    log("g_list_root       @ %p -> %p", (void*)&g_list_root, (void*)g_list_root);
    for (list_node_t* cur = g_list_root; cur; cur = cur->next) {
        log("  list node id=%u @ %p value=0x%016llX label=%s next=%p",
            cur->id, (void*)cur, cur->value, cur->label, (void*)cur->next);
    }

    uint64_t warmup = resident_mix_outer(g_magic_u64, 4);
    log("resident function chain warmup result=0x%016llX", warmup);

    open_handles();

    s_updater_thread = CreateThread(nullptr, 0, state_updater_thread, nullptr, 0, nullptr);
    if (s_updater_thread) {
        log("state-updater thread spawned");
    } else {
        log("state-updater thread FAILED (err=%lu)", GetLastError());
    }

    const char* worker_names[kWorkerCount] = {
        "resident-arith-0", "resident-arith-1", "resident-arith-2", "resident-arith-3"
    };
    const uint32_t worker_intervals[kWorkerCount] = { 250, 400, 650, 900 };

    s_worker_used = 0;
    for (int i = 0; i < kWorkerCount; ++i) {
        s_worker_ctx[i].id = i;
        s_worker_ctx[i].interval_ms = worker_intervals[i];
        s_worker_ctx[i].name = worker_names[i];
        s_worker_ctx[i].accumulator = (uint64_t)(i + 1) * 0x1000ULL;
        HANDLE h = CreateThread(nullptr, 0, arithmetic_worker_thread, &s_worker_ctx[i], 0, nullptr);
        if (h) {
            s_worker_threads[s_worker_used++] = h;
            log("spawned worker '%s' (id=%d)", worker_names[i], i);
        } else {
            log("worker '%s' (id=%d) FAILED (err=%lu)", worker_names[i], i, GetLastError());
        }
    }

    log("=== resident state ready (%d workers + updater) ===", s_worker_used);
}

void shutdown_all() {
    log("shutting down resident state...");

    HANDLE handles[kWorkerCount + 1];
    int valid = 0;
    if (s_updater_thread) handles[valid++] = s_updater_thread;
    for (int i = 0; i < s_worker_used; ++i) {
        if (s_worker_threads[i]) handles[valid++] = s_worker_threads[i];
    }

    if (valid > 0) {
        WaitForMultipleObjects(valid, handles, TRUE, 8000);
    }

    if (s_updater_thread) {
        CloseHandle(s_updater_thread);
        s_updater_thread = nullptr;
    }
    for (int i = 0; i < s_worker_used; ++i) {
        if (s_worker_threads[i]) {
            CloseHandle(s_worker_threads[i]);
            s_worker_threads[i] = nullptr;
        }
    }
    s_worker_used = 0;

    close_handles();
    free_list();

    log("resident state shut down");
}

}
}
