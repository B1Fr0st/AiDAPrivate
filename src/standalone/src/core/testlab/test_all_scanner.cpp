#include "test_all_scanner.h"

#include "../scanner/memory_scanner.hpp"
#include "../scanner/crypto_scanner.hpp"
#include "../scanner/pointer_scanner.hpp"
#include "../scanner/snapshot_diff.hpp"
#include "../scanner/aob_generator.hpp"
#include "../scanner/scan_hub_view.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace test_all_features {

namespace {

static void format_timestamp(char* out, std::size_t cap) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        static_cast<unsigned>(st.wYear),
        static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay),
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds));
}

static void write_log_file(HANDLE hf, const std::string& line) {
    if (hf == INVALID_HANDLE_VALUE) return;
    DWORD wrote = 0;
    WriteFile(hf, line.data(), static_cast<DWORD>(line.size()), &wrote, nullptr);
    FlushFileBuffers(hf);
}

static void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
    char ts[40];
    format_timestamp(ts, sizeof(ts));

    char detail[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
    va_end(ap);

    char line[1200];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
    std::string s(line);

    write_log_file(hf, s);
    diag::log_tagged_fmt("test_scan", "%s: %s", tag, detail);
    OutputDebugStringA(s.c_str());
}

static constexpr uint64_t k_marker_u64 = 0xCAFEBABE00000001ULL;
static constexpr int16_t  k_marker_i16 = static_cast<int16_t>(0x5AA5);
static constexpr int32_t  k_marker_i32 = static_cast<int32_t>(0x1337C0DE);
static constexpr float    k_marker_flt = 1234.5f;
static constexpr double   k_marker_dbl = 98765.4321;
static const uint8_t      k_marker_bytes[16] = {
    0x7F, 0x3A, 0x91, 0xC2, 0xA1, 0xDA, 0x70, 0x70,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
};
static const uint8_t      k_marker_aob[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE };
static const char         k_marker_ascii[] = "AIDA_TT_MARKER_7F3A91C2";

struct target_anchor_t {
    bool     planted = false;
    bool     attempted = false;
    uint64_t region_base = 0;
    uint64_t addr_u64 = 0;
    uint64_t addr_bytes = 0;
    uint64_t addr_ascii = 0;
    uint64_t addr_wide = 0;
    uint64_t addr_i16 = 0;
    uint64_t addr_i32 = 0;
    uint64_t addr_flt = 0;
    uint64_t addr_dbl = 0;
    uint64_t addr_aob = 0;
    uint64_t addr_scratch = 0;
    uint64_t ptr_target = 0;
    uint64_t ptr_level1 = 0;
    uint64_t ptr_level0 = 0;
};

static target_anchor_t g_anchor;

static constexpr size_t k_anchor_off_u64     = 0x000;
static constexpr size_t k_anchor_off_i16     = 0x010;
static constexpr size_t k_anchor_off_i32     = 0x020;
static constexpr size_t k_anchor_off_flt     = 0x030;
static constexpr size_t k_anchor_off_dbl     = 0x040;
static constexpr size_t k_anchor_off_bytes   = 0x060;
static constexpr size_t k_anchor_off_aob     = 0x080;
static constexpr size_t k_anchor_off_ascii   = 0x0A0;
static constexpr size_t k_anchor_off_wide    = 0x100;
static constexpr size_t k_anchor_off_scratch = 0x180;
static constexpr size_t k_anchor_off_target  = 0x200;
static constexpr size_t k_anchor_off_level1  = 0x210;
static constexpr size_t k_anchor_off_level0  = 0x220;
static constexpr size_t k_anchor_page        = 0x1000;

static void put_u64(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    std::memcpy(buf.data() + off, &v, sizeof(v));
}

static bool plant_anchor(HANDLE hf) {
    if (g_anchor.attempted) return g_anchor.planted;
    g_anchor.attempted = true;

    uint32_t pid = driver_bridge::attached_pid();
    bool attached = driver_bridge::is_loaded() && pid != 0;
    if (!attached) {
        log_msg(hf, "anchor", "plant skipped -- not attached (driver_loaded=%d pid=%u)",
            static_cast<int>(driver_bridge::is_loaded()), pid);
        return false;
    }

    uint64_t base = driver_bridge::allocate_memory(k_anchor_page);
    if (base == 0) {
        log_msg(hf, "anchor", "plant failed -- allocate_memory(%zu) returned 0 in target pid=%u (kernel allocate unavailable)",
            k_anchor_page, pid);
        return false;
    }

    std::vector<uint8_t> page(k_anchor_page, 0);
    put_u64(page, k_anchor_off_u64, k_marker_u64);
    std::memcpy(page.data() + k_anchor_off_i16, &k_marker_i16, sizeof(k_marker_i16));
    std::memcpy(page.data() + k_anchor_off_i32, &k_marker_i32, sizeof(k_marker_i32));
    std::memcpy(page.data() + k_anchor_off_flt, &k_marker_flt, sizeof(k_marker_flt));
    std::memcpy(page.data() + k_anchor_off_dbl, &k_marker_dbl, sizeof(k_marker_dbl));
    std::memcpy(page.data() + k_anchor_off_bytes, k_marker_bytes, sizeof(k_marker_bytes));
    std::memcpy(page.data() + k_anchor_off_aob, k_marker_aob, sizeof(k_marker_aob));

    size_t ascii_len = std::strlen(k_marker_ascii);
    std::memcpy(page.data() + k_anchor_off_ascii, k_marker_ascii, ascii_len + 1);

    {
        std::vector<wchar_t> w(ascii_len + 1, 0);
        int wlen = MultiByteToWideChar(CP_UTF8, 0, k_marker_ascii, -1, w.data(), static_cast<int>(w.size()));
        if (wlen > 0)
            std::memcpy(page.data() + k_anchor_off_wide, w.data(), static_cast<size_t>(wlen) * sizeof(wchar_t));
    }

    put_u64(page, k_anchor_off_target, k_marker_u64);
    put_u64(page, k_anchor_off_level1, base + k_anchor_off_target);
    put_u64(page, k_anchor_off_level0, base + k_anchor_off_level1);

    if (!driver_bridge::write_memory(base, page)) {
        log_msg(hf, "anchor", "plant failed -- write_memory(0x%llX, %zu) rejected",
            (unsigned long long)base, page.size());
        driver_bridge::free_memory(base);
        return false;
    }

    std::vector<uint8_t> verify;
    if (!driver_bridge::read_memory(base, k_anchor_page, verify) || verify.size() < k_anchor_page) {
        log_msg(hf, "anchor", "plant failed -- read-back at 0x%llX returned %zu bytes",
            (unsigned long long)base, verify.size());
        driver_bridge::free_memory(base);
        return false;
    }
    if (std::memcmp(verify.data(), page.data(), k_anchor_page) != 0) {
        log_msg(hf, "anchor", "plant failed -- read-back mismatch at 0x%llX", (unsigned long long)base);
        driver_bridge::free_memory(base);
        return false;
    }

    g_anchor.planted = true;
    g_anchor.region_base = base;
    g_anchor.addr_u64 = base + k_anchor_off_u64;
    g_anchor.addr_i16 = base + k_anchor_off_i16;
    g_anchor.addr_i32 = base + k_anchor_off_i32;
    g_anchor.addr_flt = base + k_anchor_off_flt;
    g_anchor.addr_dbl = base + k_anchor_off_dbl;
    g_anchor.addr_bytes = base + k_anchor_off_bytes;
    g_anchor.addr_aob = base + k_anchor_off_aob;
    g_anchor.addr_ascii = base + k_anchor_off_ascii;
    g_anchor.addr_wide = base + k_anchor_off_wide;
    g_anchor.addr_scratch = base + k_anchor_off_scratch;
    g_anchor.ptr_target = base + k_anchor_off_target;
    g_anchor.ptr_level1 = base + k_anchor_off_level1;
    g_anchor.ptr_level0 = base + k_anchor_off_level0;

    log_msg(hf, "anchor", "plant OK -- pid=%u base=0x%llX u64=0x%llX bytes=0x%llX ascii=0x%llX wide=0x%llX ptr_target=0x%llX ptr_l1=0x%llX ptr_l0=0x%llX",
        pid, (unsigned long long)base,
        (unsigned long long)g_anchor.addr_u64, (unsigned long long)g_anchor.addr_bytes,
        (unsigned long long)g_anchor.addr_ascii, (unsigned long long)g_anchor.addr_wide,
        (unsigned long long)g_anchor.ptr_target, (unsigned long long)g_anchor.ptr_level1,
        (unsigned long long)g_anchor.ptr_level0);
    return true;
}

static void unplant_anchor(HANDLE hf) {
    if (g_anchor.planted && g_anchor.region_base != 0) {
        bool freed = driver_bridge::free_memory(g_anchor.region_base);
        log_msg(hf, "anchor", "unplant base=0x%llX freed=%d",
            (unsigned long long)g_anchor.region_base, static_cast<int>(freed));
    }
    g_anchor = target_anchor_t{};
}

static bool wait_scan_idle(int max_iters = 100) {
    for (int i = 0; i < max_iters; ++i) {
        if (!memory_scanner::g_state.scanning.load()) return true;
        Sleep(100);
    }
    return !memory_scanner::g_state.scanning.load();
}

static size_t snapshot_results(std::vector<memory_scanner::scan_result_t>& out) {
    std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
    out = memory_scanner::g_state.results;
    return out.size();
}

static bool result_reads_back(const std::vector<memory_scanner::scan_result_t>& results,
                              const uint8_t* expected, size_t expected_len,
                              uint64_t preferred_addr, uint64_t& matched_addr,
                              std::vector<uint8_t>& read_bytes) {
    if (preferred_addr != 0) {
        for (auto& r : results) {
            if (r.address != preferred_addr) continue;
            std::vector<uint8_t> buf;
            if (driver_bridge::read_memory(r.address, expected_len, buf) &&
                buf.size() >= expected_len &&
                std::memcmp(buf.data(), expected, expected_len) == 0) {
                matched_addr = r.address;
                read_bytes = std::move(buf);
                return true;
            }
        }
    }
    for (auto& r : results) {
        std::vector<uint8_t> buf;
        if (driver_bridge::read_memory(r.address, expected_len, buf) &&
            buf.size() >= expected_len &&
            std::memcmp(buf.data(), expected, expected_len) == 0) {
            matched_addr = r.address;
            read_bytes = std::move(buf);
            return true;
        }
    }
    return false;
}

static std::string hex_preview(const uint8_t* data, size_t len, size_t cap = 16) {
    std::string out;
    char b[4];
    size_t n = (len < cap) ? len : cap;
    for (size_t i = 0; i < n; ++i) {
        std::snprintf(b, sizeof(b), "%02X", data[i]);
        if (i) out += ' ';
        out += b;
    }
    if (len > cap) out += " ...";
    return out;
}

static void test_memscan_initialize(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_init", "START -- memory_scanner::initialize");
    auto t0 = std::chrono::steady_clock::now();

    bool pre_freeze_done = memory_scanner::g_state.freeze_thread_done.load(std::memory_order_acquire);
    bool pre_scanning = memory_scanner::g_state.scanning.load();
    log_msg(hf, "scan_init", "INPUT pre-state freeze_thread_done=%d scanning=%d",
        static_cast<int>(pre_freeze_done), static_cast<int>(pre_scanning));

    memory_scanner::initialize();

    bool freeze_worker_live = false;
    for (int i = 0; i < 100; ++i) {
        if (memory_scanner::g_state.freeze_active.load() &&
            !memory_scanner::g_state.freeze_thread_done.load(std::memory_order_acquire)) {
            freeze_worker_live = true;
            break;
        }
        Sleep(10);
    }

    bool freeze_active = memory_scanner::g_state.freeze_active.load();
    bool freeze_done = memory_scanner::g_state.freeze_thread_done.load(std::memory_order_acquire);
    bool scanning = memory_scanner::g_state.scanning.load();
    bool pointer_scanning = memory_scanner::g_state.pointer_scanning.load();

    size_t results = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        results = memory_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_init", "RESULT freeze_active=%d freeze_thread_done=%d freeze_worker_live=%d scanning=%d pointer_scanning=%d results=%zu",
        static_cast<int>(freeze_active), static_cast<int>(freeze_done),
        static_cast<int>(freeze_worker_live), static_cast<int>(scanning),
        static_cast<int>(pointer_scanning), results);

    if (!freeze_active || !freeze_worker_live) {
        log_msg(hf, "scan_init", "FAIL -- freeze worker not running after initialize (freeze_active=%d freeze_thread_done=%d): work-queue post likely failed (elapsed %lld ms)",
            static_cast<int>(freeze_active), static_cast<int>(freeze_done), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (scanning || pointer_scanning) {
        log_msg(hf, "scan_init", "FAIL -- scanner not quiescent after initialize (scanning=%d pointer_scanning=%d) (elapsed %lld ms)",
            static_cast<int>(scanning), static_cast<int>(pointer_scanning), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (results != 0) {
        log_msg(hf, "scan_init", "FAIL -- result set not empty after initialize (results=%zu) (elapsed %lld ms)",
            results, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_init", "PASS -- initialize started freeze worker, scanner quiescent, results empty (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_int32(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_i32", "START -- first scan exact int32 marker 0x%08X (%d)",
        static_cast<unsigned>(k_marker_i32), k_marker_i32);
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();
    char text[32];
    std::snprintf(text, sizeof(text), "%d", k_marker_i32);

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_i32", "INPUT value='%s' type=Int32 mode=exact writable_only=0 anchor=0x%llX pid=%u",
        text, (unsigned long long)g_anchor.addr_i32, pid);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_i32", "RESULT first_scan=%d idle=%d found=%zu first_addr=0x%llX",
        static_cast<int>(ok), static_cast<int>(idle), found,
        (unsigned long long)(found ? results.front().address : 0));

    if (!ok) {
        log_msg(hf, "scan_i32", "FAIL -- first_scan refused (attach/engine) (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (found == 0) {
        log_msg(hf, "scan_i32", "FAIL -- 0 results scanning for known marker 0x%08X (elapsed %lld ms)",
            static_cast<unsigned>(k_marker_i32), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t expected = k_marker_i32;
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_i32, matched, rb)) {
        log_msg(hf, "scan_i32", "FAIL -- %zu results but none read back as 0x%08X (elapsed %lld ms)",
            found, static_cast<unsigned>(k_marker_i32), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_i32", "PASS -- found %zu, verified read-back at 0x%llX = %s (elapsed %lld ms)",
        found, (unsigned long long)matched, hex_preview(rb.data(), rb.size()).c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_byte(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_byt", "START -- first scan exact byte marker 0x%02X", k_marker_bytes[0]);
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();
    char text[16];
    std::snprintf(text, sizeof(text), "%u", k_marker_bytes[0]);

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::byte_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_byt", "INPUT value='%s' type=Byte mode=exact writable_only=0 pid=%u", text, pid);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_byt", "RESULT first_scan=%d idle=%d found=%zu",
        static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok) {
        log_msg(hf, "scan_byt", "FAIL -- first_scan refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (found == 0) {
        log_msg(hf, "scan_byt", "FAIL -- 0 byte results (value 0x%02X must exist in target) (elapsed %lld ms)",
            k_marker_bytes[0], (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint8_t expected = k_marker_bytes[0];
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, &expected, 1, g_anchor.addr_bytes, matched, rb)) {
        log_msg(hf, "scan_byt", "FAIL -- %zu results but none read back as 0x%02X (elapsed %lld ms)",
            found, expected, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_byt", "PASS -- found %zu, read-back at 0x%llX = 0x%02X (elapsed %lld ms)",
        found, (unsigned long long)matched, rb[0], (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_str", "START -- first scan ASCII marker \"%s\"", k_marker_ascii);
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::string_ascii;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = k_marker_ascii;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_str", "INPUT value='%s' type=ASCII mode=exact writable_only=0 anchor=0x%llX pid=%u",
        k_marker_ascii, (unsigned long long)g_anchor.addr_ascii, pid);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_str", "RESULT first_scan=%d idle=%d found=%zu first_addr=0x%llX",
        static_cast<int>(ok), static_cast<int>(idle), found,
        (unsigned long long)(found ? results.front().address : 0));

    if (!ok) {
        log_msg(hf, "scan_str", "FAIL -- first_scan refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (found == 0) {
        log_msg(hf, "scan_str", "FAIL -- 0 results for resident marker string \"%s\" (elapsed %lld ms)",
            k_marker_ascii, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    size_t expected_len = std::strlen(k_marker_ascii);
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(k_marker_ascii), expected_len,
                           g_anchor.addr_ascii, matched, rb)) {
        log_msg(hf, "scan_str", "FAIL -- %zu results but none read back as the marker string (elapsed %lld ms)",
            found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    std::string sample(reinterpret_cast<const char*>(rb.data()), expected_len);
    log_msg(hf, "scan_str", "PASS -- found %zu, read-back at 0x%llX = \"%s\" (elapsed %lld ms)",
        found, (unsigned long long)matched, sample.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_unchanged(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_unc", "START -- next scan unchanged (retain stable marker results)");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    char text[32];
    std::snprintf(text, sizeof(text), "%d", k_marker_i32);
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_unc", "INPUT seed exact Int32 '%s' then next_scan(unchanged)", text);

    bool seed_ok = memory_scanner::first_scan(cfg);
    wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> before;
    size_t before_n = snapshot_results(before);

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::unchanged, "", "");
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> after;
    size_t after_n = snapshot_results(after);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_unc", "RESULT seed=%d before=%zu next_scan=%d idle=%d after=%zu",
        static_cast<int>(seed_ok), before_n, static_cast<int>(ok), static_cast<int>(idle), after_n);

    if (!seed_ok || before_n == 0) {
        log_msg(hf, "scan_unc", "FAIL -- seed scan produced no marker results (before=%zu) (elapsed %lld ms)",
            before_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!ok) {
        log_msg(hf, "scan_unc", "FAIL -- next_scan(unchanged) refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (after_n == 0) {
        log_msg(hf, "scan_unc", "FAIL -- unchanged dropped all %zu stable marker results to 0 (elapsed %lld ms)",
            before_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t expected = k_marker_i32;
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    bool kept = result_reads_back(after, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                                  g_anchor.addr_i32, matched, rb);
    if (!kept) {
        log_msg(hf, "scan_unc", "FAIL -- unchanged result set lost the marker value (after=%zu) (elapsed %lld ms)",
            after_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_unc", "PASS -- unchanged kept marker (before=%zu after=%zu addr=0x%llX) (elapsed %lld ms)",
        before_n, after_n, (unsigned long long)matched, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_changed(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_chg", "START -- next scan changed (detect a written change)");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_chg", "FAIL -- no planted anchor; cannot deterministically mutate target memory (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t seed_val = 0x0BADF00D;
    std::vector<uint8_t> seed_bytes(reinterpret_cast<uint8_t*>(&seed_val), reinterpret_cast<uint8_t*>(&seed_val) + 4);
    if (!driver_bridge::write_memory(g_anchor.addr_scratch, seed_bytes)) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_chg", "FAIL -- could not seed scratch 0x%llX (elapsed %lld ms)",
            (unsigned long long)g_anchor.addr_scratch, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    char text[32];
    std::snprintf(text, sizeof(text), "%d", seed_val);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_chg", "INPUT seed exact Int32 '%s' at scratch 0x%llX then mutate and next_scan(changed)",
        text, (unsigned long long)g_anchor.addr_scratch);

    bool seed_ok = memory_scanner::first_scan(cfg);
    wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> before;
    size_t before_n = snapshot_results(before);

    int32_t new_val = 0x600DCAFE;
    std::vector<uint8_t> new_bytes(reinterpret_cast<uint8_t*>(&new_val), reinterpret_cast<uint8_t*>(&new_val) + 4);
    bool mutated = driver_bridge::write_memory(g_anchor.addr_scratch, new_bytes);

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::changed, "", "");
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> after;
    size_t after_n = snapshot_results(after);

    bool scratch_present = false;
    for (auto& r : after) {
        if (r.address == g_anchor.addr_scratch) { scratch_present = true; break; }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_chg", "RESULT seed=%d before=%zu mutated=%d next_scan=%d idle=%d after=%zu scratch_in_results=%d",
        static_cast<int>(seed_ok), before_n, static_cast<int>(mutated),
        static_cast<int>(ok), static_cast<int>(idle), after_n, static_cast<int>(scratch_present));

    if (!seed_ok || before_n == 0) {
        log_msg(hf, "scan_chg", "FAIL -- seed scan produced no result for scratch value (before=%zu) (elapsed %lld ms)",
            before_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!mutated) {
        log_msg(hf, "scan_chg", "FAIL -- mutate write rejected (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!ok) {
        log_msg(hf, "scan_chg", "FAIL -- next_scan(changed) refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (after_n == 0 || !scratch_present) {
        log_msg(hf, "scan_chg", "FAIL -- changed did not retain mutated scratch addr (after=%zu present=%d) (elapsed %lld ms)",
            after_n, static_cast<int>(scratch_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_chg", "PASS -- changed isolated scratch 0x%llX (before=%zu after=%zu) (elapsed %lld ms)",
        (unsigned long long)g_anchor.addr_scratch, before_n, after_n, (long long)ms);
    passed.fetch_add(1);
}

static void test_undo_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_undo", "START -- undo scan restores previous result set");
    auto t0 = std::chrono::steady_clock::now();

    char text[32];
    std::snprintf(text, sizeof(text), "%d", k_marker_i32);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;

    bool seed_ok = memory_scanner::first_scan(cfg);
    wait_scan_idle();
    std::vector<memory_scanner::scan_result_t> first;
    size_t first_n = snapshot_results(first);

    bool refine_ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::unchanged, "", "");
    wait_scan_idle();
    std::vector<memory_scanner::scan_result_t> refined;
    size_t refined_n = snapshot_results(refined);

    memory_scanner::undo_scan();
    std::vector<memory_scanner::scan_result_t> restored;
    size_t restored_n = snapshot_results(restored);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_undo", "RESULT seed=%d first=%zu refine=%d refined=%zu restored=%zu",
        static_cast<int>(seed_ok), first_n, static_cast<int>(refine_ok), refined_n, restored_n);

    if (!seed_ok || first_n == 0) {
        log_msg(hf, "scan_undo", "FAIL -- seed scan empty (first=%zu) (elapsed %lld ms)", first_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (!refine_ok) {
        log_msg(hf, "scan_undo", "FAIL -- refine next_scan refused (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (restored_n != first_n) {
        log_msg(hf, "scan_undo", "FAIL -- undo restored %zu but pre-refine had %zu (elapsed %lld ms)",
            restored_n, first_n, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_undo", "PASS -- undo restored result count %zu (elapsed %lld ms)", restored_n, (long long)ms);
    passed.fetch_add(1);
}

static void test_reset_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_rst", "START -- reset scan clears results");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();

    bool empty = false;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        empty = memory_scanner::g_state.results.empty();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_rst", "RESULT results_empty=%d", static_cast<int>(empty));
    if (!empty) {
        log_msg(hf, "scan_rst", "FAIL -- results not empty after reset_scan (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "scan_rst", "PASS -- reset_scan cleared results (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_add_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_add", "START -- add address to watch list");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = g_anchor.planted ? g_anchor.addr_u64
        : static_cast<uint64_t>(reinterpret_cast<uintptr_t>(GetModuleHandleW(L"ntdll.dll")));
    log_msg(hf, "scan_add", "INPUT addr=0x%llX type=Int64", (unsigned long long)addr);

    size_t before = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        before = memory_scanner::g_state.address_list.size();
    }

    memory_scanner::add_address(addr, "test_anchor_u64", memory_scanner::value_type_t::int64_val);

    size_t count = 0;
    bool present = false;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        count = memory_scanner::g_state.address_list.size();
        for (auto& e : memory_scanner::g_state.address_list)
            if (e.address == addr) { present = true; break; }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_add", "RESULT before=%zu after=%zu present=%d", before, count, static_cast<int>(present));
    if (count > before && present) {
        log_msg(hf, "scan_add", "PASS -- address list now %zu entries, target present (elapsed %lld ms)", count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_add", "FAIL -- add_address did not register addr 0x%llX (before=%zu after=%zu) (elapsed %lld ms)",
            (unsigned long long)addr, before, count, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_remove_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_rem", "START -- remove address from watch list");
    auto t0 = std::chrono::steady_clock::now();

    size_t before = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        before = memory_scanner::g_state.address_list.size();
    }

    if (before == 0) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_rem", "FAIL -- watch list empty, nothing to remove (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }

    memory_scanner::remove_address(0);

    size_t after = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        after = memory_scanner::g_state.address_list.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_rem", "RESULT before=%zu after=%zu", before, after);
    if (after + 1 == before) {
        log_msg(hf, "scan_rem", "PASS -- removed one entry (before=%zu after=%zu) (elapsed %lld ms)",
            before, after, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_rem", "FAIL -- remove_address count mismatch (before=%zu after=%zu) (elapsed %lld ms)",
            before, after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_freeze_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_frz", "START -- freeze/unfreeze address");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_frz", "FAIL -- no planted anchor; cannot validate freeze write-back (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t freeze_val = 0x5151A5A5;
    std::vector<uint8_t> fb(reinterpret_cast<uint8_t*>(&freeze_val), reinterpret_cast<uint8_t*>(&freeze_val) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, fb);

    memory_scanner::add_address(g_anchor.addr_scratch, "test_freeze", memory_scanner::value_type_t::int32_val);
    memory_scanner::refresh_address_list();

    size_t idx = 0;
    bool found_idx = false;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        for (size_t i = 0; i < memory_scanner::g_state.address_list.size(); ++i) {
            if (memory_scanner::g_state.address_list[i].address == g_anchor.addr_scratch) {
                idx = i; found_idx = true; break;
            }
        }
    }

    if (!found_idx) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_frz", "FAIL -- scratch entry missing after add (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }

    memory_scanner::freeze_address(idx, true);

    int32_t clobber = 0x00000000;
    std::vector<uint8_t> cb(reinterpret_cast<uint8_t*>(&clobber), reinterpret_cast<uint8_t*>(&clobber) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, cb);

    Sleep(120);

    std::vector<uint8_t> after_freeze;
    driver_bridge::read_memory(g_anchor.addr_scratch, 4, after_freeze);
    int32_t held = 0;
    if (after_freeze.size() >= 4) std::memcpy(&held, after_freeze.data(), 4);

    memory_scanner::freeze_address(idx, false);
    memory_scanner::remove_address(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_frz", "RESULT freeze_val=0x%08X clobbered=0x00000000 read_after=0x%08X",
        static_cast<unsigned>(freeze_val), static_cast<unsigned>(held));

    if (held == freeze_val) {
        log_msg(hf, "scan_frz", "PASS -- freeze loop restored 0x%08X after clobber (elapsed %lld ms)",
            static_cast<unsigned>(freeze_val), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_frz", "FAIL -- frozen value not restored (expected 0x%08X got 0x%08X) (elapsed %lld ms)",
            static_cast<unsigned>(freeze_val), static_cast<unsigned>(held), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_read_value_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_rdv", "START -- read_value_string against known anchor value");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_rdv", "FAIL -- no planted anchor; no known address to read (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_rdv", "INPUT addr=0x%llX type=Int32 expected=%d",
        (unsigned long long)g_anchor.addr_i32, k_marker_i32);
    std::string val = memory_scanner::read_value_string(g_anchor.addr_i32, memory_scanner::value_type_t::int32_val);

    char expected[32];
    std::snprintf(expected, sizeof(expected), "%d", k_marker_i32);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_rdv", "RESULT read_value_string=\"%s\" expected=\"%s\"", val.c_str(), expected);

    if (val.empty() || val == "<read error>") {
        log_msg(hf, "scan_rdv", "FAIL -- read returned error/empty at 0x%llX (elapsed %lld ms)",
            (unsigned long long)g_anchor.addr_i32, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (val != expected) {
        log_msg(hf, "scan_rdv", "FAIL -- read \"%s\" != expected \"%s\" (elapsed %lld ms)",
            val.c_str(), expected, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    std::string sval = memory_scanner::read_value_string(g_anchor.addr_ascii, memory_scanner::value_type_t::string_ascii);
    log_msg(hf, "scan_rdv", "RESULT string read at 0x%llX = \"%s\"",
        (unsigned long long)g_anchor.addr_ascii, sval.c_str());
    if (sval.empty() || sval == "<read error>" || sval.compare(0, std::strlen(k_marker_ascii), k_marker_ascii) != 0) {
        log_msg(hf, "scan_rdv", "FAIL -- string read mismatch at 0x%llX got \"%s\" (elapsed %lld ms)",
            (unsigned long long)g_anchor.addr_ascii, sval.c_str(), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_rdv", "PASS -- read int32=\"%s\" string=\"%s\" (elapsed %lld ms)",
        val.c_str(), sval.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_format_parse_roundtrip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fpr", "START -- format/parse value roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("12345", memory_scanner::value_type_t::int32_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::int32_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_fpr", "RESULT parsed_bytes=%zu formatted=\"%s\"", parsed.size(), formatted.c_str());
    if (parsed.size() == 4 && formatted == "12345") {
        log_msg(hf, "scan_fpr", "PASS -- roundtrip: 12345 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fpr", "FAIL -- expected 4 bytes/\"12345\" got %zu/\"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_crypto_get_signatures(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_sig", "START -- get built-in crypto signatures");
    auto t0 = std::chrono::steady_clock::now();

    auto sigs = crypto_scanner::get_signatures();

    bool patterns_ok = !sigs.empty();
    for (auto& s : sigs) {
        if (s.name == nullptr || s.pattern == nullptr || s.pattern_size == 0 || s.min_match == 0) {
            patterns_ok = false;
            break;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_sig", "RESULT signatures=%zu patterns_ok=%d", sigs.size(), static_cast<int>(patterns_ok));
    for (size_t i = 0; i < sigs.size() && i < 5; ++i) {
        log_msg(hf, "crypto_sig", "  sig[%zu]: name=%s algo=%s bytes=%zu min_match=%zu",
            i, sigs[i].name, sigs[i].algorithm, sigs[i].pattern_size, sigs[i].min_match);
    }

    if (sigs.size() < 16 || !patterns_ok) {
        log_msg(hf, "crypto_sig", "FAIL -- expected >=16 valid built-in signatures, got %zu (patterns_ok=%d) (elapsed %lld ms)",
            sigs.size(), static_cast<int>(patterns_ok), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "crypto_sig", "PASS -- %zu valid built-in signatures (elapsed %lld ms)", sigs.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_crypto_scan_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_sp", "START -- crypto scanner scan_process (target embeds AES/SHA constants)");
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();
    log_msg(hf, "crypto_sp", "INPUT scan_process against pid=%u", pid);
    crypto_scanner::scan_process();

    bool idle = false;
    for (int i = 0; i < 200; ++i) {
        if (!crypto_scanner::g_state.scanning.load()) { idle = true; break; }
        Sleep(100);
    }
    if (!idle) crypto_scanner::cancel();

    size_t hits = 0;
    std::string first_name, first_algo;
    uint64_t first_addr = 0;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        hits = crypto_scanner::g_state.results.size();
        if (hits > 0) {
            first_name = crypto_scanner::g_state.results.front().signature_name;
            first_algo = crypto_scanner::g_state.results.front().algorithm;
            first_addr = crypto_scanner::g_state.results.front().address;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_sp", "RESULT idle=%d hits=%zu first='%s'/%s@0x%llX",
        static_cast<int>(idle), hits, first_name.c_str(), first_algo.c_str(),
        (unsigned long long)first_addr);

    if (hits == 0) {
        log_msg(hf, "crypto_sp", "FAIL -- 0 crypto-constant hits in target that embeds AES S-box and SHA-256 K (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "crypto_sp", "PASS -- scan_process found %zu crypto hits (first '%s'/%s @0x%llX) (elapsed %lld ms)",
        hits, first_name.c_str(), first_algo.c_str(), (unsigned long long)first_addr, (long long)ms);
    passed.fetch_add(1);
}

static void test_crypto_scan_entropy(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_ent", "START -- crypto scanner scan_entropy");
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();
    log_msg(hf, "crypto_ent", "INPUT scan_entropy against pid=%u threshold=%.2f",
        pid, static_cast<double>(crypto_scanner::g_state.entropy_threshold));
    crypto_scanner::scan_entropy();

    bool idle = false;
    for (int i = 0; i < 200; ++i) {
        if (!crypto_scanner::g_state.scanning.load()) { idle = true; break; }
        Sleep(100);
    }
    if (!idle) crypto_scanner::cancel();

    size_t high_count = 0;
    float first_ent = 0.f;
    uint64_t first_addr = 0;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        high_count = crypto_scanner::g_state.entropy_map.size();
        if (high_count > 0) {
            first_ent = crypto_scanner::g_state.entropy_map.front().entropy;
            first_addr = crypto_scanner::g_state.entropy_map.front().address;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_ent", "RESULT idle=%d high_entropy_regions=%zu first_entropy=%.3f@0x%llX",
        static_cast<int>(idle), high_count, static_cast<double>(first_ent),
        (unsigned long long)first_addr);

    if (!idle) {
        log_msg(hf, "crypto_ent", "FAIL -- entropy scan did not complete within budget (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (high_count == 0) {
        log_msg(hf, "crypto_ent", "FAIL -- 0 high-entropy regions in a live multi-module process (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "crypto_ent", "PASS -- entropy scan found %zu high-entropy regions (first %.3f @0x%llX) (elapsed %lld ms)",
        high_count, static_cast<double>(first_ent), (unsigned long long)first_addr, (long long)ms);
    passed.fetch_add(1);
}

static void test_crypto_add_custom_sig(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_cst", "START -- add custom crypto signature");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> pattern = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    size_t before = 0;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        before = crypto_scanner::g_state.custom_sigs.size();
    }
    log_msg(hf, "crypto_cst", "INPUT name='TestSig' algo='TestAlgo' bytes=%zu before=%zu", pattern.size(), before);

    crypto_scanner::add_custom_signature("TestSig", "TestAlgo", "Test custom signature",
        crypto_scanner::crypto_category_t::symmetric, pattern);

    size_t after = 0;
    bool present = false;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        after = crypto_scanner::g_state.custom_sigs.size();
        for (auto& s : crypto_scanner::g_state.custom_sigs)
            if (s.name == "TestSig" && s.pattern == pattern) { present = true; break; }
    }

    if (after > before) {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        for (size_t i = crypto_scanner::g_state.custom_sigs.size(); i-- > 0;) {
            if (crypto_scanner::g_state.custom_sigs[i].name == "TestSig") {
                crypto_scanner::g_state.custom_sigs.erase(crypto_scanner::g_state.custom_sigs.begin() + i);
                break;
            }
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_cst", "RESULT before=%zu after=%zu present=%d", before, after, static_cast<int>(present));
    if (after == before + 1 && present) {
        log_msg(hf, "crypto_cst", "PASS -- custom signature added & matched (before=%zu after=%zu) (elapsed %lld ms)",
            before, after, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "crypto_cst", "FAIL -- custom signature not registered correctly (before=%zu after=%zu present=%d) (elapsed %lld ms)",
            before, after, static_cast<int>(present), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_build_reverse_map(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_map", "START -- pointer scanner build reverse map");
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();
    log_msg(hf, "ptr_map", "INPUT build_reverse_map against pid=%u", pid);
    pointer_scanner::build_reverse_map();

    bool idle = false;
    for (int i = 0; i < 900; ++i) {
        if (!pointer_scanner::g_state.map_building.load()) { idle = true; break; }
        Sleep(100);
    }

    size_t entries = 0;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.map_mutex);
        entries = pointer_scanner::g_state.map_entry_count;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_map", "RESULT idle=%d entries=%zu", static_cast<int>(idle), entries);

    if (!idle) {
        float progress = pointer_scanner::g_state.map_progress.load();
        log_msg(hf, "ptr_map", "FAIL -- build_reverse_map did not finish within budget progress=%.3f (elapsed %lld ms)",
            progress, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (entries == 0) {
        log_msg(hf, "ptr_map", "FAIL -- reverse map empty for a live process full of pointers (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "ptr_map", "PASS -- reverse map built with %zu entries (elapsed %lld ms)", entries, (long long)ms);
    passed.fetch_add(1);
}

static void test_snapshot_take(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "snap_take", "START -- take snapshot");
    auto t0 = std::chrono::steady_clock::now();

    uint32_t pid = driver_bridge::attached_pid();
    size_t before = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        before = snapshot_diff::g_state.snapshots.size();
    }
    log_msg(hf, "snap_take", "INPUT take_snapshot('test_snap_A') pid=%u before=%zu", pid, before);

    snapshot_diff::take_snapshot("test_snap_A");

    bool idle = false;
    for (int i = 0; i < 200; ++i) {
        if (!snapshot_diff::g_state.capturing.load()) { idle = true; break; }
        Sleep(100);
    }

    size_t snap_count = 0;
    size_t regions = 0;
    uint64_t bytes = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        snap_count = snapshot_diff::g_state.snapshots.size();
        if (snap_count > 0) {
            regions = snapshot_diff::g_state.snapshots.back().regions.size();
            bytes = snapshot_diff::g_state.snapshots.back().total_bytes;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "snap_take", "RESULT idle=%d snapshots=%zu last_regions=%zu last_bytes=%llu",
        static_cast<int>(idle), snap_count, regions, (unsigned long long)bytes);

    if (!idle) {
        log_msg(hf, "snap_take", "FAIL -- capture did not finish within budget (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (snap_count <= before || regions == 0 || bytes == 0) {
        log_msg(hf, "snap_take", "FAIL -- snapshot empty (count %zu->%zu regions=%zu bytes=%llu) (elapsed %lld ms)",
            before, snap_count, regions, (unsigned long long)bytes, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "snap_take", "PASS -- snapshot captured %zu regions / %llu bytes (count=%zu) (elapsed %lld ms)",
        regions, (unsigned long long)bytes, snap_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_snapshot_compare(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "snap_cmp", "START -- compare two snapshots across a written change");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "snap_cmp", "FAIL -- no planted anchor; cannot guarantee a detectable change (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t marker_a = 0x1111111122222222ULL;
    std::vector<uint8_t> ba(reinterpret_cast<uint8_t*>(&marker_a), reinterpret_cast<uint8_t*>(&marker_a) + 8);
    driver_bridge::write_memory(g_anchor.addr_scratch, ba);

    snapshot_diff::take_snapshot("test_snap_B1");
    for (int i = 0; i < 200; ++i) {
        if (!snapshot_diff::g_state.capturing.load()) break;
        Sleep(100);
    }

    uint64_t marker_b = 0xAAAAAAAABBBBBBBBULL;
    std::vector<uint8_t> bb(reinterpret_cast<uint8_t*>(&marker_b), reinterpret_cast<uint8_t*>(&marker_b) + 8);
    bool mutated = driver_bridge::write_memory(g_anchor.addr_scratch, bb);

    snapshot_diff::take_snapshot("test_snap_B2");
    for (int i = 0; i < 200; ++i) {
        if (!snapshot_diff::g_state.capturing.load()) break;
        Sleep(100);
    }

    uint64_t id_a = 0, id_b = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        size_t n = snapshot_diff::g_state.snapshots.size();
        if (n >= 2) {
            id_a = snapshot_diff::g_state.snapshots[n - 2].id;
            id_b = snapshot_diff::g_state.snapshots[n - 1].id;
        }
    }

    log_msg(hf, "snap_cmp", "INPUT mutate scratch 0x%llX 0x%016llX->0x%016llX (mutated=%d) compare ids a=%llu b=%llu",
        (unsigned long long)g_anchor.addr_scratch, (unsigned long long)marker_a,
        (unsigned long long)marker_b, static_cast<int>(mutated),
        (unsigned long long)id_a, (unsigned long long)id_b);

    if (id_a == 0 || id_b == 0) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "snap_cmp", "FAIL -- need two snapshots, got ids a=%llu b=%llu (elapsed %lld ms)",
            (unsigned long long)id_a, (unsigned long long)id_b, (long long)ms);
        failed.fetch_add(1);
        snapshot_diff::clear_snapshots();
        return;
    }

    snapshot_diff::compare_snapshots(id_a, id_b);
    for (int i = 0; i < 200; ++i) {
        if (!snapshot_diff::g_state.comparing.load()) break;
        Sleep(100);
    }

    size_t changes = 0;
    bool scratch_change = false;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        changes = snapshot_diff::g_state.diff.changes.size();
        for (auto& c : snapshot_diff::g_state.diff.changes) {
            if (g_anchor.addr_scratch >= c.address && g_anchor.addr_scratch < c.address + c.size) {
                scratch_change = true;
                break;
            }
        }
    }

    snapshot_diff::clear_snapshots();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "snap_cmp", "RESULT changes=%zu scratch_change_detected=%d", changes, static_cast<int>(scratch_change));

    if (!mutated) {
        log_msg(hf, "snap_cmp", "FAIL -- mutate write rejected (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (changes == 0 || !scratch_change) {
        log_msg(hf, "snap_cmp", "FAIL -- diff missed the known scratch change (changes=%zu detected=%d) (elapsed %lld ms)",
            changes, static_cast<int>(scratch_change), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "snap_cmp", "PASS -- diff detected %zu changes incl. scratch 0x%llX (elapsed %lld ms)",
        changes, (unsigned long long)g_anchor.addr_scratch, (long long)ms);
    passed.fetch_add(1);
}

static void test_aob_format_signature(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_fmt", "START -- AOB format signature");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x1000;
    sig.bytes = {
        {0x48, false}, {0x89, false}, {0x5C, false}, {0x24, false},
        {0x00, true},  {0x57, false}, {0x48, false}, {0x83, false}
    };
    sig.quality_score = aob_generator::compute_quality_score(sig);

    std::string formatted = aob_generator::format_signature(sig);
    const char* expected = "48 89 5C 24 ?? 57 48 83";

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "aob_fmt", "RESULT formatted=\"%s\" expected=\"%s\"", formatted.c_str(), expected);
    if (formatted == expected) {
        log_msg(hf, "aob_fmt", "PASS -- format matches source bytes: \"%s\" (elapsed %lld ms)", formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_fmt", "FAIL -- format \"%s\" != expected \"%s\" (elapsed %lld ms)",
            formatted.c_str(), expected, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_aob_format_ida(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_ida", "START -- AOB format as IDA signature");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x2000;
    sig.bytes = {
        {0x48, false}, {0x8B, false}, {0x00, true}, {0x00, true}, {0x48, false}
    };

    std::string ida = aob_generator::format_ida_signature(sig);
    const char* expected = "48 8B ? ? 48";

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "aob_ida", "RESULT ida=\"%s\" expected=\"%s\"", ida.c_str(), expected);
    if (ida == expected) {
        log_msg(hf, "aob_ida", "PASS -- IDA format matches source bytes: \"%s\" (elapsed %lld ms)", ida.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_ida", "FAIL -- IDA format \"%s\" != expected \"%s\" (elapsed %lld ms)",
            ida.c_str(), expected, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_aob_format_yara(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_yara", "START -- AOB format as YARA rule");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x3000;
    sig.name = "test_yara_sig";
    sig.module_name = "ntdll.dll";
    sig.bytes = {
        {0x48, false}, {0x89, false}, {0x00, true}, {0x57, false}
    };
    sig.quality_score = aob_generator::compute_quality_score(sig);

    std::string yara = aob_generator::format_yara_rule(sig);

    bool has_rule = yara.find("rule test_yara_sig") != std::string::npos;
    bool has_bytes = yara.find("48 89 ?? 57") != std::string::npos;
    bool has_cond = yara.find("$pattern") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "aob_yara", "RESULT chars=%zu has_rule=%d has_bytes=%d has_cond=%d",
        yara.size(), static_cast<int>(has_rule), static_cast<int>(has_bytes), static_cast<int>(has_cond));
    if (has_rule && has_bytes && has_cond) {
        log_msg(hf, "aob_yara", "PASS -- YARA rule has name, byte pattern and condition (%zu chars) (elapsed %lld ms)",
            yara.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_yara", "FAIL -- YARA rule missing expected content (rule=%d bytes=%d cond=%d) (elapsed %lld ms)",
            static_cast<int>(has_rule), static_cast<int>(has_bytes), static_cast<int>(has_cond), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_aob_quality_score(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_qs", "START -- AOB compute quality score");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x4000;
    for (int i = 0; i < 32; ++i) {
        sig.bytes.push_back({static_cast<uint8_t>(i), false});
    }
    sig.uniqueness_count = 1;

    float score = aob_generator::compute_quality_score(sig);
    const char* grade = aob_generator::score_grade(score);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "aob_qs", "RESULT quality=%.3f grade=%s (32 concrete bytes, unique)",
        static_cast<double>(score), grade);
    if (score >= 0.85f && grade[0] == 'A') {
        log_msg(hf, "aob_qs", "PASS -- 32 unique concrete bytes graded A (quality=%.3f) (elapsed %lld ms)",
            static_cast<double>(score), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_qs", "FAIL -- expected high quality/grade A, got %.3f/%s (elapsed %lld ms)",
            static_cast<double>(score), grade, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_first_scan_int16(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_i16", "START -- first scan exact int16 marker %d", k_marker_i16);
    auto t0 = std::chrono::steady_clock::now();

    char text[16];
    std::snprintf(text, sizeof(text), "%d", k_marker_i16);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int16_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    cfg.alignment = 2;
    log_msg(hf, "scan_i16", "INPUT value='%s' type=Int16 mode=exact writable_only=0 anchor=0x%llX",
        text, (unsigned long long)g_anchor.addr_i16);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_i16", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_i16", "FAIL -- first_scan=%d found=%zu for known int16 marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int16_t expected = k_marker_i16;
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_i16, matched, rb)) {
        log_msg(hf, "scan_i16", "FAIL -- %zu results but none read back as %d (elapsed %lld ms)",
            found, k_marker_i16, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_i16", "PASS -- found %zu, read-back at 0x%llX = %d (elapsed %lld ms)",
        found, (unsigned long long)matched, k_marker_i16, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_int64(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_i64", "START -- first scan exact int64 marker 0x%016llX", (unsigned long long)k_marker_u64);
    auto t0 = std::chrono::steady_clock::now();

    char text[32];
    std::snprintf(text, sizeof(text), "%lld", static_cast<long long>(k_marker_u64));
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int64_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    cfg.alignment = 8;
    log_msg(hf, "scan_i64", "INPUT value='%s' (0x%016llX) type=Int64 mode=exact writable_only=0 anchor=0x%llX",
        text, (unsigned long long)k_marker_u64, (unsigned long long)g_anchor.addr_u64);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_i64", "RESULT first_scan=%d idle=%d found=%zu first_addr=0x%llX",
        static_cast<int>(ok), static_cast<int>(idle), found,
        (unsigned long long)(found ? results.front().address : 0));

    if (!ok || found == 0) {
        log_msg(hf, "scan_i64", "FAIL -- first_scan=%d found=%zu for unique int64 marker 0x%016llX (elapsed %lld ms)",
            static_cast<int>(ok), found, (unsigned long long)k_marker_u64, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t expected = k_marker_u64;
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_u64, matched, rb)) {
        log_msg(hf, "scan_i64", "FAIL -- %zu results but none read back as 0x%016llX (elapsed %lld ms)",
            found, (unsigned long long)k_marker_u64, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_i64", "PASS -- found %zu, read-back at 0x%llX = %s (elapsed %lld ms)",
        found, (unsigned long long)matched, hex_preview(rb.data(), rb.size()).c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_float(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_flt", "START -- first scan exact float marker %.4f", static_cast<double>(k_marker_flt));
    auto t0 = std::chrono::steady_clock::now();

    char text[32];
    std::snprintf(text, sizeof(text), "%.6g", static_cast<double>(k_marker_flt));
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::float_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_flt", "INPUT value='%s' type=Float mode=exact writable_only=0 anchor=0x%llX",
        text, (unsigned long long)g_anchor.addr_flt);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_flt", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_flt", "FAIL -- first_scan=%d found=%zu for known float marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    float expected = k_marker_flt;
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_flt, matched, rb)) {
        log_msg(hf, "scan_flt", "FAIL -- %zu results but none read back as %.4f (elapsed %lld ms)",
            found, static_cast<double>(k_marker_flt), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    float got = 0.f;
    std::memcpy(&got, rb.data(), sizeof(got));
    log_msg(hf, "scan_flt", "PASS -- found %zu, read-back at 0x%llX = %.4f (elapsed %lld ms)",
        found, (unsigned long long)matched, static_cast<double>(got), (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_double(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_dbl", "START -- first scan exact double marker %.4f", k_marker_dbl);
    auto t0 = std::chrono::steady_clock::now();

    char text[48];
    std::snprintf(text, sizeof(text), "%.10g", k_marker_dbl);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::double_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    cfg.alignment = 8;
    log_msg(hf, "scan_dbl", "INPUT value='%s' type=Double mode=exact writable_only=0 anchor=0x%llX",
        text, (unsigned long long)g_anchor.addr_dbl);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_dbl", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_dbl", "FAIL -- first_scan=%d found=%zu for known double marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    double expected = k_marker_dbl;
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_dbl, matched, rb)) {
        log_msg(hf, "scan_dbl", "FAIL -- %zu results but none read back as %.4f (elapsed %lld ms)",
            found, k_marker_dbl, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    double got = 0.0;
    std::memcpy(&got, rb.data(), sizeof(got));
    log_msg(hf, "scan_dbl", "PASS -- found %zu, read-back at 0x%llX = %.4f (elapsed %lld ms)",
        found, (unsigned long long)matched, got, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_byte_array(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_barr", "START -- first scan byte array (unique 16-byte marker)");
    auto t0 = std::chrono::steady_clock::now();

    std::string aob;
    char b[4];
    for (size_t i = 0; i < sizeof(k_marker_bytes); ++i) {
        std::snprintf(b, sizeof(b), "%02X", k_marker_bytes[i]);
        if (i) aob += ' ';
        aob += b;
    }

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::byte_array;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = aob;
    cfg.hex_input = true;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_barr", "INPUT aob='%s' type=ByteArray writable_only=0 anchor=0x%llX",
        aob.c_str(), (unsigned long long)g_anchor.addr_bytes);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_barr", "RESULT first_scan=%d idle=%d found=%zu first_addr=0x%llX",
        static_cast<int>(ok), static_cast<int>(idle), found,
        (unsigned long long)(found ? results.front().address : 0));

    if (!ok || found == 0) {
        log_msg(hf, "scan_barr", "FAIL -- first_scan=%d found=%zu for unique 16-byte marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, k_marker_bytes, sizeof(k_marker_bytes), g_anchor.addr_bytes, matched, rb)) {
        log_msg(hf, "scan_barr", "FAIL -- %zu results but none read back as the 16-byte marker (elapsed %lld ms)",
            found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_barr", "PASS -- found %zu, read-back at 0x%llX = %s (elapsed %lld ms)",
        found, (unsigned long long)matched, hex_preview(rb.data(), rb.size()).c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_utf16_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_u16", "START -- first scan UTF-16 marker \"%s\"", k_marker_ascii);
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::string_utf16;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = k_marker_ascii;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_u16", "INPUT value='%s' type=UTF-16 mode=exact writable_only=0 anchor=0x%llX",
        k_marker_ascii, (unsigned long long)g_anchor.addr_wide);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_u16", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_u16", "FAIL -- first_scan=%d found=%zu for UTF-16 marker (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    std::vector<uint8_t> expected = memory_scanner::parse_value(k_marker_ascii,
        memory_scanner::value_type_t::string_utf16, false);
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (expected.empty() ||
        !result_reads_back(results, expected.data(), expected.size(), g_anchor.addr_wide, matched, rb)) {
        log_msg(hf, "scan_u16", "FAIL -- %zu results but none read back as the wide marker (elapsed %lld ms)",
            found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_u16", "PASS -- found %zu, wide read-back verified at 0x%llX (elapsed %lld ms)",
        found, (unsigned long long)matched, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_bigger_than(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_gt", "START -- scan mode bigger_than (marker > sentinel)");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_gt", "FAIL -- no planted anchor; cannot validate bigger_than against known value (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t sentinel = k_marker_i32 - 1;
    char text[32];
    std::snprintf(text, sizeof(text), "%d", sentinel);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::bigger_than;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_gt", "INPUT bigger_than '%s' (marker 0x%08X must qualify)", text, static_cast<unsigned>(k_marker_i32));

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);
    bool anchor_present = false;
    for (auto& r : results) if (r.address == g_anchor.addr_i32) { anchor_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_gt", "RESULT first_scan=%d idle=%d found=%zu anchor_present=%d",
        static_cast<int>(ok), static_cast<int>(idle), found, static_cast<int>(anchor_present));

    if (!ok || found == 0 || !anchor_present) {
        log_msg(hf, "scan_gt", "FAIL -- bigger_than missed marker (ok=%d found=%zu present=%d) (elapsed %lld ms)",
            static_cast<int>(ok), found, static_cast<int>(anchor_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_gt", "PASS -- bigger_than(%d) found %zu incl. marker @0x%llX (elapsed %lld ms)",
        sentinel, found, (unsigned long long)g_anchor.addr_i32, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_smaller_than(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_lt", "START -- scan mode smaller_than (marker < sentinel)");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_lt", "FAIL -- no planted anchor; cannot validate smaller_than against known value (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t marker = k_marker_i16;
    int32_t sentinel = marker + 1;
    int32_t probe = marker;
    std::vector<uint8_t> pb(reinterpret_cast<uint8_t*>(&probe), reinterpret_cast<uint8_t*>(&probe) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, pb);

    char text[32];
    std::snprintf(text, sizeof(text), "%d", sentinel);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::smaller_than;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_lt", "INPUT smaller_than '%s' (scratch holds %d at 0x%llX)",
        text, probe, (unsigned long long)g_anchor.addr_scratch);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);
    bool scratch_present = false;
    for (auto& r : results) if (r.address == g_anchor.addr_scratch) { scratch_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_lt", "RESULT first_scan=%d idle=%d found=%zu scratch_present=%d",
        static_cast<int>(ok), static_cast<int>(idle), found, static_cast<int>(scratch_present));

    if (!ok || found == 0 || !scratch_present) {
        log_msg(hf, "scan_lt", "FAIL -- smaller_than missed scratch (ok=%d found=%zu present=%d) (elapsed %lld ms)",
            static_cast<int>(ok), found, static_cast<int>(scratch_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_lt", "PASS -- smaller_than(%d) found %zu incl. scratch @0x%llX (elapsed %lld ms)",
        sentinel, found, (unsigned long long)g_anchor.addr_scratch, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_between(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_btw", "START -- scan mode value_between bracketing the marker");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_btw", "FAIL -- no planted anchor; cannot bracket a known value (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t lo = k_marker_i32 - 16;
    int32_t hi = k_marker_i32 + 16;
    char t_lo[32], t_hi[32];
    std::snprintf(t_lo, sizeof(t_lo), "%d", lo);
    std::snprintf(t_hi, sizeof(t_hi), "%d", hi);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::value_between;
    cfg.value_text = t_lo;
    cfg.value_text2 = t_hi;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_btw", "INPUT between [%d,%d] (marker 0x%08X inside)", lo, hi, static_cast<unsigned>(k_marker_i32));

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);
    bool anchor_present = false;
    for (auto& r : results) if (r.address == g_anchor.addr_i32) { anchor_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_btw", "RESULT first_scan=%d idle=%d found=%zu anchor_present=%d",
        static_cast<int>(ok), static_cast<int>(idle), found, static_cast<int>(anchor_present));

    if (!ok || found == 0 || !anchor_present) {
        log_msg(hf, "scan_btw", "FAIL -- between missed marker (ok=%d found=%zu present=%d) (elapsed %lld ms)",
            static_cast<int>(ok), found, static_cast<int>(anchor_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_btw", "PASS -- between [%d,%d] found %zu incl. marker @0x%llX (elapsed %lld ms)",
        lo, hi, found, (unsigned long long)g_anchor.addr_i32, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_unknown_initial(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_unk", "START -- scan mode unknown_initial");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::unknown_initial;
    cfg.writable_only = true;
    cfg.executable_exclude = true;
    cfg.alignment = 4;
    log_msg(hf, "scan_unk", "INPUT unknown_initial type=Int32 writable_only=1");

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    size_t found = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        found = memory_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_unk", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_unk", "FAIL -- unknown_initial captured no addresses (ok=%d found=%zu) (elapsed %lld ms)",
            static_cast<int>(ok), found, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_unk", "PASS -- unknown_initial snapshotted %zu candidate addresses (elapsed %lld ms)",
        found, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_increased(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_inc", "START -- next scan increased after a +1 write");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_inc", "FAIL -- no planted anchor; cannot drive a deterministic increase (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t base_val = 1000;
    std::vector<uint8_t> b0(reinterpret_cast<uint8_t*>(&base_val), reinterpret_cast<uint8_t*>(&base_val) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, b0);

    char text[32];
    std::snprintf(text, sizeof(text), "%d", base_val);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_inc", "INPUT seed exact %d at 0x%llX then raise and next_scan(increased)",
        base_val, (unsigned long long)g_anchor.addr_scratch);

    bool seed_ok = memory_scanner::first_scan(cfg);
    wait_scan_idle();
    std::vector<memory_scanner::scan_result_t> before;
    size_t before_n = snapshot_results(before);

    int32_t raised = base_val + 5000;
    std::vector<uint8_t> b1(reinterpret_cast<uint8_t*>(&raised), reinterpret_cast<uint8_t*>(&raised) + 4);
    bool mutated = driver_bridge::write_memory(g_anchor.addr_scratch, b1);

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::increased, "", "");
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> after;
    size_t after_n = snapshot_results(after);
    bool scratch_present = false;
    for (auto& r : after) if (r.address == g_anchor.addr_scratch) { scratch_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_inc", "RESULT seed=%d before=%zu mutated=%d next_scan=%d idle=%d after=%zu scratch_present=%d",
        static_cast<int>(seed_ok), before_n, static_cast<int>(mutated),
        static_cast<int>(ok), static_cast<int>(idle), after_n, static_cast<int>(scratch_present));

    if (!seed_ok || before_n == 0 || !mutated || !ok) {
        log_msg(hf, "scan_inc", "FAIL -- setup failed (seed=%d before=%zu mutated=%d next=%d) (elapsed %lld ms)",
            static_cast<int>(seed_ok), before_n, static_cast<int>(mutated), static_cast<int>(ok), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (after_n == 0 || !scratch_present) {
        log_msg(hf, "scan_inc", "FAIL -- increased missed the raised scratch (after=%zu present=%d) (elapsed %lld ms)",
            after_n, static_cast<int>(scratch_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_inc", "PASS -- increased retained raised scratch 0x%llX (after=%zu) (elapsed %lld ms)",
        (unsigned long long)g_anchor.addr_scratch, after_n, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_decreased(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_dec", "START -- next scan decreased after a -1 write");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_dec", "FAIL -- no planted anchor; cannot drive a deterministic decrease (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t base_val = 9000;
    std::vector<uint8_t> b0(reinterpret_cast<uint8_t*>(&base_val), reinterpret_cast<uint8_t*>(&base_val) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, b0);

    char text[32];
    std::snprintf(text, sizeof(text), "%d", base_val);
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_dec", "INPUT seed exact %d at 0x%llX then lower and next_scan(decreased)",
        base_val, (unsigned long long)g_anchor.addr_scratch);

    bool seed_ok = memory_scanner::first_scan(cfg);
    wait_scan_idle();
    std::vector<memory_scanner::scan_result_t> before;
    size_t before_n = snapshot_results(before);

    int32_t lowered = base_val - 5000;
    std::vector<uint8_t> b1(reinterpret_cast<uint8_t*>(&lowered), reinterpret_cast<uint8_t*>(&lowered) + 4);
    bool mutated = driver_bridge::write_memory(g_anchor.addr_scratch, b1);

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::decreased, "", "");
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> after;
    size_t after_n = snapshot_results(after);
    bool scratch_present = false;
    for (auto& r : after) if (r.address == g_anchor.addr_scratch) { scratch_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_dec", "RESULT seed=%d before=%zu mutated=%d next_scan=%d idle=%d after=%zu scratch_present=%d",
        static_cast<int>(seed_ok), before_n, static_cast<int>(mutated),
        static_cast<int>(ok), static_cast<int>(idle), after_n, static_cast<int>(scratch_present));

    if (!seed_ok || before_n == 0 || !mutated || !ok) {
        log_msg(hf, "scan_dec", "FAIL -- setup failed (seed=%d before=%zu mutated=%d next=%d) (elapsed %lld ms)",
            static_cast<int>(seed_ok), before_n, static_cast<int>(mutated), static_cast<int>(ok), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (after_n == 0 || !scratch_present) {
        log_msg(hf, "scan_dec", "FAIL -- decreased missed the lowered scratch (after=%zu present=%d) (elapsed %lld ms)",
            after_n, static_cast<int>(scratch_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_dec", "PASS -- decreased retained lowered scratch 0x%llX (after=%zu) (elapsed %lld ms)",
        (unsigned long long)g_anchor.addr_scratch, after_n, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_hex_input(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_hex", "START -- first scan with hex input (marker via hex)");
    auto t0 = std::chrono::steady_clock::now();

    char text[16];
    std::snprintf(text, sizeof(text), "%X", static_cast<unsigned>(k_marker_i32));
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.hex_input = true;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    log_msg(hf, "scan_hex", "INPUT hex value='%s' type=Int32 anchor=0x%llX",
        text, (unsigned long long)g_anchor.addr_i32);

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_hex", "RESULT first_scan=%d idle=%d found=%zu", static_cast<int>(ok), static_cast<int>(idle), found);

    if (!ok || found == 0) {
        log_msg(hf, "scan_hex", "FAIL -- hex scan first_scan=%d found=%zu for marker 0x%s (elapsed %lld ms)",
            static_cast<int>(ok), found, text, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t expected = k_marker_i32;
    uint64_t matched = 0;
    std::vector<uint8_t> rb;
    if (!result_reads_back(results, reinterpret_cast<const uint8_t*>(&expected), sizeof(expected),
                           g_anchor.addr_i32, matched, rb)) {
        log_msg(hf, "scan_hex", "FAIL -- %zu results but none read back as 0x%s (elapsed %lld ms)",
            found, text, (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_hex", "PASS -- hex input parsed and matched marker @0x%llX (found %zu) (elapsed %lld ms)",
        (unsigned long long)matched, found, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_alignment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_aln", "START -- first scan with alignment=8 finds 8-aligned marker");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_aln", "FAIL -- no planted anchor with known alignment (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }

    char text[32];
    std::snprintf(text, sizeof(text), "%lld", static_cast<long long>(k_marker_u64));
    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int64_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = text;
    cfg.alignment = 8;
    cfg.writable_only = false;
    cfg.executable_exclude = false;
    bool aligned8 = (g_anchor.addr_u64 % 8) == 0;
    log_msg(hf, "scan_aln", "INPUT exact Int64 marker alignment=8 anchor=0x%llX aligned8=%d",
        (unsigned long long)g_anchor.addr_u64, static_cast<int>(aligned8));

    bool ok = memory_scanner::first_scan(cfg);
    bool idle = wait_scan_idle();

    std::vector<memory_scanner::scan_result_t> results;
    size_t found = snapshot_results(results);
    bool anchor_present = false;
    for (auto& r : results) if (r.address == g_anchor.addr_u64) { anchor_present = true; break; }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_aln", "RESULT first_scan=%d idle=%d found=%zu anchor_present=%d",
        static_cast<int>(ok), static_cast<int>(idle), found, static_cast<int>(anchor_present));

    if (!ok || found == 0 || !anchor_present) {
        log_msg(hf, "scan_aln", "FAIL -- aligned scan missed 8-aligned marker (ok=%d found=%zu present=%d) (elapsed %lld ms)",
            static_cast<int>(ok), found, static_cast<int>(anchor_present), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "scan_aln", "PASS -- alignment=8 scan found %zu incl. marker @0x%llX (elapsed %lld ms)",
        found, (unsigned long long)g_anchor.addr_u64, (long long)ms);
    passed.fetch_add(1);
}

static void test_write_value(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_wrv", "START -- write_value then read-back");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_wrv", "FAIL -- no planted anchor; no safe writable address to verify (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t target_val = 0x2468ACE0;
    char text[32];
    std::snprintf(text, sizeof(text), "%d", target_val);
    log_msg(hf, "scan_wrv", "INPUT write_value addr=0x%llX type=Int32 value='%s'",
        (unsigned long long)g_anchor.addr_scratch, text);

    memory_scanner::write_value(g_anchor.addr_scratch, memory_scanner::value_type_t::int32_val, text, false);

    std::vector<uint8_t> rb;
    bool read_ok = driver_bridge::read_memory(g_anchor.addr_scratch, 4, rb);
    int32_t got = 0;
    if (rb.size() >= 4) std::memcpy(&got, rb.data(), 4);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_wrv", "RESULT read_ok=%d wrote=%d read=%d",
        static_cast<int>(read_ok), target_val, got);

    if (read_ok && got == target_val) {
        log_msg(hf, "scan_wrv", "PASS -- write_value wrote 0x%08X and read back identical (elapsed %lld ms)",
            static_cast<unsigned>(target_val), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_wrv", "FAIL -- write_value mismatch (wrote 0x%08X read 0x%08X read_ok=%d) (elapsed %lld ms)",
            static_cast<unsigned>(target_val), static_cast<unsigned>(got), static_cast<int>(read_ok), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_refresh_address_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_ral", "START -- refresh_address_list reads live value");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "scan_ral", "FAIL -- no planted anchor; cannot validate refreshed value (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    int32_t known = 0x0FACADE0;
    std::vector<uint8_t> kb(reinterpret_cast<uint8_t*>(&known), reinterpret_cast<uint8_t*>(&known) + 4);
    driver_bridge::write_memory(g_anchor.addr_scratch, kb);

    memory_scanner::add_address(g_anchor.addr_scratch, "test_refresh", memory_scanner::value_type_t::int32_val);
    memory_scanner::refresh_address_list();

    size_t idx = 0;
    bool found_idx = false;
    int32_t last_val = 0;
    bool has_value = false;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        for (size_t i = 0; i < memory_scanner::g_state.address_list.size(); ++i) {
            auto& e = memory_scanner::g_state.address_list[i];
            if (e.address == g_anchor.addr_scratch) {
                idx = i; found_idx = true;
                if (e.last_value.size() >= 4) {
                    std::memcpy(&last_val, e.last_value.data(), 4);
                    has_value = true;
                }
                break;
            }
        }
    }

    if (found_idx) memory_scanner::remove_address(idx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_ral", "RESULT found_idx=%d has_value=%d last_value=0x%08X expected=0x%08X",
        static_cast<int>(found_idx), static_cast<int>(has_value),
        static_cast<unsigned>(last_val), static_cast<unsigned>(known));

    if (found_idx && has_value && last_val == known) {
        log_msg(hf, "scan_ral", "PASS -- refresh populated last_value=0x%08X (elapsed %lld ms)",
            static_cast<unsigned>(last_val), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_ral", "FAIL -- refresh did not capture known value (found=%d has=%d got=0x%08X) (elapsed %lld ms)",
            static_cast<int>(found_idx), static_cast<int>(has_value), static_cast<unsigned>(last_val), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_parse_int16(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fp16", "START -- format/parse int16 roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("1234", memory_scanner::value_type_t::int16_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::int16_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_fp16", "RESULT parsed_bytes=%zu formatted=\"%s\"", parsed.size(), formatted.c_str());
    if (parsed.size() == 2 && formatted == "1234") {
        log_msg(hf, "scan_fp16", "PASS -- roundtrip int16: 1234 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fp16", "FAIL -- expected 2 bytes/\"1234\" got %zu/\"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_parse_float(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fpfl", "START -- format/parse float roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("1.5", memory_scanner::value_type_t::float_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::float_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_fpfl", "RESULT parsed_bytes=%zu formatted=\"%s\"", parsed.size(), formatted.c_str());
    bool close = parsed.size() == 4 && !formatted.empty() && formatted.find("1.5") != std::string::npos;
    if (close) {
        log_msg(hf, "scan_fpfl", "PASS -- roundtrip float: 1.5 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fpfl", "FAIL -- expected 4 bytes/~\"1.5\" got %zu/\"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_parse_double(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fpdl", "START -- format/parse double roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("2.71828", memory_scanner::value_type_t::double_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::double_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_fpdl", "RESULT parsed_bytes=%zu formatted=\"%s\"", parsed.size(), formatted.c_str());
    bool close = parsed.size() == 8 && !formatted.empty() && formatted.find("2.71") != std::string::npos;
    if (close) {
        log_msg(hf, "scan_fpdl", "PASS -- roundtrip double: 2.71828 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fpdl", "FAIL -- expected 8 bytes/~2.71828 got %zu/\"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_scan_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_scan", "START -- pointer scanner start_scan against planted chain");
    auto t0 = std::chrono::steady_clock::now();

    if (!g_anchor.planted) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "ptr_scan", "FAIL -- no planted anchor; cannot guarantee a known pointer chain (elapsed %lld ms)",
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    pointer_scanner::clear_results();
    pointer_scanner::clear_map();

    log_msg(hf, "ptr_scan", "INPUT rebuild reverse map then scan target=0x%llX (chain l0=0x%llX -> l1=0x%llX -> target)",
        (unsigned long long)g_anchor.ptr_target, (unsigned long long)g_anchor.ptr_level0,
        (unsigned long long)g_anchor.ptr_level1);

    pointer_scanner::build_reverse_map();
    bool map_idle = false;
    for (int i = 0; i < 200; ++i) {
        if (!pointer_scanner::g_state.map_building.load()) { map_idle = true; break; }
        Sleep(100);
    }

    size_t map_entries = 0;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.map_mutex);
        map_entries = pointer_scanner::g_state.map_entry_count;
    }

    pointer_scanner::g_state.config.target_address = g_anchor.ptr_target;
    pointer_scanner::g_state.config.max_depth = 4;
    pointer_scanner::g_state.config.max_offset = 256;
    pointer_scanner::g_state.config.struct_size = 256;
    pointer_scanner::g_state.config.negative_offsets = false;
    pointer_scanner::g_state.config.only_static_bases = false;

    pointer_scanner::start_scan();
    bool scan_idle = false;
    for (int i = 0; i < 200; ++i) {
        if (!pointer_scanner::g_state.scanning.load()) { scan_idle = true; break; }
        Sleep(100);
    }

    size_t chains = 0;
    bool found_level1 = false;
    bool found_level0 = false;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.results_mutex);
        chains = pointer_scanner::g_state.results.size();
        for (auto& c : pointer_scanner::g_state.results) {
            if (c.base_offset == g_anchor.ptr_level1) found_level1 = true;
            if (c.base_offset == g_anchor.ptr_level0) found_level0 = true;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_scan", "RESULT map_idle=%d entries=%zu scan_idle=%d chains=%zu found_l1=%d found_l0=%d",
        static_cast<int>(map_idle), map_entries, static_cast<int>(scan_idle), chains,
        static_cast<int>(found_level1), static_cast<int>(found_level0));

    if (!map_idle || !scan_idle) {
        log_msg(hf, "ptr_scan", "FAIL -- map/scan did not finish within budget (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
        return;
    }
    if (chains == 0 || !found_level1) {
        log_msg(hf, "ptr_scan", "FAIL -- 0 chains or planted chain not recovered (chains=%zu l1=%d l0=%d) (elapsed %lld ms)",
            chains, static_cast<int>(found_level1), static_cast<int>(found_level0), (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "ptr_scan", "PASS -- pointer scan found %zu chains incl. planted l1=0x%llX (l0=%d) (elapsed %lld ms)",
        chains, (unsigned long long)g_anchor.ptr_level1, static_cast<int>(found_level0), (long long)ms);
    passed.fetch_add(1);
}

static void test_pointer_chain_to_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_str", "START -- pointer scanner chain_to_string");
    auto t0 = std::chrono::steady_clock::now();

    pointer_scanner::pointer_chain_t chain;
    chain.module_name = "ntdll.dll";
    chain.base_offset = 0x1000;
    chain.offsets = { 0x10, 0x20, 0x30 };
    chain.depth = 3;
    chain.is_static = true;

    std::string str = pointer_scanner::chain_to_string(chain);
    const char* expected = "ntdll.dll+0x1000 -> +0x10 -> +0x20 -> +0x30";

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_str", "RESULT chain_to_string=\"%s\" expected=\"%s\"", str.c_str(), expected);
    if (str == expected) {
        log_msg(hf, "ptr_str", "PASS -- chain_to_string exact: \"%s\" (elapsed %lld ms)", str.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ptr_str", "FAIL -- chain_to_string \"%s\" != \"%s\" (elapsed %lld ms)",
            str.c_str(), expected, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_export_cpp(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_cpp", "START -- pointer scanner export_chain_cpp");
    auto t0 = std::chrono::steady_clock::now();

    pointer_scanner::pointer_chain_t chain;
    chain.module_name = "ntdll.dll";
    chain.base_offset = 0x2000;
    chain.offsets = { 0x18, 0x28 };
    chain.depth = 2;
    chain.is_static = true;

    std::string cpp = pointer_scanner::export_chain_cpp(chain);

    bool has_rpm = cpp.find("ReadProcessMemory") != std::string::npos;
    bool has_base = cpp.find("moduleBase + 0x2000") != std::string::npos;
    bool has_off1 = cpp.find("0x18") != std::string::npos;
    bool has_off2 = cpp.find("0x28") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_cpp", "RESULT chars=%zu has_rpm=%d has_base=%d has_off1=%d has_off2=%d",
        cpp.size(), static_cast<int>(has_rpm), static_cast<int>(has_base),
        static_cast<int>(has_off1), static_cast<int>(has_off2));
    if (has_rpm && has_base && has_off1 && has_off2) {
        log_msg(hf, "ptr_cpp", "PASS -- export_chain_cpp emitted resolver with base+offsets (%zu chars) (elapsed %lld ms)",
            cpp.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ptr_cpp", "FAIL -- export_chain_cpp missing expected content (rpm=%d base=%d o1=%d o2=%d) (elapsed %lld ms)",
            static_cast<int>(has_rpm), static_cast<int>(has_base),
            static_cast<int>(has_off1), static_cast<int>(has_off2), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_export_json(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_json", "START -- pointer scanner export_results_json");
    auto t0 = std::chrono::steady_clock::now();

    pointer_scanner::clear_results();
    {
        pointer_scanner::pointer_chain_t chain;
        chain.module_name = "test_mod.dll";
        chain.base_offset = 0x4000;
        chain.offsets = { 0x8, 0x40 };
        chain.depth = 2;
        chain.is_static = true;
        chain.validated = true;
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.results_mutex);
        pointer_scanner::g_state.results.push_back(std::move(chain));
    }

    std::string json = pointer_scanner::export_results_json();
    pointer_scanner::clear_results();

    bool has_mod = json.find("test_mod.dll") != std::string::npos;
    bool has_base = json.find("0x4000") != std::string::npos;
    bool has_offsets = json.find("\"offsets\"") != std::string::npos;
    bool has_valid = json.find("\"valid\": true") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_json", "RESULT chars=%zu has_mod=%d has_base=%d has_offsets=%d has_valid=%d",
        json.size(), static_cast<int>(has_mod), static_cast<int>(has_base),
        static_cast<int>(has_offsets), static_cast<int>(has_valid));
    if (has_mod && has_base && has_offsets && has_valid) {
        log_msg(hf, "ptr_json", "PASS -- export_results_json serialized chain fields (%zu chars) (elapsed %lld ms)",
            json.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ptr_json", "FAIL -- export_results_json missing chain fields (mod=%d base=%d off=%d valid=%d) (elapsed %lld ms)",
            static_cast<int>(has_mod), static_cast<int>(has_base),
            static_cast<int>(has_offsets), static_cast<int>(has_valid), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_snapshot_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "snap_clr", "START -- clear snapshots");
    auto t0 = std::chrono::steady_clock::now();

    snapshot_diff::clear_snapshots();

    size_t snap_count = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        snap_count = snapshot_diff::g_state.snapshots.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "snap_clr", "RESULT remaining=%zu", snap_count);
    if (snap_count == 0) {
        log_msg(hf, "snap_clr", "PASS -- snapshots cleared (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "snap_clr", "FAIL -- %zu snapshots remaining (elapsed %lld ms)", snap_count, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_aob_format_code(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_code", "START -- AOB format as code pattern+mask");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x5000;
    sig.bytes = {
        {0x48, false}, {0x89, false}, {0x00, true}, {0x57, false}
    };

    std::string code = aob_generator::format_code_signature(sig);
    const char* expected = "\"\\x48\\x89\\x00\\x57\", \"xx?x\"";

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "aob_code", "RESULT code=\"%s\" expected=\"%s\"", code.c_str(), expected);
    if (code == expected) {
        log_msg(hf, "aob_code", "PASS -- code format matches source bytes+mask: \"%s\" (elapsed %lld ms)", code.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_code", "FAIL -- code format \"%s\" != expected \"%s\" (elapsed %lld ms)",
            code.c_str(), expected, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_aob_format_x64dbg(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_x64", "START -- AOB format as x64dbg signature");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x6000;
    sig.bytes = {
        {0x48, false}, {0x8B, false}, {0x00, true}, {0x48, false}, {0x85, false}
    };

    std::string x64dbg = aob_generator::format_x64dbg_signature(sig);
    const char* expected = "48 8b ?? 48 85";

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "aob_x64", "RESULT x64dbg=\"%s\" expected=\"%s\"", x64dbg.c_str(), expected);
    if (x64dbg == expected) {
        log_msg(hf, "aob_x64", "PASS -- x64dbg format matches source bytes: \"%s\" (elapsed %lld ms)", x64dbg.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_x64", "FAIL -- x64dbg format \"%s\" != expected \"%s\" (elapsed %lld ms)",
            x64dbg.c_str(), expected, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_aob_score_grades(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_grd", "START -- AOB score grade boundaries");
    auto t0 = std::chrono::steady_clock::now();

    const char* grade_a = aob_generator::score_grade(0.90f);
    const char* grade_b = aob_generator::score_grade(0.75f);
    const char* grade_c = aob_generator::score_grade(0.55f);
    const char* grade_d = aob_generator::score_grade(0.35f);
    const char* grade_f = aob_generator::score_grade(0.10f);

    bool ok = (grade_a[0] == 'A' && grade_b[0] == 'B' && grade_c[0] == 'C' &&
               grade_d[0] == 'D' && grade_f[0] == 'F');

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "aob_grd", "RESULT A=%s B=%s C=%s D=%s F=%s", grade_a, grade_b, grade_c, grade_d, grade_f);
    if (ok) {
        log_msg(hf, "aob_grd", "PASS -- grade boundaries: A=%s B=%s C=%s D=%s F=%s (elapsed %lld ms)",
            grade_a, grade_b, grade_c, grade_d, grade_f, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_grd", "FAIL -- unexpected grade mapping A=%s B=%s C=%s D=%s F=%s (elapsed %lld ms)",
            grade_a, grade_b, grade_c, grade_d, grade_f, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_aob_quality_all_wildcards(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "aob_qaw", "START -- AOB quality score all-wildcard signature");
    auto t0 = std::chrono::steady_clock::now();

    aob_generator::signature_t sig;
    sig.address = 0x7000;
    for (int i = 0; i < 16; ++i) {
        sig.bytes.push_back({0x00, true});
    }

    float score = aob_generator::compute_quality_score(sig);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "aob_qaw", "RESULT quality=%.3f (expected ~0 for all-wildcard)", static_cast<double>(score));
    if (score < 0.01f) {
        log_msg(hf, "aob_qaw", "PASS -- all-wildcard quality=%.3f (~0) (elapsed %lld ms)", static_cast<double>(score), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_qaw", "FAIL -- all-wildcard quality=%.3f should be ~0 (elapsed %lld ms)", static_cast<double>(score), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_crypto_category_name(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_cn", "START -- crypto scanner category_name");
    auto t0 = std::chrono::steady_clock::now();

    const char* sym = crypto_scanner::category_name(crypto_scanner::crypto_category_t::symmetric);
    const char* hash = crypto_scanner::category_name(crypto_scanner::crypto_category_t::hash);
    const char* stream = crypto_scanner::category_name(crypto_scanner::crypto_category_t::stream_cipher);
    const char* block = crypto_scanner::category_name(crypto_scanner::crypto_category_t::block_cipher);
    const char* check = crypto_scanner::category_name(crypto_scanner::crypto_category_t::checksum);
    const char* enc = crypto_scanner::category_name(crypto_scanner::crypto_category_t::encoding);
    const char* asym = crypto_scanner::category_name(crypto_scanner::crypto_category_t::asymmetric);

    bool ok = (std::strcmp(sym, "Symmetric") == 0 &&
               std::strcmp(hash, "Hash") == 0 &&
               std::strcmp(stream, "Stream Cipher") == 0 &&
               std::strcmp(block, "Block Cipher") == 0 &&
               std::strcmp(check, "Checksum") == 0 &&
               std::strcmp(enc, "Encoding") == 0 &&
               std::strcmp(asym, "Asymmetric") == 0);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_cn", "RESULT sym=%s hash=%s stream=%s block=%s check=%s enc=%s asym=%s",
        sym, hash, stream, block, check, enc, asym);
    if (ok) {
        log_msg(hf, "crypto_cn", "PASS -- all category names correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "crypto_cn", "FAIL -- unexpected category name (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_crypto_get_function_label(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_gl", "START -- crypto scanner get_function_label (unmapped addr => empty)");
    auto t0 = std::chrono::steady_clock::now();

    std::string label = crypto_scanner::get_function_label(0xDEADBEEFDEADBEEFULL);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_gl", "RESULT label=\"%s\" (empty expected)", label.c_str());
    if (label.empty()) {
        log_msg(hf, "crypto_gl", "PASS -- get_function_label returned empty for unlabeled address (elapsed %lld ms)",
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "crypto_gl", "FAIL -- get_function_label returned \"%s\" for unlabeled address (elapsed %lld ms)",
            label.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_value_type_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_vtn", "START -- value_type_name and scan_mode_name");
    auto t0 = std::chrono::steady_clock::now();

    const char* n_byte = memory_scanner::value_type_name(memory_scanner::value_type_t::byte_val);
    const char* n_i32 = memory_scanner::value_type_name(memory_scanner::value_type_t::int32_val);
    const char* n_flt = memory_scanner::value_type_name(memory_scanner::value_type_t::float_val);
    const char* m_exact = memory_scanner::scan_mode_name(memory_scanner::scan_mode_t::exact);
    const char* m_bigger = memory_scanner::scan_mode_name(memory_scanner::scan_mode_t::bigger_than);

    bool ok = (std::strcmp(n_byte, "Byte") == 0 &&
               std::strcmp(n_i32, "Int32") == 0 &&
               std::strcmp(n_flt, "Float") == 0 &&
               std::strcmp(m_exact, "Exact Value") == 0 &&
               std::strcmp(m_bigger, "Bigger Than") == 0);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_vtn", "RESULT byte=%s i32=%s flt=%s exact=%s bigger=%s",
        n_byte, n_i32, n_flt, m_exact, m_bigger);
    if (ok) {
        log_msg(hf, "scan_vtn", "PASS -- all type/mode names correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_vtn", "FAIL -- unexpected name (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_value_type_size(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_vts", "START -- value_type_size");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = (memory_scanner::value_type_size(memory_scanner::value_type_t::byte_val) == 1 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::int16_val) == 2 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::int32_val) == 4 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::int64_val) == 8 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::float_val) == 4 &&
               memory_scanner::value_type_size(memory_scanner::value_type_t::double_val) == 8);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "scan_vts", "PASS -- all value_type_size correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_vts", "FAIL -- unexpected value_type_size (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_memscan_shutdown(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_shut", "START -- memory_scanner::shutdown");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::shutdown();

    bool idle = !memory_scanner::g_state.scanning.load() &&
                !memory_scanner::g_state.pointer_scanning.load() &&
                memory_scanner::g_state.scan_thread_done.load() &&
                memory_scanner::g_state.freeze_thread_done.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_shut", "RESULT idle=%d scanning=%d freeze_done=%d",
        static_cast<int>(idle),
        static_cast<int>(memory_scanner::g_state.scanning.load()),
        static_cast<int>(memory_scanner::g_state.freeze_thread_done.load()));
    if (idle) {
        log_msg(hf, "scan_shut", "PASS -- shutdown quiesced all worker flags (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_shut", "FAIL -- worker flags still active after shutdown (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void select_scan_hub_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                const char* tag, scan_hub_view::sub_tab_t value) {
    scan_hub_view::set_sub_tab(value);
    scan_hub_view::sub_tab_t got = scan_hub_view::active_sub_tab();
    if (got == value) {
        log_msg(hf, tag, "PASS -- scan_hub sub_tab selected and read back (%d)", static_cast<int>(value));
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- scan_hub sub_tab set %d but read back %d",
            static_cast<int>(value), static_cast<int>(got));
        failed.fetch_add(1);
    }
}

static void test_scan_hub_tab_value_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.value_scan", scan_hub_view::sub_tab_t::value_scan);
}
static void test_scan_hub_tab_crypto(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.crypto", scan_hub_view::sub_tab_t::crypto);
}
static void test_scan_hub_tab_aob(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.aob", scan_hub_view::sub_tab_t::aob);
}
static void test_scan_hub_tab_decrypt(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.decrypt", scan_hub_view::sub_tab_t::decrypt);
}
static void test_scan_hub_tab_pointers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.pointers", scan_hub_view::sub_tab_t::pointers);
}
static void test_scan_hub_tab_snapshots(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.snapshots", scan_hub_view::sub_tab_t::snapshots);
}
static void test_scan_hub_tab_integrity(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_scan_hub_tab(hf, passed, failed, "scan_hub_tab.integrity", scan_hub_view::sub_tab_t::integrity);
}

}

void phase_scanner_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    log_msg(hf, "scanner", "=== BEGIN scanner tests (63 tests) ===");

    bool planted = plant_anchor(hf);
    log_msg(hf, "scanner", "anchor planted=%d pid=%u (value/snapshot/pointer tests key off resident markers)",
        static_cast<int>(planted), driver_bridge::attached_pid());

    struct test_entry_t {
        const char* name;
        void (*fn)(HANDLE, std::atomic<int>&, std::atomic<int>&);
    };

    static const test_entry_t tests[] = {
        { "memscan_initialize",       test_memscan_initialize       },
        { "first_scan_int32",         test_first_scan_int32         },
        { "first_scan_byte",          test_first_scan_byte          },
        { "first_scan_int16",         test_first_scan_int16         },
        { "first_scan_int64",         test_first_scan_int64         },
        { "first_scan_float",         test_first_scan_float         },
        { "first_scan_double",        test_first_scan_double        },
        { "first_scan_byte_array",    test_first_scan_byte_array    },
        { "first_scan_string",        test_first_scan_string        },
        { "first_scan_utf16_string",  test_first_scan_utf16_string  },
        { "scan_mode_bigger_than",    test_scan_mode_bigger_than    },
        { "scan_mode_smaller_than",   test_scan_mode_smaller_than   },
        { "scan_mode_between",        test_scan_mode_between        },
        { "scan_mode_unknown_init",   test_scan_mode_unknown_initial},
        { "next_scan_unchanged",      test_next_scan_unchanged      },
        { "next_scan_changed",        test_next_scan_changed        },
        { "next_scan_increased",      test_next_scan_increased      },
        { "next_scan_decreased",      test_next_scan_decreased      },
        { "scan_hex_input",           test_scan_hex_input           },
        { "scan_alignment",           test_scan_alignment           },
        { "undo_scan",                test_undo_scan                },
        { "reset_scan",               test_reset_scan               },
        { "add_address",              test_add_address              },
        { "remove_address",           test_remove_address           },
        { "freeze_address",           test_freeze_address           },
        { "write_value",              test_write_value              },
        { "read_value_string",        test_read_value_string        },
        { "refresh_address_list",     test_refresh_address_list     },
        { "format_parse_roundtrip",   test_format_parse_roundtrip   },
        { "format_parse_int16",       test_format_parse_int16       },
        { "format_parse_float",       test_format_parse_float       },
        { "format_parse_double",      test_format_parse_double      },
        { "value_type_names",         test_value_type_names         },
        { "value_type_size",          test_value_type_size          },
        { "crypto_get_signatures",    test_crypto_get_signatures    },
        { "crypto_scan_process",      test_crypto_scan_process      },
        { "crypto_scan_entropy",      test_crypto_scan_entropy      },
        { "crypto_add_custom_sig",    test_crypto_add_custom_sig    },
        { "crypto_category_name",     test_crypto_category_name     },
        { "crypto_get_func_label",    test_crypto_get_function_label},
        { "pointer_build_map",        test_pointer_build_reverse_map},
        { "pointer_scan_start",       test_pointer_scan_start       },
        { "pointer_chain_to_string",  test_pointer_chain_to_string  },
        { "pointer_export_cpp",       test_pointer_export_cpp       },
        { "pointer_export_json",      test_pointer_export_json      },
        { "snapshot_take",            test_snapshot_take             },
        { "snapshot_compare",         test_snapshot_compare          },
        { "snapshot_clear",           test_snapshot_clear            },
        { "aob_format_signature",     test_aob_format_signature     },
        { "aob_format_ida",           test_aob_format_ida           },
        { "aob_format_yara",          test_aob_format_yara          },
        { "aob_format_code",          test_aob_format_code          },
        { "aob_format_x64dbg",        test_aob_format_x64dbg        },
        { "aob_quality_score",        test_aob_quality_score        },
        { "aob_score_grades",         test_aob_score_grades         },
        { "aob_quality_all_wc",       test_aob_quality_all_wildcards},

        { "scan_hub_tab_value_scan",  test_scan_hub_tab_value_scan  },
        { "scan_hub_tab_crypto",      test_scan_hub_tab_crypto      },
        { "scan_hub_tab_aob",         test_scan_hub_tab_aob         },
        { "scan_hub_tab_decrypt",     test_scan_hub_tab_decrypt     },
        { "scan_hub_tab_pointers",    test_scan_hub_tab_pointers    },
        { "scan_hub_tab_snapshots",   test_scan_hub_tab_snapshots   },
        { "scan_hub_tab_integrity",   test_scan_hub_tab_integrity   },

        { "memscan_shutdown",         test_memscan_shutdown         },
    };

    int total = static_cast<int>(sizeof(tests) / sizeof(tests[0]));
    for (int i = 0; i < total; ++i) {
        if (cancelled && cancelled()) {
            int remaining = total - i;
            skipped.fetch_add(remaining);
            log_msg(hf, "scanner", "cancelled -- skipping %d remaining tests", remaining);
            break;
        }

        log_msg(hf, "scanner", "[%d/%d] %s", i + 1, total, tests[i].name);
        __try {
            tests[i].fn(hf, passed, failed);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_msg(hf, "scanner", "FAIL -- %s threw SEH exception 0x%08X",
                tests[i].name, GetExceptionCode());
            failed.fetch_add(1);
        }
    }

    memory_scanner::reset_scan();
    pointer_scanner::cancel_all();
    pointer_scanner::clear_results();
    pointer_scanner::clear_map();
    snapshot_diff::clear_snapshots();
    unplant_anchor(hf);

    log_msg(hf, "scanner", "=== END scanner tests ===");
}

}
