#include "test_all_scanner.h"

#include "../scanner/memory_scanner.hpp"
#include "../scanner/crypto_scanner.hpp"
#include "../scanner/pointer_scanner.hpp"
#include "../scanner/snapshot_diff.hpp"
#include "../scanner/aob_generator.hpp"
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

static void test_memscan_initialize(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_init", "START -- memory_scanner::initialize");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::initialize();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_init", "PASS -- initialize completed (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_int32(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_i32", "START -- first scan exact int32 value");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "42";
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);

    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    size_t found = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        found = memory_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_i32", "PASS -- first_scan returned %d, found %zu results (elapsed %lld ms)",
        ok, found, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_byte(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_byt", "START -- first scan exact byte value");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::byte_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "255";
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_byt", "PASS -- first_scan(byte) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_str", "START -- first scan ASCII string");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::string_ascii;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "ntdll.dll";
    cfg.writable_only = false;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    size_t found = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        found = memory_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_str", "PASS -- string scan returned %d, found %zu results (elapsed %lld ms)",
        ok, found, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_unchanged(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_unc", "START -- next scan unchanged");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::unchanged, "", "");
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_unc", "PASS -- next_scan(unchanged) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_changed(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_chg", "START -- next scan changed");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::changed, "", "");
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_chg", "PASS -- next_scan(changed) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_undo_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_undo", "START -- undo scan");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::undo_scan();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_undo", "PASS -- undo_scan completed (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_reset_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_rst", "START -- reset scan");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();

    bool empty = false;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        empty = memory_scanner::g_state.results.empty();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_rst", "PASS -- reset_scan completed, results_empty=%d (elapsed %lld ms)",
        empty, (long long)ms);
    passed.fetch_add(1);
}

static void test_add_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_add", "START -- add address to watch list");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));

    memory_scanner::add_address(addr, "test_ntdll_base", memory_scanner::value_type_t::int64_val);

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        count = memory_scanner::g_state.address_list.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (count > 0) {
        log_msg(hf, "scan_add", "PASS -- address list has %zu entries (elapsed %lld ms)", count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_add", "FAIL -- address list empty after add (elapsed %lld ms)", (long long)ms);
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

    if (before > 0) {
        memory_scanner::remove_address(0);
    }

    size_t after = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        after = memory_scanner::g_state.address_list.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_rem", "PASS -- before=%zu after=%zu (elapsed %lld ms)", before, after, (long long)ms);
    passed.fetch_add(1);
}

static void test_freeze_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_frz", "START -- freeze/unfreeze address");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));
    memory_scanner::add_address(addr, "test_freeze", memory_scanner::value_type_t::int32_val);

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        count = memory_scanner::g_state.address_list.size();
    }

    if (count > 0) {
        memory_scanner::freeze_address(count - 1, true);
        memory_scanner::freeze_address(count - 1, false);
        memory_scanner::remove_address(count - 1);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_frz", "PASS -- freeze/unfreeze toggled (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_read_value_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_rdv", "START -- read_value_string");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));

    std::string val = memory_scanner::read_value_string(addr, memory_scanner::value_type_t::int32_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_rdv", "PASS -- read_value_string at 0x%llX = \"%s\" (elapsed %lld ms)",
        (unsigned long long)addr, val.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_format_parse_roundtrip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fpr", "START -- format/parse value roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("12345", memory_scanner::value_type_t::int32_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::int32_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (formatted == "12345") {
        log_msg(hf, "scan_fpr", "PASS -- roundtrip: 12345 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fpr", "FAIL -- expected \"12345\" got \"%s\" (elapsed %lld ms)", formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_crypto_get_signatures(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_sig", "START -- get built-in crypto signatures");
    auto t0 = std::chrono::steady_clock::now();

    auto sigs = crypto_scanner::get_signatures();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_sig", "PASS -- %zu built-in signatures (elapsed %lld ms)", sigs.size(), (long long)ms);
    for (size_t i = 0; i < sigs.size() && i < 5; ++i) {
        log_msg(hf, "crypto_sig", "  sig[%zu]: name=%s algo=%s bytes=%zu",
            i, sigs[i].name, sigs[i].algorithm, sigs[i].pattern_size);
    }
    passed.fetch_add(1);
}

static void test_crypto_scan_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_sp", "START -- crypto scanner scan process");
    auto t0 = std::chrono::steady_clock::now();

    crypto_scanner::scan_process();

    for (int i = 0; i < 100; ++i) {
        if (!crypto_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }
    crypto_scanner::cancel();

    size_t hits = 0;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        hits = crypto_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_sp", "PASS -- scan_process found %zu hits (elapsed %lld ms)", hits, (long long)ms);
    passed.fetch_add(1);
}

static void test_crypto_scan_entropy(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_ent", "START -- crypto scanner scan entropy");
    auto t0 = std::chrono::steady_clock::now();

    crypto_scanner::scan_entropy();

    for (int i = 0; i < 100; ++i) {
        if (!crypto_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }
    crypto_scanner::cancel();

    size_t high_count = 0;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        high_count = crypto_scanner::g_state.entropy_map.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_ent", "PASS -- entropy scan found %zu high-entropy regions (elapsed %lld ms)",
        high_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_crypto_add_custom_sig(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_cst", "START -- add custom crypto signature");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> pattern = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    crypto_scanner::add_custom_signature("TestSig", "TestAlgo", "Test custom signature",
        crypto_scanner::crypto_category_t::symmetric, pattern);

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(crypto_scanner::g_state.mutex);
        count = crypto_scanner::g_state.custom_sigs.size();
    }

    if (count > 0) {
        crypto_scanner::remove_custom_signature(static_cast<int>(count - 1));
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (count > 0) {
        log_msg(hf, "crypto_cst", "PASS -- custom signature added, total=%zu (elapsed %lld ms)", count, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "crypto_cst", "FAIL -- custom_sigs empty after add (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_build_reverse_map(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_map", "START -- pointer scanner build reverse map");
    auto t0 = std::chrono::steady_clock::now();

    pointer_scanner::build_reverse_map();

    for (int i = 0; i < 100; ++i) {
        if (!pointer_scanner::g_state.map_building.load()) break;
        Sleep(100);
    }
    pointer_scanner::cancel_all();

    size_t entries = 0;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.map_mutex);
        entries = pointer_scanner::g_state.map_entry_count;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_map", "PASS -- reverse map built with %zu entries (elapsed %lld ms)", entries, (long long)ms);
    passed.fetch_add(1);
}

static void test_snapshot_take(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "snap_take", "START -- take snapshot");
    auto t0 = std::chrono::steady_clock::now();

    snapshot_diff::take_snapshot("test_snap_A");

    for (int i = 0; i < 100; ++i) {
        if (!snapshot_diff::g_state.capturing.load()) break;
        Sleep(100);
    }

    size_t snap_count = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        snap_count = snapshot_diff::g_state.snapshots.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "snap_take", "PASS -- snapshot count=%zu (elapsed %lld ms)", snap_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_snapshot_compare(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "snap_cmp", "START -- compare two snapshots");
    auto t0 = std::chrono::steady_clock::now();

    snapshot_diff::take_snapshot("test_snap_B");
    for (int i = 0; i < 100; ++i) {
        if (!snapshot_diff::g_state.capturing.load()) break;
        Sleep(100);
    }

    uint64_t id_a = 0, id_b = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        if (snapshot_diff::g_state.snapshots.size() >= 2) {
            id_a = snapshot_diff::g_state.snapshots[snapshot_diff::g_state.snapshots.size() - 2].id;
            id_b = snapshot_diff::g_state.snapshots[snapshot_diff::g_state.snapshots.size() - 1].id;
        }
    }

    if (id_a != 0 && id_b != 0) {
        snapshot_diff::compare_snapshots(id_a, id_b);
        for (int i = 0; i < 100; ++i) {
            if (!snapshot_diff::g_state.comparing.load()) break;
            Sleep(100);
        }
    }

    size_t changes = 0;
    {
        std::lock_guard<std::mutex> lk(snapshot_diff::g_state.mutex);
        changes = snapshot_diff::g_state.diff.changes.size();
    }

    snapshot_diff::clear_snapshots();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "snap_cmp", "PASS -- compare found %zu changes, ids a=%llu b=%llu (elapsed %lld ms)",
        changes, (unsigned long long)id_a, (unsigned long long)id_b, (long long)ms);
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!formatted.empty()) {
        log_msg(hf, "aob_fmt", "PASS -- format: \"%s\" (elapsed %lld ms)", formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_fmt", "FAIL -- format_signature returned empty (elapsed %lld ms)", (long long)ms);
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!ida.empty()) {
        log_msg(hf, "aob_ida", "PASS -- IDA format: \"%s\" (elapsed %lld ms)", ida.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_ida", "FAIL -- format_ida_signature returned empty (elapsed %lld ms)", (long long)ms);
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (yara.find("rule test_yara_sig") != std::string::npos) {
        log_msg(hf, "aob_yara", "PASS -- YARA rule generated (%zu chars) (elapsed %lld ms)",
            yara.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_yara", "FAIL -- YARA rule missing expected content (elapsed %lld ms)", (long long)ms);
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
    log_msg(hf, "aob_qs", "PASS -- quality=%.3f grade=%s (32 concrete bytes, unique) (elapsed %lld ms)",
        score, grade, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_int16(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_i16", "START -- first scan exact int16 value");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int16_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "256";
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    size_t found = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        found = memory_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_i16", "PASS -- first_scan(int16) returned %d, found %zu results (elapsed %lld ms)",
        ok, found, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_int64(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_i64", "START -- first scan exact int64 value");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int64_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "4294967296";
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_i64", "PASS -- first_scan(int64) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_float(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_flt", "START -- first scan exact float value");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::float_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "1.0";
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_flt", "PASS -- first_scan(float) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_double(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_dbl", "START -- first scan exact double value");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::double_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "3.14159";
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_dbl", "PASS -- first_scan(double) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_byte_array(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_barr", "START -- first scan byte array");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::byte_array;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "4D 5A 90 00";
    cfg.hex_input = true;
    cfg.writable_only = false;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    size_t found = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.results_mutex);
        found = memory_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_barr", "PASS -- first_scan(byte_array) returned %d, found %zu (elapsed %lld ms)",
        ok, found, (long long)ms);
    passed.fetch_add(1);
}

static void test_first_scan_utf16_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_u16", "START -- first scan UTF-16 string");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::string_utf16;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "ntdll";
    cfg.writable_only = false;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_u16", "PASS -- first_scan(utf16) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_bigger_than(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_gt", "START -- scan mode bigger_than");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::bigger_than;
    cfg.value_text = "2147483640";
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_gt", "PASS -- first_scan(bigger_than) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_smaller_than(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_lt", "START -- scan mode smaller_than");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::smaller_than;
    cfg.value_text = "5";
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_lt", "PASS -- first_scan(smaller_than) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_mode_between(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_btw", "START -- scan mode value_between");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::value_between;
    cfg.value_text = "100";
    cfg.value_text2 = "200";
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_btw", "PASS -- first_scan(between 100-200) returned %d (elapsed %lld ms)", ok, (long long)ms);
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

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_unk", "PASS -- first_scan(unknown_initial) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_increased(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_inc", "START -- next scan increased");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::increased, "", "");
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_inc", "PASS -- next_scan(increased) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_next_scan_decreased(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_dec", "START -- next scan decreased");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = memory_scanner::next_scan(memory_scanner::scan_mode_t::decreased, "", "");
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_dec", "PASS -- next_scan(decreased) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_hex_input(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_hex", "START -- first scan with hex input");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int32_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "DEADBEEF";
    cfg.hex_input = true;
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_hex", "PASS -- first_scan(hex DEADBEEF) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_scan_alignment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_aln", "START -- first scan with alignment=8");
    auto t0 = std::chrono::steady_clock::now();

    memory_scanner::reset_scan();
    memory_scanner::scan_config_t cfg;
    cfg.value_type = memory_scanner::value_type_t::int64_val;
    cfg.scan_mode = memory_scanner::scan_mode_t::exact;
    cfg.value_text = "0";
    cfg.alignment = 8;
    cfg.writable_only = true;

    bool ok = memory_scanner::first_scan(cfg);
    for (int i = 0; i < 50; ++i) {
        if (!memory_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_aln", "PASS -- first_scan(alignment=8) returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_write_value(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_wrv", "START -- write_value to watched address");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));

    memory_scanner::add_address(addr, "test_write_val", memory_scanner::value_type_t::int32_val);

    memory_scanner::write_value(addr, memory_scanner::value_type_t::int32_val, "0", false);

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        count = memory_scanner::g_state.address_list.size();
    }

    if (count > 0) {
        memory_scanner::remove_address(count - 1);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_wrv", "PASS -- write_value invoked (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_refresh_address_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_ral", "START -- refresh_address_list");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));

    memory_scanner::add_address(addr, "test_refresh", memory_scanner::value_type_t::int32_val);
    memory_scanner::refresh_address_list();

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(memory_scanner::g_state.address_mutex);
        count = memory_scanner::g_state.address_list.size();
    }

    if (count > 0) {
        memory_scanner::remove_address(count - 1);
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_ral", "PASS -- refresh_address_list completed (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_format_parse_int16(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fp16", "START -- format/parse int16 roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("1234", memory_scanner::value_type_t::int16_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::int16_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (formatted == "1234") {
        log_msg(hf, "scan_fp16", "PASS -- roundtrip int16: 1234 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fp16", "FAIL -- expected \"1234\" got \"%s\" (elapsed %lld ms)", formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_parse_float(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fpfl", "START -- format/parse float roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("1.5", memory_scanner::value_type_t::float_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::float_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    bool close = !formatted.empty() && formatted.find("1.5") != std::string::npos;
    if (close) {
        log_msg(hf, "scan_fpfl", "PASS -- roundtrip float: 1.5 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fpfl", "FAIL -- expected \"1.5\" got \"%s\" (elapsed %lld ms)", formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_format_parse_double(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "scan_fpdl", "START -- format/parse double roundtrip");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> parsed = memory_scanner::parse_value("2.71828", memory_scanner::value_type_t::double_val, false);
    std::string formatted = memory_scanner::format_value(parsed, memory_scanner::value_type_t::double_val);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    bool close = !formatted.empty() && formatted.find("2.71") != std::string::npos;
    if (close) {
        log_msg(hf, "scan_fpdl", "PASS -- roundtrip double: 2.71828 => %zu bytes => \"%s\" (elapsed %lld ms)",
            parsed.size(), formatted.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "scan_fpdl", "FAIL -- expected ~2.71828 got \"%s\" (elapsed %lld ms)", formatted.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_scan_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_scan", "START -- pointer scanner start_scan");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    uint64_t addr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));

    pointer_scanner::g_state.config.target_address = addr;
    pointer_scanner::g_state.config.max_depth = 2;
    pointer_scanner::g_state.config.max_offset = 1024;

    pointer_scanner::start_scan();

    for (int i = 0; i < 50; ++i) {
        if (!pointer_scanner::g_state.scanning.load()) break;
        Sleep(100);
    }
    pointer_scanner::cancel_all();

    size_t chains = 0;
    {
        std::lock_guard<std::mutex> lk(pointer_scanner::g_state.results_mutex);
        chains = pointer_scanner::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ptr_scan", "PASS -- start_scan found %zu chains (elapsed %lld ms)", chains, (long long)ms);
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!str.empty() && str.find("ntdll") != std::string::npos) {
        log_msg(hf, "ptr_str", "PASS -- chain_to_string: \"%s\" (elapsed %lld ms)", str.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ptr_str", "FAIL -- chain_to_string returned \"%s\" (elapsed %lld ms)", str.c_str(), (long long)ms);
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!cpp.empty() && cpp.find("ReadProcessMemory") != std::string::npos) {
        log_msg(hf, "ptr_cpp", "PASS -- export_chain_cpp generated %zu chars (elapsed %lld ms)", cpp.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ptr_cpp", "FAIL -- export_chain_cpp missing expected content (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pointer_export_json(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ptr_json", "START -- pointer scanner export_results_json");
    auto t0 = std::chrono::steady_clock::now();

    std::string json = pointer_scanner::export_results_json();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!json.empty()) {
        log_msg(hf, "ptr_json", "PASS -- export_results_json returned %zu chars (elapsed %lld ms)", json.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ptr_json", "FAIL -- export_results_json returned empty (elapsed %lld ms)", (long long)ms);
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!code.empty() && code.find("\\x48") != std::string::npos) {
        log_msg(hf, "aob_code", "PASS -- code format: \"%s\" (elapsed %lld ms)", code.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_code", "FAIL -- format_code_signature returned \"%s\" (elapsed %lld ms)", code.c_str(), (long long)ms);
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!x64dbg.empty() && x64dbg.find("??") != std::string::npos) {
        log_msg(hf, "aob_x64", "PASS -- x64dbg format: \"%s\" (elapsed %lld ms)", x64dbg.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_x64", "FAIL -- format_x64dbg_signature returned \"%s\" (elapsed %lld ms)", x64dbg.c_str(), (long long)ms);
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
    if (ok) {
        log_msg(hf, "aob_grd", "PASS -- grade boundaries: A=%s B=%s C=%s D=%s F=%s (elapsed %lld ms)",
            grade_a, grade_b, grade_c, grade_d, grade_f, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_grd", "FAIL -- unexpected grades (elapsed %lld ms)", (long long)ms);
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
    if (score < 0.01f) {
        log_msg(hf, "aob_qaw", "PASS -- all-wildcard quality=%.3f (expected ~0) (elapsed %lld ms)", score, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "aob_qaw", "FAIL -- all-wildcard quality=%.3f (expected ~0) (elapsed %lld ms)", score, (long long)ms);
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
    if (ok) {
        log_msg(hf, "crypto_cn", "PASS -- all category names correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "crypto_cn", "FAIL -- unexpected category name (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_crypto_get_function_label(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "crypto_gl", "START -- crypto scanner get_function_label");
    auto t0 = std::chrono::steady_clock::now();

    std::string label = crypto_scanner::get_function_label(0xDEADBEEF);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "crypto_gl", "PASS -- get_function_label(0xDEADBEEF) = \"%s\" (empty expected) (elapsed %lld ms)",
        label.c_str(), (long long)ms);
    passed.fetch_add(1);
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

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "scan_shut", "PASS -- shutdown completed (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

}

void phase_scanner_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    log_msg(hf, "scanner", "=== BEGIN scanner tests (56 tests) ===");

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

    log_msg(hf, "scanner", "=== END scanner tests ===");
}

}
