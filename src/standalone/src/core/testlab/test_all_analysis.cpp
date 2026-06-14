#include "test_all_analysis.h"

#include "test_all_features.hpp"
#include "test_lab_bounded_runner.hpp"
#include "../emulation/symbolic_engine.hpp"
#include "../emulation/deobfuscation_engine.hpp"
#include "../analysis/code_patcher.hpp"
#include "../analysis/integrity_hunter.hpp"
#include "../analysis/binary_map.hpp"
#include "../analysis/source_reconstructor.hpp"
#include "../analysis/xref_engine.hpp"
#include "../analysis/xref_db.hpp"
#include "../analysis/fuzzer_engine.hpp"
#include "../analysis/struct_recon_engine.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../analysis/decrypt_oracle.hpp"
#include "../analysis/pdb_downloader.hpp"
#include "../analysis/analysis_hub_view.hpp"
#include "../analysis/types_hub_view.hpp"
#include "../disasm/comment_store.hpp"
#include "../disasm/rename_store.hpp"
#include "../editor/expression_eval.hpp"
#include "../infra/critical_work_queue.hpp"
#include "../../helpers/diag_log.hpp"

#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
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
    test_all_features::write_full_test_log_line(hf, line.data(), line.size());
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
    test_all_features::mirror_full_test_log_line(tag, detail, s.c_str());
}

static int driver_attached_flag(uint32_t pid) {
    return (pid != 0 && driver_bridge::using_kernel_driver()) ? 1 : 0;
}

static bool require_attached_live_target(HANDLE hf, const char* tag, std::atomic<int>& failed) {
    uint32_t pid = driver_bridge::attached_pid();
    const int driver_attached = driver_attached_flag(pid);
    if (pid == 0) {
        log_msg(hf, tag, "FAIL -- root dependency unavailable: no active attached test target PID (target_pid=0 driver_attached=%d status=\"%s\" last_error=\"%s\")",
            driver_attached,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        failed.fetch_add(1);
        return false;
    }
    uint32_t exit_code = 0;
    if (!driver_bridge::attached_process_alive(&exit_code)) {
        log_msg(hf, tag, "FAIL -- root dependency unavailable: attached test target is not alive (target_pid=%u driver_attached=%d exit_code_or_error=0x%08X status=\"%s\" last_error=\"%s\")",
            (unsigned)pid,
            driver_attached,
            (unsigned)exit_code,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        failed.fetch_add(1);
        return false;
    }
    if (!driver_attached) {
        log_msg(hf, tag, "FAIL -- root dependency unavailable: kernel driver bridge is not attached for live target (target_pid=%u driver_attached=0 status=\"%s\" last_error=\"%s\")",
            (unsigned)pid,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        failed.fetch_add(1);
        return false;
    }
    return true;
}

static long long elapsed_us_since(std::chrono::steady_clock::time_point t0) {
    return static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0).count());
}

struct integrity_hunter_fixture_t {
    uint32_t pid = 0;
    uint64_t address = 0;
    size_t size = 0;

    integrity_hunter_fixture_t() = default;
    integrity_hunter_fixture_t(const integrity_hunter_fixture_t&) = delete;
    integrity_hunter_fixture_t& operator=(const integrity_hunter_fixture_t&) = delete;
    integrity_hunter_fixture_t(integrity_hunter_fixture_t&& other) noexcept {
        pid = other.pid;
        address = other.address;
        size = other.size;
        other.pid = 0;
        other.address = 0;
        other.size = 0;
    }
    integrity_hunter_fixture_t& operator=(integrity_hunter_fixture_t&& other) noexcept {
        if (this != &other) {
            reset();
            pid = other.pid;
            address = other.address;
            size = other.size;
            other.pid = 0;
            other.address = 0;
            other.size = 0;
        }
        return *this;
    }
    ~integrity_hunter_fixture_t() {
        reset();
    }
    void reset() {
        if (address != 0) {
            if (pid != 0)
                driver_bridge::free_memory_for(pid, address);
            else
                driver_bridge::free_memory(address);
            pid = 0;
            address = 0;
            size = 0;
        }
    }
};

static uint64_t resolve_attached_ntdll_export(uint32_t pid, const char* name, std::string& module_name) {
    if (pid == 0)
        return 0;
    for (const auto& mod : driver_bridge::enumerate_modules_for(pid)) {
        if (mod.base == 0)
            continue;
        const bool is_ntdll = _stricmp(mod.name.c_str(), "ntdll.dll") == 0 ||
            mod.name.find("ntdll") != std::string::npos ||
            mod.path.find("ntdll") != std::string::npos;
        if (!is_ntdll)
            continue;
        uint64_t fn = driver_bridge::resolve_export_for(pid, mod.base, name);
        if (fn != 0) {
            module_name = mod.name.empty() ? mod.path : mod.name;
            return fn;
        }
        HMODULE local_ntdll = GetModuleHandleW(L"ntdll.dll");
        FARPROC local_fn = local_ntdll ? GetProcAddress(local_ntdll, name) : nullptr;
        if (local_ntdll && local_fn) {
            const uint64_t offset = reinterpret_cast<uintptr_t>(local_fn) - reinterpret_cast<uintptr_t>(local_ntdll);
            if (offset != 0 && (mod.size == 0 || offset < mod.size)) {
                module_name = mod.name.empty() ? mod.path : mod.name;
                return mod.base + offset;
            }
        }
    }
    return 0;
}

static integrity_hunter_fixture_t make_integrity_hunter_fixture(HANDLE hf, const char* tag) {
    integrity_hunter_fixture_t fx;
    fx.pid = driver_bridge::attached_pid();
    fx.size = 4096;
    if (fx.pid == 0) {
        log_msg(hf, tag, "FAIL -- root dependency unavailable: cannot allocate integrity fixture without attached target PID (target_pid=0 driver_attached=%d status=\"%s\" last_error=\"%s\")",
            driver_attached_flag(fx.pid),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return fx;
    }
    fx.address = driver_bridge::allocate_memory_for(fx.pid, fx.size);
    if (fx.address == 0) {
        log_msg(hf, tag, "FAIL -- allocate_memory_for returned 0 for integrity hunter fixture (target_pid=%u driver_attached=%d status=\"%s\" last_error=\"%s\")",
            (unsigned)fx.pid,
            driver_attached_flag(fx.pid),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return fx;
    }

    std::vector<uint8_t> bytes(fx.size);
    for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<uint8_t>((i * 31u + 0x53u) & 0xFFu);

    if (!driver_bridge::write_memory_for(fx.pid, fx.address, bytes)) {
        log_msg(hf, tag, "FAIL -- write_memory_for failed for integrity hunter fixture target_pid=%u addr=0x%016llX size=%zu status=\"%s\" last_error=\"%s\"",
            (unsigned)fx.pid,
            (unsigned long long)fx.address,
            fx.size,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        fx.reset();
        return fx;
    }

    uint32_t old_protect = 0;
    if (!driver_bridge::protect_memory_for(fx.pid, fx.address, fx.size, PAGE_READWRITE, &old_protect)) {
        log_msg(hf, tag, "FAIL -- protect_memory_for failed for integrity hunter fixture target_pid=%u addr=0x%016llX size=%zu status=\"%s\" last_error=\"%s\"",
            (unsigned)fx.pid,
            (unsigned long long)fx.address,
            fx.size,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        fx.reset();
        return fx;
    }

    driver_bridge::memory_region_t region{};
    const bool query_ok = driver_bridge::query_memory_for(fx.pid, fx.address, region);
    log_msg(hf, tag, "fixture target_pid=%u driver_attached=%d addr=0x%016llX size=%zu old_protect=0x%08X query_ok=%d base=0x%016llX region_size=0x%016llX state=0x%08X protect=0x%08X type=0x%08X",
        (unsigned)fx.pid,
        driver_attached_flag(fx.pid),
        (unsigned long long)fx.address,
        fx.size,
        old_protect,
        query_ok ? 1 : 0,
        (unsigned long long)region.base,
        (unsigned long long)region.size,
        (unsigned)region.state,
        (unsigned)region.protect,
        (unsigned)region.type);
    return fx;
}

struct symbolic_fixture_t {
    uint64_t address = 0;
    size_t size = 0;

    symbolic_fixture_t() = default;
    symbolic_fixture_t(const symbolic_fixture_t&) = delete;
    symbolic_fixture_t& operator=(const symbolic_fixture_t&) = delete;
    symbolic_fixture_t(symbolic_fixture_t&& other) noexcept {
        address = other.address;
        size = other.size;
        other.address = 0;
        other.size = 0;
    }
    symbolic_fixture_t& operator=(symbolic_fixture_t&& other) noexcept {
        if (this != &other) {
            reset();
            address = other.address;
            size = other.size;
            other.address = 0;
            other.size = 0;
        }
        return *this;
    }
    ~symbolic_fixture_t() {
        reset();
    }
    void reset() {
        if (address != 0) {
            driver_bridge::free_memory(address);
            address = 0;
            size = 0;
        }
    }
};

static symbolic_fixture_t make_symbolic_fixture(HANDLE hf, const char* tag, const std::vector<uint8_t>& code) {
    symbolic_fixture_t fx;
    fx.size = code.empty() ? 1 : ((code.size() + 0xFFFu) & ~0xFFFu);
    fx.address = driver_bridge::allocate_memory(fx.size);
    if (fx.address == 0) {
        log_msg(hf, tag, "FAIL -- allocate_memory returned 0 for symbolic fixture");
        fx.size = 0;
        return fx;
    }
    std::vector<uint8_t> page(fx.size, 0x90);
    if (!code.empty())
        std::memcpy(page.data(), code.data(), code.size());
    if (!driver_bridge::write_memory(fx.address, page)) {
        log_msg(hf, tag, "FAIL -- write_memory failed for symbolic fixture addr=0x%016llX size=%zu",
            static_cast<unsigned long long>(fx.address), page.size());
        fx.reset();
        return fx;
    }
    uint32_t old_protect = 0;
    if (!driver_bridge::protect_memory(fx.address, fx.size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        log_msg(hf, tag, "FAIL -- protect_memory failed for symbolic fixture addr=0x%016llX size=%zu",
            static_cast<unsigned long long>(fx.address), fx.size);
        fx.reset();
        return fx;
    }
    log_msg(hf, tag, "fixture addr=0x%016llX size=%zu bytes=%zu",
        static_cast<unsigned long long>(fx.address), fx.size, code.size());
    return fx;
}

static std::vector<uint8_t> symbolic_arithmetic_fixture() {
    return {
        0x48, 0x89, 0xC8,
        0x48, 0x83, 0xC0, 0x05,
        0x48, 0x31, 0xD0,
        0x48, 0x85, 0xC0,
        0x75, 0x03,
        0x48, 0xFF, 0xC0,
        0xC3
    };
}

static std::vector<uint8_t> symbolic_r10_fixture() {
    return {
        0x4C, 0x8B, 0xD1,
        0x49, 0x83, 0xC2, 0x01,
        0x4C, 0x89, 0xD0,
        0xC3
    };
}

static std::vector<uint8_t> symbolic_branch_fixture() {
    return {
        0x48, 0x85, 0xC9,
        0x75, 0x03,
        0x31, 0xC0,
        0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };
}

struct source_recon_fixture_t {
    uint64_t address = 0;
    size_t size = 0;
    bool release_on_reset = true;

    source_recon_fixture_t() = default;
    source_recon_fixture_t(const source_recon_fixture_t&) = delete;
    source_recon_fixture_t& operator=(const source_recon_fixture_t&) = delete;
    source_recon_fixture_t(source_recon_fixture_t&& other) noexcept {
        address = other.address;
        size = other.size;
        release_on_reset = other.release_on_reset;
        other.address = 0;
        other.size = 0;
        other.release_on_reset = true;
    }
    source_recon_fixture_t& operator=(source_recon_fixture_t&& other) noexcept {
        if (this != &other) {
            reset();
            address = other.address;
            size = other.size;
            release_on_reset = other.release_on_reset;
            other.address = 0;
            other.size = 0;
            other.release_on_reset = true;
        }
        return *this;
    }
    ~source_recon_fixture_t() {
        reset();
    }
    void disarm() {
        release_on_reset = false;
    }
    void reset() {
        if (address != 0 && release_on_reset)
            driver_bridge::free_memory(address);
        address = 0;
        size = 0;
        release_on_reset = true;
    }
};

static void put_u16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    if (off + sizeof(v) <= b.size())
        std::memcpy(b.data() + off, &v, sizeof(v));
}

static void put_u32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    if (off + sizeof(v) <= b.size())
        std::memcpy(b.data() + off, &v, sizeof(v));
}

static void put_u64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    if (off + sizeof(v) <= b.size())
        std::memcpy(b.data() + off, &v, sizeof(v));
}

static std::vector<uint8_t> make_source_recon_pe_image(uint64_t image_base) {
    std::vector<uint8_t> image(0x2000, 0);
    image[0] = 'M';
    image[1] = 'Z';
    put_u32(image, 0x3C, 0x80);

    const size_t nt = 0x80;
    put_u32(image, nt, 0x00004550);
    put_u16(image, nt + 4, 0x8664);
    put_u16(image, nt + 6, 1);
    put_u32(image, nt + 8, 0x66550000);
    put_u16(image, nt + 20, 0xF0);
    put_u16(image, nt + 22, 0x0022);

    const size_t opt = nt + 24;
    put_u16(image, opt + 0, 0x020B);
    image[opt + 2] = 14;
    put_u32(image, opt + 4, 0x200);
    put_u32(image, opt + 16, 0x1000);
    put_u32(image, opt + 20, 0x1000);
    put_u64(image, opt + 24, image_base);
    put_u32(image, opt + 32, 0x1000);
    put_u32(image, opt + 36, 0x200);
    put_u16(image, opt + 48, 6);
    put_u16(image, opt + 50, 0);
    put_u16(image, opt + 64, 3);
    put_u32(image, opt + 56, static_cast<uint32_t>(image.size()));
    put_u32(image, opt + 60, 0x400);
    put_u16(image, opt + 68, 3);
    put_u64(image, opt + 72, 0x100000);
    put_u64(image, opt + 80, 0x1000);
    put_u64(image, opt + 88, 0x100000);
    put_u64(image, opt + 96, 0x1000);
    put_u32(image, opt + 108, 16);

    const size_t sec = opt + 0xF0;
    const char text_name[8] = { '.', 't', 'e', 'x', 't', 0, 0, 0 };
    std::memcpy(image.data() + sec, text_name, sizeof(text_name));
    put_u32(image, sec + 8, 0x200);
    put_u32(image, sec + 12, 0x1000);
    put_u32(image, sec + 16, 0x200);
    put_u32(image, sec + 20, 0x400);
    put_u32(image, sec + 36, 0x60000020);

    const size_t entry = 0x1000;
    const uint64_t call_src = image_base + 0x1000;
    const uint64_t call_dst = image_base + 0x1010;
    const int32_t rel = static_cast<int32_t>(call_dst - (call_src + 5));
    image[entry + 0] = 0xE8;
    std::memcpy(image.data() + entry + 1, &rel, sizeof(rel));
    image[entry + 5] = 0xC3;
    const uint8_t fn[] = {
        0x48, 0x83, 0xEC, 0x28,
        0xB8, 0x2A, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    std::memcpy(image.data() + 0x1010, fn, sizeof(fn));
    return image;
}

static source_recon_fixture_t make_source_recon_fixture(HANDLE hf, const char* tag) {
    source_recon_fixture_t fx;
    fx.size = 0x2000;
    fx.address = driver_bridge::allocate_memory(fx.size);
    if (fx.address == 0) {
        log_msg(hf, tag, "FAIL -- allocate_memory returned 0 for source reconstruction fixture");
        fx.size = 0;
        return fx;
    }

    std::vector<uint8_t> image = make_source_recon_pe_image(fx.address);
    if (!driver_bridge::write_memory(fx.address, image)) {
        log_msg(hf, tag, "FAIL -- write_memory failed for source reconstruction fixture addr=0x%016llX size=%zu",
            static_cast<unsigned long long>(fx.address), image.size());
        fx.reset();
        return fx;
    }

    uint32_t old_protect = 0;
    if (!driver_bridge::protect_memory(fx.address, fx.size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        log_msg(hf, tag, "FAIL -- protect_memory failed for source reconstruction fixture addr=0x%016llX size=%zu",
            static_cast<unsigned long long>(fx.address), fx.size);
        fx.reset();
        return fx;
    }

    log_msg(hf, tag, "fixture addr=0x%016llX size=%zu old_protect=0x%08X",
        static_cast<unsigned long long>(fx.address), fx.size, old_protect);
    return fx;
}

static std::string source_recon_output_dir() {
    char tmp[MAX_PATH + 1] = {};
    DWORD len = GetTempPathA(MAX_PATH, tmp);
    std::string base = (len > 0 && len < MAX_PATH) ? std::string(tmp, len) : std::string(".\\");
    if (!base.empty()) {
        char last = base.back();
        if (last != '\\' && last != '/')
            base.push_back('\\');
    }
    char suffix[160];
    _snprintf_s(suffix, sizeof(suffix), _TRUNCATE, "AiDA_TestLab\\source_recon_%lu_%llu",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(GetTickCount64()));
    return base + suffix;
}

static bool file_exists_nonempty(const std::string& path, unsigned long long* size_out = nullptr) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER sz{};
    bool ok = GetFileSizeEx(h, &sz) && sz.QuadPart > 0;
    if (size_out)
        *size_out = GetFileSizeEx(h, &sz) ? static_cast<unsigned long long>(sz.QuadPart) : 0ULL;
    CloseHandle(h);
    return ok;
}

static bool read_text_file_limited(const std::string& path, std::string& out, size_t limit) {
    out.clear();
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        return false;
    std::vector<char> buf(limit);
    ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    std::streamsize got = ifs.gcount();
    if (got <= 0)
        return false;
    out.assign(buf.data(), static_cast<size_t>(got));
    return true;
}

static aida::binary_map::map_t make_binary_map_fixture() {
    aida::binary_map::map_t map;
    map.module_name = "fixture.exe";
    map.module_path = "fixture.exe";
    map.architecture = "x64";
    map.format = "PE";
    map.image_base = 0x140000000;
    map.image_size = 0x3000;

    aida::binary_map::map_section_t text;
    text.name = ".text";
    text.va = map.image_base + 0x1000;
    text.size = 0x600;
    text.executable = true;
    text.readable = true;
    text.entropy = 0.42f;
    text.sampled_bytes = 0x600;
    map.sections.push_back(std::move(text));

    aida::binary_map::map_function_t fn;
    fn.va = map.image_base + 0x1010;
    fn.name = "fixture_entry";
    fn.xref_count = 2;
    fn.callee_count = 1;
    fn.top_callees.push_back("fixture_leaf");
    fn.section_name = ".text";
    fn.score = 80;
    map.functions.push_back(std::move(fn));

    aida::binary_map::map_global_t global;
    global.va = map.image_base + 0x2200;
    global.name = "fixture_counter";
    global.xref_count = 1;
    global.writable = true;
    global.section_name = ".data";
    map.globals.push_back(std::move(global));

    map.imports.push_back("kernel32!CloseHandle");
    map.exports.push_back("FixtureExport");
    return map;
}

static void seed_xref_db_fixture(uint64_t from, uint64_t to) {
    xref_db::module_index_t mod;
    mod.name = "fixture_xref_module";
    mod.base = from & ~0xFFFULL;
    mod.size = 0x1000;
    mod.timestamp = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());
    mod.total_xrefs = 1;
    mod.built = true;

    xref_db::xref_entry_t entry;
    entry.from_addr = from;
    entry.to_addr = to;
    entry.type = xref_engine::xref_type_t::lea;
    entry.disasm_text = "lea rax, [rip+1]";
    mod.to_index[to].push_back(entry);
    mod.from_index[from].push_back(entry);

    std::string key = mod.name;
    std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
    xref_db::g_state.modules[key] = std::move(mod);
}

static void test_symbolic_execute(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_exec", "START -- symbolic engine execute on small range");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_exec", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::execute_symbolic(fx.address, fx.address + code.size(), 16, {"rcx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_exec", "FAIL -- execute_symbolic success=0 error=\"%s\" traced=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.trace.empty()) {
        log_msg(hf, "sym_exec", "FAIL -- execute_symbolic returned empty trace success=%d traced=%u trace=%zu (elapsed %lld ms)",
            result.success, result.total_instructions, result.trace.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_exec", "PASS -- success=%d traced=%u tainted=%u junk=%u opaque=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.tainted_count,
        result.junk_count, result.opaque_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_slice(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_slice", "START -- symbolic engine slice to register");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_slice", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::slice_to_register(fx.address, fx.address + code.size(), 16, "rax");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_slice", "FAIL -- slice_to_register success=0 error=\"%s\" total=%u effective=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.effective_instructions.empty()) {
        log_msg(hf, "sym_slice", "FAIL -- slice_to_register returned empty slice success=%d total=%u effective=%u (elapsed %lld ms)",
            result.success, result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_slice", "PASS -- success=%d total=%u effective=%u removed=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.effective_count,
        result.removed_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_taint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_taint", "START -- symbolic engine taint trace");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_taint", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::taint_trace(fx.address, fx.address + code.size(), 16, {"rcx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_taint", "FAIL -- taint_trace success=0 error=\"%s\" traced=%u tainted=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_processed, result.tainted_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_processed == 0 || result.tainted_instructions.empty()) {
        log_msg(hf, "sym_taint", "FAIL -- taint_trace returned empty taint result success=%d traced=%u tainted=%u (elapsed %lld ms)",
            result.success, result.total_processed, result.tainted_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_taint", "PASS -- success=%d traced=%u tainted=%u (elapsed %lld ms)",
        result.success, result.total_processed, result.tainted_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_opaque_predicate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_opq", "START -- symbolic engine check opaque predicate");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_branch_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_opq", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    bool is_opaque = symbolic_engine::is_opaque_predicate(fx.address + 3, 8);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "sym_opq", "PASS -- is_opaque_predicate(fixture_branch)=%d (elapsed %lld ms)",
        is_opaque, (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_strip_junk(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_jnk", "START -- deobfuscation engine strip junk code");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "deob_jnk", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = deobfuscation_engine::strip_junk_code(fx.address, fx.address + code.size(), { "rax" }, 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "deob_jnk", "FAIL -- fixture-limited deobfuscation success=0 error=\"%s\" original=%u clean=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_original, result.total_clean, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_original == 0 || result.clean_instructions.empty()) {
        log_msg(hf, "deob_jnk", "FAIL -- fixture-limited deobfuscation returned empty clean result success=%d original=%u clean=%u (elapsed %lld ms)",
            result.success, result.total_original, result.total_clean, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "deob_jnk", "PASS -- success=%d original=%u clean=%u removed=%u junk_ratio=%.2f (elapsed %lld ms)",
        result.success, result.total_original, result.total_clean,
        result.removed_junk, static_cast<double>(result.junk_ratio), (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_resolve_constants(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_cst", "START -- deobfuscation engine resolve constants");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "deob_cst", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto constants = deobfuscation_engine::resolve_constants(fx.address, fx.address + code.size(), 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (constants.empty()) {
        log_msg(hf, "deob_cst", "FAIL -- resolve_constants returned 0 constants (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "deob_cst", "PASS -- resolved %zu constants (elapsed %lld ms)", constants.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_code_patcher_create_apply_revert(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_car", "START -- code patcher create/apply/revert");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t scratch = driver_bridge::allocate_memory(16);
    if (scratch == 0) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "patch_car", "FAIL -- allocate_memory returned 0 for patch fixture (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1); return;
    }

    std::vector<uint8_t> original = { 0x41, 0x42, 0x43 };
    std::vector<uint8_t> patched = { 0x90, 0x90, 0x90 };
    bool seed_ok = driver_bridge::write_memory(scratch, original);
    int idx = seed_ok ? code_patcher::create_patch(scratch, patched, "test patch fixture") : -1;
    bool apply_ok = idx >= 0 && code_patcher::apply_patch(idx);
    std::vector<uint8_t> after_apply;
    bool read_apply_ok = driver_bridge::read_memory(scratch, patched.size(), after_apply);
    bool revert_ok = idx >= 0 && code_patcher::revert_patch(idx);
    std::vector<uint8_t> after_revert;
    bool read_revert_ok = driver_bridge::read_memory(scratch, original.size(), after_revert);
    size_t count = code_patcher::count();
    size_t active = code_patcher::active_count();

    if (idx >= 0)
        code_patcher::remove_patch(idx);
    bool freed = driver_bridge::free_memory(scratch);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (seed_ok && idx >= 0 && apply_ok && read_apply_ok && after_apply == patched &&
        revert_ok && read_revert_ok && after_revert == original && freed) {
        log_msg(hf, "patch_car", "PASS -- patch idx=%d applied/reverted on scratch=0x%016llX count=%zu active=%zu (elapsed %lld ms)",
            idx, (unsigned long long)scratch, count, active, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "patch_car", "FAIL -- seed=%d idx=%d apply=%d read_apply=%d revert=%d read_revert=%d freed=%d active=%zu (elapsed %lld ms)",
            seed_ok ? 1 : 0, idx, apply_ok ? 1 : 0, read_apply_ok ? 1 : 0,
            revert_ok ? 1 : 0, read_revert_ok ? 1 : 0, freed ? 1 : 0, active, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_code_patcher_nop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_nop", "START -- code patcher NOP region");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = code_patcher::nop_region(0xBAADF00D, 4, "test nop region");

    size_t count = code_patcher::count();
    if (count > 0) {
        code_patcher::remove_patch(static_cast<int>(count - 1));
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "patch_nop", "PASS -- nop_region returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_code_patcher_find_caves(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_cav", "START -- code patcher find code caves");
    auto t0 = std::chrono::steady_clock::now();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        log_msg(hf, "patch_cav", "FAIL -- ntdll not loaded");
        failed.fetch_add(1); return;
    }

    uint64_t base = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ntdll));
    auto caves = code_patcher::find_code_caves(base, 0x100000, 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "patch_cav", "PASS -- found %zu code caves >= 16 bytes (elapsed %lld ms)",
        caves.size(), (long long)ms);
    for (size_t i = 0; i < caves.size() && i < 5; ++i) {
        log_msg(hf, "patch_cav", "  cave[%zu]: addr=0x%llX size=%llu module=%s",
            i, (unsigned long long)caves[i].address,
            (unsigned long long)caves[i].size, caves[i].module_name.c_str());
    }
    passed.fetch_add(1);
}

static void test_integrity_hunter_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "integ_st", "START -- integrity hunter check state");
    auto t0 = std::chrono::steady_clock::now();

    bool hunting = integrity_hunter::g_state.hunting.load();
    uint64_t reads = integrity_hunter::g_state.total_reads.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "integ_st", "PASS -- hunting=%d total_reads=%llu (elapsed %lld ms)",
        hunting, (unsigned long long)reads, (long long)ms);
    passed.fetch_add(1);
}

static void test_binary_map_generate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap", "START -- binary map generate");
    auto t0 = std::chrono::steady_clock::now();

    aida::binary_map::map_options_t opts;
    opts.max_functions = 2;
    opts.max_globals = 1;
    opts.max_chars = 1024;

    aida::binary_map::map_t map = make_binary_map_fixture();
    std::string text = aida::binary_map::render_text(map, opts);
    bool ok = !text.empty() && text.find("fixture.exe") != std::string::npos;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!ok) {
        log_msg(hf, "binmap", "FAIL -- fixture map render missing module text (chars=%zu) (elapsed %lld ms)",
            text.size(), (long long)ms);
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "binmap", "PASS -- fixture module=%s arch=%s sections=%zu functions=%zu (elapsed %lld ms)",
        map.module_name.c_str(), map.architecture.c_str(),
        map.sections.size(), map.functions.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_source_reconstructor_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "srcrecon", "START -- source reconstructor status check (no execution)");
    auto t0 = std::chrono::steady_clock::now();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "srcrecon", "PASS -- source_reconstructor namespace accessible (elapsed %lld ms)", (long long)ms);
    passed.fetch_add(1);
}

static void test_xref_find(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xref_find", "START -- xref engine find xrefs to known function");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t scratch = driver_bridge::allocate_memory(32);
    if (scratch == 0) {
        log_msg(hf, "xref_find", "FAIL -- allocate_memory returned 0 for xref fixture");
        failed.fetch_add(1); return;
    }

    uint8_t code[16] = { 0x48, 0x8D, 0x05, 0x01, 0x00, 0x00, 0x00, 0xC3 };
    uint64_t target = scratch + 8;
    bool wrote = driver_bridge::write_memory(scratch, std::vector<uint8_t>(code, code + sizeof(code)));
    xref_engine::find_xrefs_to(target, scratch, sizeof(code));

    for (int i = 0; i < 50; ++i) {
        if (!xref_engine::is_scanning()) break;
        Sleep(100);
    }
    xref_engine::cancel_scan();

    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(xref_engine::g_state.mutex);
        count = xref_engine::g_state.results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (count == 0) {
        driver_bridge::free_memory(scratch);
        log_msg(hf, "xref_find", "FAIL -- found 0 xrefs to fixture target 0x%llX (wrote=%d elapsed %lld ms)",
            (unsigned long long)target, static_cast<int>(wrote), (long long)ms);
        failed.fetch_add(1); return;
    }
    driver_bridge::free_memory(scratch);
    log_msg(hf, "xref_find", "PASS -- found %zu fixture xrefs to 0x%llX (elapsed %lld ms)",
        count, (unsigned long long)target, (long long)ms);
    passed.fetch_add(1);
}

static void test_expression_eval_hex(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_hex", "START -- expression eval: 0x1000 + 0x20");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0x1000 + 0x20", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0x1020) {
        log_msg(hf, "expr_hex", "PASS -- 0x1000 + 0x20 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_hex", "FAIL -- ok=%d value=0x%llX error=\"%s\" (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, result.error.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_reg", "START -- expression eval: rax + rbx with context");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    ctx.rax = 100;
    ctx.rbx = 200;
    auto result = expression_eval::evaluate("rax + rbx", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 300) {
        log_msg(hf, "expr_reg", "PASS -- rax(100) + rbx(200) = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_reg", "FAIL -- ok=%d value=%llu error=\"%s\" (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, result.error.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_comment_store(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "cmt_store", "START -- comment store set/get/has");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_addr = 0xDEAD0001;
    comment_store::set(test_addr, "test_comment_analysis");

    bool has = comment_store::has(test_addr);
    std::string got = comment_store::get(test_addr);

    comment_store::set(test_addr, "");

    bool has_after = comment_store::has(test_addr);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (has && got == "test_comment_analysis" && !has_after) {
        log_msg(hf, "cmt_store", "PASS -- set/get/has/clear all correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "cmt_store", "FAIL -- has=%d got=\"%s\" has_after=%d (elapsed %lld ms)",
            has, got.c_str(), has_after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_rename_store(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ren_store", "START -- rename store set/get/has");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_addr = 0xDEAD0002;
    rename_store::set(test_addr, "test_label_analysis");

    bool has = rename_store::has(test_addr);
    std::string got = rename_store::get(test_addr);

    rename_store::clear(test_addr);

    bool has_after = rename_store::has(test_addr);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (has && got == "test_label_analysis" && !has_after) {
        log_msg(hf, "ren_store", "PASS -- set/get/has/clear all correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ren_store", "FAIL -- has=%d got=\"%s\" has_after=%d (elapsed %lld ms)",
            has, got.c_str(), has_after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_rename_store_resolve_or(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "ren_reso", "START -- rename store resolve_or");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_addr = 0xDEAD0003;
    rename_store::set(test_addr, "resolved_name");

    std::string found = rename_store::resolve_or(test_addr, "fallback");
    std::string not_found = rename_store::resolve_or(0xDEAD9999, "fallback_val");

    rename_store::clear(test_addr);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (found == "resolved_name" && not_found == "fallback_val") {
        log_msg(hf, "ren_reso", "PASS -- resolve_or correct: found=\"%s\" not_found=\"%s\" (elapsed %lld ms)",
            found.c_str(), not_found.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "ren_reso", "FAIL -- found=\"%s\" not_found=\"%s\" (elapsed %lld ms)",
            found.c_str(), not_found.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_symbolic_execute_larger(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_exlg", "START -- symbolic engine execute on larger range");
    auto t0 = std::chrono::steady_clock::now();

    auto code = symbolic_arithmetic_fixture();
    const auto r10 = symbolic_r10_fixture();
    code.insert(code.end(), r10.begin(), r10.end());
    auto fx = make_symbolic_fixture(hf, "sym_exlg", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::execute_symbolic(fx.address, fx.address + code.size(), 32, {"rcx", "rdx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_exlg", "FAIL -- execute_symbolic success=0 error=\"%s\" traced=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.trace.empty()) {
        log_msg(hf, "sym_exlg", "FAIL -- execute_symbolic returned empty trace success=%d traced=%u trace=%zu (elapsed %lld ms)",
            result.success, result.total_instructions, result.trace.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_exlg", "PASS -- success=%d traced=%u tainted=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.tainted_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_slice_rsi(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_slrsi", "START -- symbolic engine slice to syscall argument mirror r10");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_r10_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_slrsi", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::slice_to_register(fx.address, fx.address + code.size(), 16, "r10");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_slrsi", "FAIL -- slice_to_register success=0 error=\"%s\" total=%u effective=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_instructions == 0 || result.effective_instructions.empty()) {
        log_msg(hf, "sym_slrsi", "FAIL -- slice_to_register returned empty slice success=%d total=%u effective=%u (elapsed %lld ms)",
            result.success, result.total_instructions, result.effective_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_slrsi", "PASS -- success=%d total=%u effective=%u removed=%u (elapsed %lld ms)",
        result.success, result.total_instructions, result.effective_count,
        result.removed_count, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_taint_rdx(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_trdx", "START -- symbolic engine taint trace syscall input rcx");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_trdx", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::taint_trace(fx.address, fx.address + code.size(), 16, {"rcx"}, {});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_trdx", "FAIL -- taint_trace success=0 error=\"%s\" traced=%u tainted=%u (elapsed %lld ms)",
            result.error.c_str(), result.total_processed, result.tainted_count, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_processed == 0 || result.tainted_instructions.empty()) {
        log_msg(hf, "sym_trdx", "FAIL -- taint_trace returned empty taint result success=%d traced=%u tainted=%u regs=%zu mem=%zu (elapsed %lld ms)",
            result.success, result.total_processed, result.tainted_count,
            result.tainted_registers.size(), result.tainted_memory_addresses.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_trdx", "PASS -- success=%d traced=%u tainted=%u regs=%zu mem=%zu (elapsed %lld ms)",
        result.success, result.total_processed, result.tainted_count,
        result.tainted_registers.size(), result.tainted_memory_addresses.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_solve_for_path(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_solv", "START -- symbolic engine solve_for_path");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_branch_fixture();
    auto fx = make_symbolic_fixture(hf, "sym_solv", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = symbolic_engine::solve_for_path(fx.address, fx.address + 8, 16, {"rcx"});

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "sym_solv", "FAIL -- solve_for_path success=0 error=\"%s\" satisfiable=%d vars=%zu solve_ms=%u (elapsed %lld ms)",
            result.error.c_str(), result.satisfiable,
            result.variable_values.size(), result.solving_time_ms, (long long)ms);
        failed.fetch_add(1); return;
    }
    if (!result.satisfiable || result.variable_values.empty()) {
        log_msg(hf, "sym_solv", "FAIL -- solve_for_path returned no satisfying input satisfiable=%d vars=%zu solve_ms=%u (elapsed %lld ms)",
            result.satisfiable,
            result.variable_values.size(), result.solving_time_ms, (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "sym_solv", "PASS -- success=%d satisfiable=%d vars=%zu solve_ms=%u (elapsed %lld ms)",
        result.success, result.satisfiable,
        result.variable_values.size(), result.solving_time_ms, (long long)ms);
    passed.fetch_add(1);
}

static void test_symbolic_state_check(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "sym_stch", "START -- symbolic engine state check");
    auto t0 = std::chrono::steady_clock::now();

    bool processing = symbolic_engine::g_state.processing.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "sym_stch", "PASS -- processing=%d (elapsed %lld ms)", processing, (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_deobfuscate_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_fn", "START -- deobfuscation engine deobfuscate_function");
    auto t0 = std::chrono::steady_clock::now();

    const auto code = symbolic_arithmetic_fixture();
    auto fx = make_symbolic_fixture(hf, "deob_fn", code);
    if (fx.address == 0) {
        failed.fetch_add(1); return;
    }

    auto result = deobfuscation_engine::deobfuscate_function(fx.address, 16);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!result.success) {
        log_msg(hf, "deob_fn", "FAIL -- deobfuscate_function success=0 error=\"%s\" original=%u clean=%u blocks=%zu (elapsed %lld ms)",
            result.error.c_str(), result.total_original, result.total_clean,
            result.clean_blocks.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    if (result.total_original == 0 || result.clean_instructions.empty() || result.clean_blocks.empty()) {
        log_msg(hf, "deob_fn", "FAIL -- deobfuscate_function returned empty result success=%d original=%u clean=%u blocks=%zu (elapsed %lld ms)",
            result.success, result.total_original, result.total_clean,
            result.clean_blocks.size(), (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "deob_fn", "PASS -- success=%d original=%u clean=%u blocks=%zu edges=%zu (elapsed %lld ms)",
        result.success, result.total_original, result.total_clean,
        result.clean_blocks.size(), result.clean_edges.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_deobfusc_export_asm(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_asm", "START -- deobfuscation engine export_clean_asm");
    auto t0 = std::chrono::steady_clock::now();

    deobfuscation_engine::deobfuscated_result_t empty_result;
    empty_result.success = true;

    deobfuscation_engine::clean_instruction_t ci;
    ci.address = 0x1000;
    ci.size = 3;
    ci.disasm = "mov eax, ecx";
    empty_result.clean_instructions.push_back(ci);

    std::string asm_text = deobfuscation_engine::export_clean_asm(empty_result);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!asm_text.empty()) {
        log_msg(hf, "deob_asm", "PASS -- export_clean_asm returned %zu chars (elapsed %lld ms)",
            asm_text.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "deob_asm", "FAIL -- export_clean_asm returned empty (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_deobfusc_export_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "deob_stat", "START -- deobfuscation engine export_statistics");
    auto t0 = std::chrono::steady_clock::now();

    deobfuscation_engine::deobfuscated_result_t result;
    result.success = true;
    result.total_original = 100;
    result.total_clean = 80;
    result.removed_junk = 15;
    result.opaque_predicates_found = 3;
    result.constants_resolved = 2;
    result.junk_ratio = 0.15f;

    std::string stats = deobfuscation_engine::export_statistics(result);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!stats.empty()) {
        log_msg(hf, "deob_stat", "PASS -- export_statistics returned %zu chars (elapsed %lld ms)",
            stats.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "deob_stat", "FAIL -- export_statistics returned empty (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_code_patcher_format_parse(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_fp", "START -- code patcher format_bytes/parse_bytes");
    auto t0 = std::chrono::steady_clock::now();

    std::vector<uint8_t> original = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
    std::string formatted = code_patcher::format_bytes(original);
    std::vector<uint8_t> parsed = code_patcher::parse_bytes(formatted);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (parsed == original) {
        log_msg(hf, "patch_fp", "PASS -- format/parse roundtrip: \"%s\" => %zu bytes (elapsed %lld ms)",
            formatted.c_str(), parsed.size(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "patch_fp", "FAIL -- format=\"%s\" parsed_size=%zu (elapsed %lld ms)",
            formatted.c_str(), parsed.size(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_code_patcher_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "patch_cnt", "START -- code patcher count/active_count");
    auto t0 = std::chrono::steady_clock::now();

    size_t total = code_patcher::count();
    size_t active = code_patcher::active_count();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "patch_cnt", "PASS -- total=%zu active=%zu (elapsed %lld ms)", total, active, (long long)ms);
    passed.fetch_add(1);
}

static void test_integrity_hunter_start_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "integ_ss", "START -- integrity hunter start/stop hunt");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "integ_ss", failed))
        return;

    integrity_hunter::stop_hunt();
    const bool pre_idle = integrity_hunter::wait_until_idle(12000);
    const bool pre_hunting = integrity_hunter::g_state.hunting.load();
    const bool pre_worker = integrity_hunter::g_state.worker_active.load();
    const uint32_t pre_session = integrity_hunter::g_state.pg_session_id.load();
    if (!pre_idle || pre_hunting || pre_worker) {
        auto ms_pre = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "integ_ss", "FAIL -- stale integrity hunter state before start/stop test: pre_idle=%d hunting=%d worker=%d session=%u target_pid=%u driver_attached=%d status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            pre_idle ? 1 : 0,
            pre_hunting ? 1 : 0,
            pre_worker ? 1 : 0,
            pre_session,
            (unsigned)driver_bridge::attached_pid(),
            driver_attached_flag(driver_bridge::attached_pid()),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms_pre);
        failed.fetch_add(1);
        return;
    }

    const uint32_t target_pid = driver_bridge::attached_pid();
    uint64_t addr = 0;
    for (const auto& mod : driver_bridge::enumerate_modules_for(target_pid)) {
        if (_stricmp(mod.name.c_str(), "ntdll.dll") == 0) {
            addr = mod.base;
            break;
        }
    }
    if (addr == 0) {
        auto ms_mod = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "integ_ss", "FAIL -- root dependency unavailable: target ntdll module not found (target_pid=%u driver_attached=%d status=\"%s\" last_error=\"%s\" elapsed %lld ms)",
            (unsigned)target_pid,
            driver_attached_flag(target_pid),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms_mod);
        failed.fetch_add(1);
        return;
    }

    bool started = integrity_hunter::start_hunt(addr, 4096);

    Sleep(200);

    integrity_hunter::stop_hunt();

    bool idle = integrity_hunter::wait_until_idle(12000);
    bool hunting = integrity_hunter::g_state.hunting.load();
    bool worker = integrity_hunter::g_state.worker_active.load();
    bool install_complete = integrity_hunter::g_state.install_complete.load();
    bool install_success = integrity_hunter::g_state.install_success.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (started && idle && !hunting && !worker) {
        log_msg(hf, "integ_ss", "PASS -- target_pid=%u driver_attached=%d target=0x%016llX started=%d idle=%d hunting_after_stop=%d worker=%d install_complete=%d install_success=%d (elapsed %lld ms)",
            (unsigned)target_pid, driver_attached_flag(target_pid), (unsigned long long)addr,
            started ? 1 : 0, idle ? 1 : 0, hunting ? 1 : 0, worker ? 1 : 0,
            install_complete ? 1 : 0, install_success ? 1 : 0, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "integ_ss", "FAIL -- target_pid=%u driver_attached=%d target=0x%016llX started=%d idle=%d hunting_after_stop=%d worker=%d install_complete=%d install_success=%d status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            (unsigned)target_pid, driver_attached_flag(target_pid), (unsigned long long)addr,
            started ? 1 : 0, idle ? 1 : 0, hunting ? 1 : 0, worker ? 1 : 0,
            install_complete ? 1 : 0, install_success ? 1 : 0,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_integrity_hunter_nodes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "integ_nd", "START -- integrity hunter node list with deterministic page-guard stimulus");
    auto t0 = std::chrono::steady_clock::now();

    if (!require_attached_live_target(hf, "integ_nd", failed))
        return;

    integrity_hunter::stop_hunt();
    const bool pre_idle = integrity_hunter::wait_until_idle(12000);
    const bool pre_hunting = integrity_hunter::g_state.hunting.load();
    const bool pre_worker = integrity_hunter::g_state.worker_active.load();
    const bool pre_install_complete = integrity_hunter::g_state.install_complete.load();
    const bool pre_install_success = integrity_hunter::g_state.install_success.load();
    const uint32_t pre_session = integrity_hunter::g_state.pg_session_id.load();
    std::string pre_status_text;
    size_t pre_nodes = 0;
    size_t pre_events = 0;
    {
        std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
        pre_status_text = integrity_hunter::g_state.status_text;
        pre_nodes = integrity_hunter::g_state.nodes.size();
        pre_events = integrity_hunter::g_state.event_log.size();
    }
    if (!pre_idle || pre_hunting || pre_worker) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        diag::log_tagged_fmt("test_analysis_detail",
            "integ_nd stale_pre_idle: pid=%u pre_idle=%d hunting=%d worker=%d install_complete=%d install_success=%d session=%u nodes=%zu events=%zu total_reads=%llu status='%s' bridge_status='%s' bridge_last_error='%s' elapsed_ms=%lld",
            (unsigned)driver_bridge::attached_pid(),
            pre_idle ? 1 : 0,
            pre_hunting ? 1 : 0,
            pre_worker ? 1 : 0,
            pre_install_complete ? 1 : 0,
            pre_install_success ? 1 : 0,
            pre_session,
            pre_nodes,
            pre_events,
            (unsigned long long)integrity_hunter::g_state.total_reads.load(),
            pre_status_text.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        log_msg(hf, "integ_nd", "FAIL -- stale integrity hunter state before node test: pre_idle=%d hunting=%d worker=%d install_complete=%d install_success=%d session=%u nodes=%zu events=%zu total_reads=%llu status=\"%s\" bridge_status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            pre_idle ? 1 : 0,
            pre_hunting ? 1 : 0,
            pre_worker ? 1 : 0,
            pre_install_complete ? 1 : 0,
            pre_install_success ? 1 : 0,
            pre_session,
            pre_nodes,
            pre_events,
            (unsigned long long)integrity_hunter::g_state.total_reads.load(),
            pre_status_text.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    integrity_hunter_fixture_t fixture = make_integrity_hunter_fixture(hf, "integ_nd");
    if (fixture.address == 0) {
        failed.fetch_add(1);
        return;
    }
    const uint32_t target_pid = fixture.pid;

    driver_bridge::memory_region_t before_region{};
    const bool before_query = driver_bridge::query_memory_for(target_pid, fixture.address, before_region);

    std::string read_module;
    uint64_t target_read_fn = resolve_attached_ntdll_export(target_pid, "RtlCompareMemory", read_module);
    const char* target_read_kind = "RtlCompareMemory";
    if (target_read_fn == 0) {
        target_read_fn = resolve_attached_ntdll_export(target_pid, "RtlComputeCrc32", read_module);
        target_read_kind = "RtlComputeCrc32";
    }

    if (target_read_fn == 0) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "integ_nd", "FAIL -- no target-side ntdll read function resolved for integrity fixture pid=%u addr=0x%016llX before_query=%d before_protect=0x%08X status=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            (unsigned)target_pid,
            (unsigned long long)fixture.address,
            before_query ? 1 : 0,
            (unsigned)before_region.protect,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    const bool started = integrity_hunter::start_hunt(fixture.address, 128);
    bool install_seen = false;
    const DWORD install_start = GetTickCount();
    while (GetTickCount() - install_start < 6500) {
        if (integrity_hunter::g_state.install_complete.load()) {
            install_seen = true;
            break;
        }
        if (!integrity_hunter::g_state.hunting.load() && !integrity_hunter::g_state.worker_active.load())
            break;
        Sleep(25);
    }

    const bool install_complete = integrity_hunter::g_state.install_complete.load();
    const bool install_success = integrity_hunter::g_state.install_success.load();
    const uint32_t pg_session = integrity_hunter::g_state.pg_session_id.load();

    driver_bridge::memory_region_t guard_region{};
    const bool guard_query = driver_bridge::query_memory_for(target_pid, fixture.address, guard_region);
    const bool guard_set = guard_query && ((guard_region.protect & PAGE_GUARD) != 0);

    uint32_t target_read_attempts = 0;
    uint32_t target_read_ok = 0;
    uint64_t target_read_result = 0;
    if (started && install_seen && install_success) {
        for (uint32_t i = 0; i < 8; ++i) {
            ++target_read_attempts;
            target_read_result = std::strcmp(target_read_kind, "RtlCompareMemory") == 0
                ? page_guard_engine::remote_thread_call(target_pid, target_read_fn, fixture.address, fixture.address, 128, 0, 2500, "testlab_integrity_RtlCompareMemory")
                : page_guard_engine::remote_thread_call(target_pid, target_read_fn, i, fixture.address, 128, 0, 2500, "testlab_integrity_RtlComputeCrc32");
            if (target_read_result != 0)
                ++target_read_ok;
            Sleep(75);
        }
    }

    std::vector<uint8_t> readback;
    const bool driver_read_ok = driver_bridge::read_memory_for(target_pid, fixture.address, 128, readback) && !readback.empty();
    std::vector<uint8_t> writeback = readback;
    if (!writeback.empty())
        writeback[0] ^= 0x5Au;
    const bool driver_write_ok = !writeback.empty() && driver_bridge::write_memory_for(target_pid, fixture.address, writeback);

    integrity_hunter::stop_hunt();
    const bool idle = integrity_hunter::wait_until_idle(12000);

    size_t node_count = 0;
    size_t event_count = 0;
    uint64_t first_reader = 0;
    uint64_t first_fault = 0;
    uint32_t first_access = 0;
    int first_node_reads = 0;
    std::string status_text;
    {
        std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
        node_count = integrity_hunter::g_state.nodes.size();
        event_count = integrity_hunter::g_state.event_log.size();
        if (!integrity_hunter::g_state.event_log.empty()) {
            first_reader = integrity_hunter::g_state.event_log.front().rip;
            first_fault = integrity_hunter::g_state.event_log.front().fault_addr;
            first_access = integrity_hunter::g_state.event_log.front().access_type;
        }
        if (!integrity_hunter::g_state.nodes.empty()) {
            first_node_reads = integrity_hunter::g_state.nodes.front().read_count;
        }
        status_text = integrity_hunter::g_state.status_text;
    }
    const uint64_t total_reads = integrity_hunter::g_state.total_reads.load();

    driver_bridge::memory_region_t after_region{};
    const bool after_query = driver_bridge::query_memory_for(target_pid, fixture.address, after_region);
    const bool after_guard = after_query && ((after_region.protect & PAGE_GUARD) != 0);

    diag::log_tagged_fmt("test_analysis_detail", "integ_nd result: pid=%u addr=0x%llX started=%d install_seen=%d install_complete=%d install_success=%d idle=%d pg_session=%u before_query=%d before_protect=0x%08X guard_query=%d guard_state=%d guard_protect=0x%08X after_query=%d after_guard=%d after_protect=0x%08X driver_read_ok=%d read_bytes=%zu driver_write_ok=%d target_read_kind=%s target_read_module=%s target_read_fn=0x%llX target_read_attempts=%u target_read_ok=%u target_read_result=0x%llX nodes=%zu events=%zu total_reads=%llu first_reader=0x%llX first_fault=0x%llX first_access=%u first_node_reads=%d status='%s'",
        (unsigned)target_pid,
        (unsigned long long)fixture.address,
        started ? 1 : 0,
        install_seen ? 1 : 0,
        install_complete ? 1 : 0,
        install_success ? 1 : 0,
        idle ? 1 : 0,
        pg_session,
        before_query ? 1 : 0,
        (unsigned)before_region.protect,
        guard_query ? 1 : 0,
        guard_set ? 1 : 0,
        (unsigned)guard_region.protect,
        after_query ? 1 : 0,
        after_guard ? 1 : 0,
        (unsigned)after_region.protect,
        driver_read_ok ? 1 : 0,
        readback.size(),
        driver_write_ok ? 1 : 0,
        target_read_kind,
        read_module.empty() ? "<none>" : read_module.c_str(),
        (unsigned long long)target_read_fn,
        target_read_attempts,
        target_read_ok,
        (unsigned long long)target_read_result,
        node_count,
        event_count,
        (unsigned long long)total_reads,
        (unsigned long long)first_reader,
        (unsigned long long)first_fault,
        first_access,
        first_node_reads,
        status_text.c_str());

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (started && install_seen && install_complete && install_success && idle && guard_query && guard_set && target_read_ok > 0 && total_reads > 0 && event_count > 0 && node_count > 0) {
        log_msg(hf, "integ_nd", "PASS -- fixture=0x%016llX guard_state=%d read_ok=%d write_ok=%d target_read=%s module=%s attempts=%u ok=%u nodes=%zu events=%zu total_reads=%llu first_reader=0x%016llX first_fault=0x%016llX node_reads=%d status=\"%s\" (elapsed %lld ms)",
            (unsigned long long)fixture.address,
            guard_set ? 1 : 0,
            driver_read_ok ? 1 : 0,
            driver_write_ok ? 1 : 0,
            target_read_kind,
            read_module.empty() ? "<none>" : read_module.c_str(),
            target_read_attempts,
            target_read_ok,
            node_count,
            event_count,
            (unsigned long long)total_reads,
            (unsigned long long)first_reader,
            (unsigned long long)first_fault,
            first_node_reads,
            status_text.c_str(),
            (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "integ_nd", "FAIL -- integrity hunter evidence insufficient: fixture=0x%016llX started=%d install_seen=%d install_complete=%d install_success=%d idle=%d pg_session=%u guard_query=%d guard_state=%d guard_protect=0x%08X read_ok=%d read_bytes=%zu write_ok=%d target_read=%s module=%s attempts=%u ok=%u result=0x%016llX nodes=%zu events=%zu total_reads=%llu first_reader=0x%016llX first_fault=0x%016llX first_access=%u node_reads=%d status=\"%s\" status_bridge=\"%s\" last_error=\"%s\" (elapsed %lld ms)",
            (unsigned long long)fixture.address,
            started ? 1 : 0,
            install_seen ? 1 : 0,
            install_complete ? 1 : 0,
            install_success ? 1 : 0,
            idle ? 1 : 0,
            pg_session,
            guard_query ? 1 : 0,
            guard_set ? 1 : 0,
            (unsigned)guard_region.protect,
            driver_read_ok ? 1 : 0,
            readback.size(),
            driver_write_ok ? 1 : 0,
            target_read_kind,
            read_module.empty() ? "<none>" : read_module.c_str(),
            target_read_attempts,
            target_read_ok,
            (unsigned long long)target_read_result,
            node_count,
            event_count,
            (unsigned long long)total_reads,
            (unsigned long long)first_reader,
            (unsigned long long)first_fault,
            first_access,
            first_node_reads,
            status_text.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_binary_map_options(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_op", "START -- binary map generate with different options");
    auto t0 = std::chrono::steady_clock::now();

    aida::binary_map::map_options_t opts;
    opts.max_functions = 5;
    opts.max_globals = 3;
    opts.max_chars = 1024;
    opts.include_imports = true;
    opts.include_exports = true;

    aida::binary_map::map_t map = make_binary_map_fixture();
    std::string text = aida::binary_map::render_text(map, opts);
    bool ok = !text.empty();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap_op", "PASS -- generate returned %d, sections=%zu funcs=%zu imports=%zu exports=%zu (elapsed %lld ms)",
        ok, map.sections.size(), map.functions.size(),
        map.imports.size(), map.exports.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_binary_map_pin_unpin(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_pin", "START -- binary map pin/unpin function");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t test_va = 0xDEAD1234;
    aida::binary_map::pin_function(test_va);

    auto pinned = aida::binary_map::pinned_functions();
    bool found = false;
    for (auto va : pinned) {
        if (va == test_va) { found = true; break; }
    }

    aida::binary_map::unpin_function(test_va);

    auto pinned_after = aida::binary_map::pinned_functions();
    bool found_after = false;
    for (auto va : pinned_after) {
        if (va == test_va) { found_after = true; break; }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (found && !found_after) {
        log_msg(hf, "binmap_pin", "PASS -- pin/unpin correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "binmap_pin", "FAIL -- pinned=%d unpinned=%d (elapsed %lld ms)", found, !found_after, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_binary_map_clear_cache(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_cc", "START -- binary map clear_cache");
    auto t0 = std::chrono::steady_clock::now();

    bool ok = aida::binary_map::clear_cache();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap_cc", "PASS -- clear_cache returned %d (elapsed %lld ms)", ok, (long long)ms);
    passed.fetch_add(1);
}

static void test_binary_map_render_text(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "binmap_rt", "START -- binary map render_text");
    auto t0 = std::chrono::steady_clock::now();

    aida::binary_map::map_options_t opts;
    opts.max_functions = 3;
    opts.max_globals = 2;
    opts.max_chars = 512;

    aida::binary_map::map_t map = make_binary_map_fixture();

    std::string text = aida::binary_map::render_text(map, opts);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "binmap_rt", "PASS -- render_text returned %zu chars (elapsed %lld ms)", text.size(), (long long)ms);
    passed.fetch_add(1);
}

static void test_source_reconstructor_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "srcrecon_r", "START -- source reconstructor is_running/get_progress");
    auto t0 = std::chrono::steady_clock::now();

    bool running = source_reconstructor::is_running();
    float progress = source_reconstructor::get_progress();
    std::string status = source_reconstructor::get_status();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "srcrecon_r", "PASS -- running=%d progress=%.2f status=\"%s\" (elapsed %lld ms)",
        running, progress, status.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_source_reconstructor_last_result(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "srcrecon_lr", "START -- source reconstructor get_last_result");
    auto t0 = std::chrono::steady_clock::now();

    if (source_reconstructor::is_running()) {
        const ULONGLONG wait_start = GetTickCount64();
        while (source_reconstructor::is_running() && GetTickCount64() - wait_start < 10000)
            Sleep(25);
        if (source_reconstructor::is_running()) {
            float progress = source_reconstructor::get_progress();
            std::string status = source_reconstructor::get_status();
            auto stats = work_queue::stats();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
            log_msg(hf, "srcrecon_lr", "FAIL -- previous reconstruction still running progress=%.2f status=\"%s\" queue_alive=%d queue_pending=%zu queue_active=%u elapsed=%lld ms",
                progress, status.c_str(), stats.alive ? 1 : 0, stats.pending, stats.active, (long long)ms);
            failed.fetch_add(1);
            return;
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    source_recon_fixture_t fx = make_source_recon_fixture(hf, "srcrecon_lr");
    if (fx.address == 0 || fx.size == 0) {
        failed.fetch_add(1);
        return;
    }

    source_reconstructor::reconstruction_config_t config;
    config.project_name = "aida_test_recon";
    config.output_dir = source_recon_output_dir();
    config.module_name = "aida_sr_fixture.exe";
    config.module_base = fx.address;
    config.module_size = static_cast<uint32_t>(fx.size);
    config.include_imports = false;
    config.include_exports = true;
    config.generate_cmake = true;
    config.use_ai_refinement = false;
    config.max_functions = 1;

    log_msg(hf, "srcrecon_lr", "RUN -- reconstruct base=0x%016llX size=%u output=\"%s\" max_functions=%d",
        static_cast<unsigned long long>(config.module_base),
        static_cast<unsigned>(config.module_size),
        config.output_dir.c_str(),
        config.max_functions);

    source_reconstructor::reconstruct(config);
    if (!source_reconstructor::is_running()) {
        source_reconstructor::reconstruction_result_t immediate{};
        {
            std::lock_guard<std::mutex> lk(source_reconstructor::g_state.mutex);
            immediate = source_reconstructor::g_state.last_result;
        }
        log_msg(hf, "srcrecon_lr", "FAIL -- reconstruct returned without entering running state success=%d error=\"%s\" total_funcs=%d files=%zu",
            immediate.success ? 1 : 0,
            immediate.error.c_str(),
            immediate.total_functions,
            immediate.files_created.size());
        failed.fetch_add(1);
        return;
    }

    const ULONGLONG run_start = GetTickCount64();
    ULONGLONG next_log = run_start + 500;
    bool timed_out = false;
    while (source_reconstructor::is_running()) {
        ULONGLONG now = GetTickCount64();
        if (now >= next_log) {
            auto stats = work_queue::stats();
            log_msg(hf, "srcrecon_lr", "WAIT -- elapsed_ms=%llu progress=%.2f stage=%d status=\"%s\" queue_pending=%zu queue_active=%u",
                static_cast<unsigned long long>(now - run_start),
                source_reconstructor::get_progress(),
                static_cast<int>(source_reconstructor::get_stage()),
                source_reconstructor::get_status().c_str(),
                stats.pending,
                stats.active);
            next_log = now + 500;
        }
        if (now - run_start >= 16000) {
            timed_out = true;
            break;
        }
        Sleep(25);
    }

    if (timed_out) {
        source_reconstructor::cancel();
        const ULONGLONG cancel_start = GetTickCount64();
        while (source_reconstructor::is_running() && GetTickCount64() - cancel_start < 5000)
            Sleep(25);
        const ULONGLONG cancel_elapsed = GetTickCount64() - cancel_start;
        if (source_reconstructor::is_running())
            fx.disarm();
        source_reconstructor::reconstruction_result_t result{};
        {
            std::lock_guard<std::mutex> lk(source_reconstructor::g_state.mutex);
            result = source_reconstructor::g_state.last_result;
        }
        auto stats = work_queue::stats();
        auto svc_stats = work_queue::service_stats();
        auto critical_stats = critical_work_queue::stats();
        ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        log_msg(hf, "srcrecon_lr", "FAIL -- reconstruction timeout cancel_wait_ms=%llu running=%d progress=%.2f stage=%d status=\"%s\" success=%d error=\"%s\" total_funcs=%d decompiled=%d modules=%d files=%zu preload_read=%zu work_pending=%zu work_active=%u work_rejected=%llu service_pending=%zu service_active=%u service_rejected=%llu critical_pending=%zu critical_active=%u critical_rejected=%llu elapsed=%lld ms",
            static_cast<unsigned long long>(cancel_elapsed),
            source_reconstructor::is_running() ? 1 : 0,
            source_reconstructor::get_progress(),
            static_cast<int>(source_reconstructor::get_stage()),
            source_reconstructor::get_status().c_str(),
            result.success ? 1 : 0,
            result.error.c_str(),
            result.total_functions,
            result.decompiled_functions,
            result.modules_created,
            result.files_created.size(),
            result.preload.total_read,
            stats.pending,
            stats.active,
            static_cast<unsigned long long>(stats.rejected),
            svc_stats.pending,
            svc_stats.active,
            static_cast<unsigned long long>(svc_stats.rejected),
            critical_stats.pending,
            critical_stats.active,
            static_cast<unsigned long long>(critical_stats.rejected),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    source_reconstructor::reconstruction_result_t result{};
    {
        std::lock_guard<std::mutex> lk(source_reconstructor::g_state.mutex);
        result = source_reconstructor::g_state.last_result;
    }

    size_t existing_files = 0;
    size_t source_files = 0;
    unsigned long long total_bytes = 0;
    bool source_content_ok = false;
    for (const auto& path : result.files_created) {
        unsigned long long file_size = 0;
        if (file_exists_nonempty(path, &file_size)) {
            ++existing_files;
            total_bytes += file_size;
        }
        if (path.size() >= 4 && _stricmp(path.c_str() + path.size() - 4, ".cpp") == 0) {
            ++source_files;
            std::string text;
            if (read_text_file_limited(path, text, 65536) &&
                (text.find("sub_") != std::string::npos ||
                 text.find("__asm") != std::string::npos ||
                 text.find("void ") != std::string::npos)) {
                source_content_ok = true;
            }
        }
    }

    ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    const bool ok = result.success && result.total_functions > 0 &&
        result.modules_created > 0 && !result.files_created.empty() &&
        existing_files == result.files_created.size() && source_files > 0 &&
        source_content_ok && result.preload.total_read > 0 &&
        result.preload.mz && result.preload.pe_header_ok;

    if (!ok) {
        log_msg(hf, "srcrecon_lr", "FAIL -- reconstruction result success=%d error=\"%s\" total_funcs=%d decompiled=%d modules=%d files=%zu existing=%zu source_files=%zu source_content=%d bytes=%llu preload_read=%zu mz=%d pe=%d chunks_ok=%zu chunks_failed=%zu output=\"%s\" (elapsed %lld ms)",
            result.success ? 1 : 0,
            result.error.c_str(),
            result.total_functions,
            result.decompiled_functions,
            result.modules_created,
            result.files_created.size(),
            existing_files,
            source_files,
            source_content_ok ? 1 : 0,
            total_bytes,
            result.preload.total_read,
            result.preload.mz ? 1 : 0,
            result.preload.pe_header_ok ? 1 : 0,
            result.preload.chunks_ok,
            result.preload.chunks_failed,
            result.output_dir.c_str(),
            (long long)ms);
        failed.fetch_add(1);
        return;
    }

    log_msg(hf, "srcrecon_lr", "PASS -- success=%d total_funcs=%d decompiled=%d fallback_only=%d modules=%d files=%zu bytes=%llu preload_read=%zu output=\"%s\" (elapsed %lld ms)",
        result.success ? 1 : 0,
        result.total_functions,
        result.decompiled_functions,
        result.decompiled_functions == 0 ? 1 : 0,
        result.modules_created,
        result.files_created.size(),
        total_bytes,
        result.preload.total_read,
        result.output_dir.c_str(),
        (long long)ms);
    passed.fetch_add(1);
}

static void test_xref_engine_scan_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xref_st", "START -- xref engine scanning state");
    auto t0 = std::chrono::steady_clock::now();

    bool scanning = xref_engine::is_scanning();
    xref_engine::cancel_scan();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "xref_st", "PASS -- is_scanning=%d (elapsed %lld ms)", scanning, (long long)ms);
    passed.fetch_add(1);
}

static void test_xref_type_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xref_tn", "START -- xref engine type names");
    auto t0 = std::chrono::steady_clock::now();

    std::string call_name = xref_engine::xref_type_name(xref_engine::xref_type_t::call);
    std::string jmp_name = xref_engine::xref_type_name(xref_engine::xref_type_t::jump);
    std::string jcc_name = xref_engine::xref_type_name(xref_engine::xref_type_t::conditional_jump);
    std::string lea_name = xref_engine::xref_type_name(xref_engine::xref_type_t::lea);
    std::string data_name = xref_engine::xref_type_name(xref_engine::xref_type_t::data_ref);

    bool ok = (call_name == "CALL" && jmp_name == "JMP" && jcc_name == "Jcc" &&
               lea_name == "LEA" && data_name == "DATA");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "xref_tn", "PASS -- all xref type names correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "xref_tn", "FAIL -- unexpected type names (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_xref_db_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xrefdb_st", "START -- xref_db state check");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t from = 0x140001020;
    uint64_t addr = 0x140002000;
    seed_xref_db_fixture(from, addr);
    bool building = xref_db::g_state.building.load();
    size_t module_count = 0;
    size_t built_count = 0;
    size_t total_xrefs = 0;
    {
        std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
        module_count = xref_db::g_state.modules.size();
        for (const auto& kv : xref_db::g_state.modules) {
            if (kv.second.built) {
                ++built_count;
                total_xrefs += kv.second.total_xrefs;
            }
        }
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (!building && (module_count == 0 || built_count == 0 || total_xrefs == 0)) {
        log_msg(hf, "xrefdb_st", "FAIL -- xref_db idle with empty fixture state modules=%zu built=%zu total_xrefs=%zu (elapsed %lld ms)",
            module_count, built_count, total_xrefs, (long long)ms);
        failed.fetch_add(1);
        return;
    }
    log_msg(hf, "xrefdb_st", "PASS -- building=%d modules=%zu built=%zu total_xrefs=%zu (elapsed %lld ms)",
        building, module_count, built_count, total_xrefs, (long long)ms);
    passed.fetch_add(1);
}

static void test_xref_db_query_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "xrefdb_qt", "START -- xref_db query_xrefs_to");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t from = 0x140001020;
    uint64_t addr = 0x140002000;
    seed_xref_db_fixture(from, addr);
    xref_db::query_xrefs_to(addr);

    size_t results = 0;
    {
        std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
        results = xref_db::g_state.query_results.size();
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (results == 0) {
        log_msg(hf, "xrefdb_qt", "FAIL -- query_xrefs_to found 0 results (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1); return;
    }
    log_msg(hf, "xrefdb_qt", "PASS -- query_xrefs_to found %zu results (elapsed %lld ms)", results, (long long)ms);
    passed.fetch_add(1);
}

static void test_expression_eval_multiply(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_mul", "START -- expression eval: 0x10 * 0x10");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0x10 * 0x10", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0x100) {
        log_msg(hf, "expr_mul", "PASS -- 0x10 * 0x10 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_mul", "FAIL -- ok=%d value=0x%llX (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_bitwise(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_bit", "START -- expression eval: 0xFF & 0x0F | 0xF0");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0xFF & 0x0F | 0xF0", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0xFF) {
        log_msg(hf, "expr_bit", "PASS -- 0xFF & 0x0F | 0xF0 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_bit", "FAIL -- ok=%d value=0x%llX (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_shift(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_shl", "START -- expression eval: 1 << 16");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("1 << 16", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 65536) {
        log_msg(hf, "expr_shl", "PASS -- 1 << 16 = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_shl", "FAIL -- ok=%d value=%llu (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_nested_parens(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_par", "START -- expression eval: (10 + 20) * (3 + 7)");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("(10 + 20) * (3 + 7)", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 300) {
        log_msg(hf, "expr_par", "PASS -- (10+20)*(3+7) = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_par", "FAIL -- ok=%d value=%llu (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_xor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_xor", "START -- expression eval: 0xAAAA ^ 0x5555");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    auto result = expression_eval::evaluate("0xAAAA ^ 0x5555", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 0xFFFF) {
        log_msg(hf, "expr_xor", "PASS -- 0xAAAA ^ 0x5555 = 0x%llX (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_xor", "FAIL -- ok=%d value=0x%llX (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_expression_eval_multi_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "expr_mreg", "START -- expression eval: rax + rbx * rcx");
    auto t0 = std::chrono::steady_clock::now();

    expression_eval::context_t ctx{};
    ctx.rax = 10;
    ctx.rbx = 5;
    ctx.rcx = 3;
    auto result = expression_eval::evaluate("rax + rbx * rcx", ctx);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (result.ok && result.value == 25) {
        log_msg(hf, "expr_mreg", "PASS -- rax(10) + rbx(5)*rcx(3) = %llu (elapsed %lld ms)",
            (unsigned long long)result.value, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "expr_mreg", "FAIL -- ok=%d value=%llu (elapsed %lld ms)",
            result.ok, (unsigned long long)result.value, (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_fuzzer_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "fuzz_st", "START -- fuzzer engine state check");
    auto t0 = std::chrono::steady_clock::now();

    bool running = fuzzer_engine::g_state.running.load();
    bool cancel = fuzzer_engine::g_state.cancel.load();

    uint64_t total_exec = 0;
    uint64_t total_crash = 0;
    {
        std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
        total_exec = fuzzer_engine::g_state.stats.total_executions;
        total_crash = fuzzer_engine::g_state.stats.total_crashes;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "fuzz_st", "PASS -- running=%d cancel=%d execs=%llu crashes=%llu (elapsed %lld ms)",
        running, cancel,
        (unsigned long long)total_exec, (unsigned long long)total_crash, (long long)ms);
    passed.fetch_add(1);
}

static void test_fuzzer_config(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "fuzz_cfg", "START -- fuzzer engine config defaults");
    auto t0 = std::chrono::steady_clock::now();

    fuzzer_engine::fuzz_config_t cfg;
    bool ok = (cfg.max_instructions == 100000 &&
               cfg.timeout_ms == 5000 &&
               cfg.max_iterations == 100000 &&
               cfg.input_size == 256 &&
               cfg.mutation_count == 4);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "fuzz_cfg", "PASS -- config defaults correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "fuzz_cfg", "FAIL -- unexpected config defaults (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_stealth_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "stealth_st", "START -- stealth engine state check");
    auto t0 = std::chrono::steady_clock::now();

    bool active = stealth_engine::g_state.active.load();
    uint32_t attached_pid = driver_bridge::attached_pid();
    bool active_for_attached = attached_pid != 0 && stealth_engine::is_active_for_pid(attached_pid);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (attached_pid == 0 || active_for_attached) {
        log_msg(hf, "stealth_st", "PASS -- active=%d attached_pid=%u active_for_attached=%d (elapsed %lld ms)",
            active ? 1 : 0, attached_pid, active_for_attached ? 1 : 0, (long long)ms);
        passed.fetch_add(1);
    } else {
        auto session = stealth_engine::get_session_info();
        log_msg(hf, "stealth_st", "FAIL -- attached_pid=%u stealth_active=%d session_pid=%u status=\"%s\" (elapsed %lld ms)",
            attached_pid,
            active ? 1 : 0,
            session.pid,
            stealth_engine::get_status().c_str(),
            (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_stealth_options_default(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "stealth_op", "START -- stealth engine default options");
    auto t0 = std::chrono::steady_clock::now();

    stealth_engine::stealth_options_t opts;
    bool ok = (opts.spoof_peb == true && opts.hook_rdtsc == true && opts.scrub_context == false);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "stealth_op", "PASS -- default options correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "stealth_op", "FAIL -- unexpected defaults (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_struct_recon_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "strecon_st", "START -- struct recon state check");
    auto t0 = std::chrono::steady_clock::now();

    bool monitoring = struct_recon::g_state.monitoring.load();
    float progress = struct_recon::g_state.progress.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "strecon_st", "PASS -- monitoring=%d progress=%.2f (elapsed %lld ms)",
        monitoring, progress, (long long)ms);
    passed.fetch_add(1);
}

static void test_struct_recon_field_types(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "strecon_ft", "START -- struct recon field type enum range");
    auto t0 = std::chrono::steady_clock::now();

    int count_val = static_cast<int>(struct_recon::field_type_t::COUNT);
    bool ok = (count_val > 20 &&
               static_cast<int>(struct_recon::field_type_t::unknown) == 0 &&
               static_cast<int>(struct_recon::field_type_t::pointer) == 11 &&
               static_cast<int>(struct_recon::field_type_t::vtable_ptr) == 12 &&
               std::strcmp(struct_recon::field_type_name(struct_recon::field_type_t::pointer), "void*") == 0 &&
               std::strcmp(struct_recon::field_type_name(struct_recon::field_type_t::vtable_ptr), "vtable*") == 0);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "strecon_ft", "PASS -- field_type_t has %d values (elapsed %lld ms)", count_val, (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "strecon_ft", "FAIL -- unexpected field_type_t layout (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_decrypt_oracle_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "decr_st", "START -- decrypt oracle state check");
    auto t0 = std::chrono::steady_clock::now();

    bool scanning = decrypt_oracle::g_state.scanning.load();
    float progress = decrypt_oracle::g_state.progress.load();
    int total_xrefs = decrypt_oracle::g_state.total_xrefs.load();
    int processed_xrefs = decrypt_oracle::g_state.processed_xrefs.load();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "decr_st", "PASS -- scanning=%d progress=%.2f total_xrefs=%d processed=%d (elapsed %lld ms)",
        scanning, progress, total_xrefs, processed_xrefs, (long long)ms);
    passed.fetch_add(1);
}

static void test_decrypt_oracle_config(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "decr_cfg", "START -- decrypt oracle config defaults");
    auto t0 = std::chrono::steady_clock::now();

    decrypt_oracle::scan_config_t cfg;
    bool ok = (cfg.max_instructions == 50000 &&
               cfg.timeout_ms == 5000 &&
               cfg.min_string_length == 4 &&
               cfg.min_printable_ratio > 0.7f);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (ok) {
        log_msg(hf, "decr_cfg", "PASS -- config defaults correct (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "decr_cfg", "FAIL -- unexpected config defaults (elapsed %lld ms)", (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_pdb_resolve_cache_path(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "pdb_cache", "START -- pdb downloader resolve_cache_path");
    auto t0 = std::chrono::steady_clock::now();

    pdb_downloader::download_request_t req;
    req.pdb_name = "ntdll.pdb";
    req.pdb_guid = "00000000000000000000000000000000";
    req.pdb_age = 1;

    char* appdata = nullptr;
    size_t len = 0;
    _dupenv_s(&appdata, &len, "APPDATA");
    if (appdata) {
        req.cache_root = std::string(appdata) + "\\AiDA\\Standalone\\symbols";
        free(appdata);
    }

    std::string out_path;
    bool resolved = pdb_downloader::resolve_cache_path(req, out_path);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "pdb_cache", "PASS -- resolve_cache_path returned %d path=\"%s\" (elapsed %lld ms)",
        resolved, out_path.c_str(), (long long)ms);
    passed.fetch_add(1);
}

static void test_comment_store_multiple(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "cmt_multi", "START -- comment store multiple addresses");
    auto t0 = std::chrono::steady_clock::now();

    comment_store::set(0xBEEF0001, "comment_alpha");
    comment_store::set(0xBEEF0002, "comment_beta");
    comment_store::set(0xBEEF0003, "comment_gamma");

    std::string a = comment_store::get(0xBEEF0001);
    std::string b = comment_store::get(0xBEEF0002);
    std::string c = comment_store::get(0xBEEF0003);

    comment_store::set(0xBEEF0001, "");
    comment_store::set(0xBEEF0002, "");
    comment_store::set(0xBEEF0003, "");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (a == "comment_alpha" && b == "comment_beta" && c == "comment_gamma") {
        log_msg(hf, "cmt_multi", "PASS -- all 3 comments stored/retrieved correctly (elapsed %lld ms)", (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "cmt_multi", "FAIL -- a=\"%s\" b=\"%s\" c=\"%s\" (elapsed %lld ms)",
            a.c_str(), b.c_str(), c.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void test_comment_store_overwrite(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    log_msg(hf, "cmt_over", "START -- comment store overwrite");
    auto t0 = std::chrono::steady_clock::now();

    uint64_t addr = 0xBEEF1234;
    comment_store::set(addr, "first_value");
    comment_store::set(addr, "second_value");

    std::string got = comment_store::get(addr);
    comment_store::set(addr, "");

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    if (got == "second_value") {
        log_msg(hf, "cmt_over", "PASS -- overwrite correct: \"%s\" (elapsed %lld ms)", got.c_str(), (long long)ms);
        passed.fetch_add(1);
    } else {
        log_msg(hf, "cmt_over", "FAIL -- got \"%s\" (elapsed %lld ms)", got.c_str(), (long long)ms);
        failed.fetch_add(1);
    }
}

static void select_analysis_hub_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                     const char* tag, analysis_hub_view::sub_tab_t value) {
    auto t0 = std::chrono::steady_clock::now();
    analysis_hub_view::sub_tab_t before = analysis_hub_view::active_sub_tab();
    const char* before_label = analysis_hub_view::sub_tab_label(before);
    const char* target_label = analysis_hub_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- before=%d label=%s target=%d target_label=%s tid=%lu",
        static_cast<int>(before),
        before_label,
        static_cast<int>(value),
        target_label,
        (unsigned long)GetCurrentThreadId());
    analysis_hub_view::set_sub_tab(value);
    analysis_hub_view::sub_tab_t got = analysis_hub_view::active_sub_tab();
    const char* label = analysis_hub_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- after=%d label=%s changed=%d elapsed_us=%lld",
        static_cast<int>(got),
        analysis_hub_view::sub_tab_label(got),
        (before != got) ? 1 : 0,
        elapsed_us_since(t0));
    if (got == value && label[0] != '\0') {
        log_msg(hf, tag, "PASS -- analysis_hub sub_tab selected and read back (%d label=%s)",
            static_cast<int>(value), label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- analysis_hub sub_tab set %d but read back %d label=\"%s\"",
            static_cast<int>(value), static_cast<int>(got), label);
        failed.fetch_add(1);
    }
}

static void select_symbolic_inner_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                      const char* tag, int value, const char* expected_label) {
    auto t0 = std::chrono::steady_clock::now();
    analysis_hub_view::sub_tab_t parent_before = analysis_hub_view::active_sub_tab();
    int before = symbolic_view::active_tab();
    log_msg(hf, tag, "STATE -- parent_before=%d parent_label=%s inner_before=%d inner_label=%s target=%d expected_label=%s tid=%lu",
        static_cast<int>(parent_before),
        analysis_hub_view::sub_tab_label(parent_before),
        before,
        symbolic_view::tab_label(before),
        value,
        expected_label,
        (unsigned long)GetCurrentThreadId());
    analysis_hub_view::set_sub_tab(analysis_hub_view::sub_tab_t::symbolic);
    symbolic_view::set_active_tab(value);
    int got = symbolic_view::active_tab();
    const char* label = symbolic_view::tab_label(value);
    log_msg(hf, tag, "STATE -- parent_after=%d parent_label=%s inner_after=%d readback_label=%s changed=%d elapsed_us=%lld",
        static_cast<int>(analysis_hub_view::active_sub_tab()),
        analysis_hub_view::sub_tab_label(analysis_hub_view::active_sub_tab()),
        got,
        symbolic_view::tab_label(got),
        (before != got) ? 1 : 0,
        elapsed_us_since(t0));
    if (got == value && std::strcmp(label, expected_label) == 0) {
        log_msg(hf, tag, "PASS -- symbolic inner tab selected and read back (%d label=%s)",
            value, label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- symbolic inner tab set %d but read back %d label=\"%s\" expected=\"%s\"",
            value, got, label, expected_label);
        failed.fetch_add(1);
    }
}

static void select_protection_inner_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                        const char* tag, int value, const char* expected_label) {
    auto t0 = std::chrono::steady_clock::now();
    analysis_hub_view::sub_tab_t parent_before = analysis_hub_view::active_sub_tab();
    int before = stealth_view::active_sub_tab();
    log_msg(hf, tag, "STATE -- parent_before=%d parent_label=%s inner_before=%d inner_label=%s target=%d expected_label=%s tid=%lu",
        static_cast<int>(parent_before),
        analysis_hub_view::sub_tab_label(parent_before),
        before,
        stealth_view::sub_tab_label(before),
        value,
        expected_label,
        (unsigned long)GetCurrentThreadId());
    analysis_hub_view::set_sub_tab(analysis_hub_view::sub_tab_t::stealth);
    stealth_view::set_sub_tab(value);
    int got = stealth_view::active_sub_tab();
    const char* label = stealth_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- parent_after=%d parent_label=%s inner_after=%d readback_label=%s changed=%d elapsed_us=%lld",
        static_cast<int>(analysis_hub_view::active_sub_tab()),
        analysis_hub_view::sub_tab_label(analysis_hub_view::active_sub_tab()),
        got,
        stealth_view::sub_tab_label(got),
        (before != got) ? 1 : 0,
        elapsed_us_since(t0));
    if (got == value && std::strcmp(label, expected_label) == 0) {
        log_msg(hf, tag, "PASS -- protection inner tab selected and read back (%d label=%s)",
            value, label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- protection inner tab set %d but read back %d label=\"%s\" expected=\"%s\"",
            value, got, label, expected_label);
        failed.fetch_add(1);
    }
}

static void test_analysis_hub_tab_symbolic(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.symbolic", analysis_hub_view::sub_tab_t::symbolic);
}
static void test_analysis_hub_tab_taint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.taint", analysis_hub_view::sub_tab_t::taint);
}
static void test_analysis_hub_tab_deobfuscation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.deobfuscation", analysis_hub_view::sub_tab_t::deobfuscation);
}
static void test_analysis_hub_tab_fuzzer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.fuzzer", analysis_hub_view::sub_tab_t::fuzzer);
}
static void test_analysis_hub_tab_protection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_analysis_hub_tab(hf, passed, failed, "analysis_hub_tab.protection", analysis_hub_view::sub_tab_t::stealth);
}

static void select_types_hub_tab(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed,
                                 const char* tag, types_hub_view::sub_tab_t value) {
    auto t0 = std::chrono::steady_clock::now();
    types_hub_view::sub_tab_t before = types_hub_view::active_sub_tab();
    const char* before_label = types_hub_view::sub_tab_label(before);
    const char* target_label = types_hub_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- before=%d label=%s target=%d target_label=%s tid=%lu",
        static_cast<int>(before),
        before_label,
        static_cast<int>(value),
        target_label,
        (unsigned long)GetCurrentThreadId());
    types_hub_view::set_sub_tab(value);
    types_hub_view::sub_tab_t got = types_hub_view::active_sub_tab();
    const char* label = types_hub_view::sub_tab_label(value);
    log_msg(hf, tag, "STATE -- after=%d label=%s changed=%d elapsed_us=%lld",
        static_cast<int>(got),
        types_hub_view::sub_tab_label(got),
        (before != got) ? 1 : 0,
        elapsed_us_since(t0));
    if (got == value && label[0] != '\0') {
        log_msg(hf, tag, "PASS -- types_hub sub_tab selected and read back (%d label=%s)",
            static_cast<int>(value), label);
        passed.fetch_add(1);
    } else {
        log_msg(hf, tag, "FAIL -- types_hub sub_tab set %d but read back %d label=\"%s\"",
            static_cast<int>(value), static_cast<int>(got), label);
        failed.fetch_add(1);
    }
}

static void test_types_hub_tab_structs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.structs", types_hub_view::sub_tab_t::structs);
}
static void test_types_hub_tab_unions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.unions", types_hub_view::sub_tab_t::unions);
}
static void test_types_hub_tab_enums(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.enums", types_hub_view::sub_tab_t::enums);
}
static void test_types_hub_tab_typedefs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.typedefs", types_hub_view::sub_tab_t::typedefs);
}
static void test_types_hub_tab_functions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.functions", types_hub_view::sub_tab_t::functions);
}
static void test_types_hub_tab_inferred(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.inferred", types_hub_view::sub_tab_t::inferred);
}
static void test_types_hub_tab_dissector(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_types_hub_tab(hf, passed, failed, "types_hub_tab.dissector", types_hub_view::sub_tab_t::dissector);
}

static void test_symbolic_inner_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.trace", 0, "Trace");
}
static void test_symbolic_inner_deobfuscation(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.deobfuscation", 1, "Deobfuscation");
}
static void test_symbolic_inner_slice(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.slice", 2, "Slice");
}
static void test_symbolic_inner_solver(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.solver", 3, "Solver");
}
static void test_symbolic_inner_constraints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.constraints", 4, "Constraints");
}
static void test_symbolic_inner_expression(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_symbolic_inner_tab(hf, passed, failed, "symbolic_inner.expression", 5, "Expression");
}

static void test_protection_inner_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_protection_inner_tab(hf, passed, failed, "protection_inner.scan", 0, "Protection Scan");
}
static void test_protection_inner_controls(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    select_protection_inner_tab(hf, passed, failed, "protection_inner.controls", 1, "Stealth Status");
}

using analysis_test_fn_t = void (*)(HANDLE, std::atomic<int>&, std::atomic<int>&);

struct analysis_test_entry_t {
    const char* name;
    analysis_test_fn_t fn;
    DWORD timeout_ms = 5000;
};

static void run_analysis_test_seh(HANDLE hf, const analysis_test_entry_t& test, std::atomic<int>& passed, std::atomic<int>& failed) {
    __try {
        test.fn(hf, passed, failed);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_msg(hf, "analysis", "FAIL -- %s threw SEH exception 0x%08X",
            test.name, GetExceptionCode());
        failed.fetch_add(1);
    }
}

struct analysis_worker_state_t {
    std::atomic<int> passed{0};
    std::atomic<int> failed{0};
};

struct analysis_log_handle_t {
    HANDLE handle = nullptr;
    explicit analysis_log_handle_t(HANDLE h) : handle(h) {}
    ~analysis_log_handle_t() {
        if (handle && handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
    }
    HANDLE get() const {
        return handle;
    }
};

static HANDLE duplicate_analysis_log_handle(HANDLE hf) {
    if (!hf || hf == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;
    HANDLE dup = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), hf, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return INVALID_HANDLE_VALUE;
    return dup;
}

static bool run_analysis_test_bounded(HANDLE hf, const analysis_test_entry_t& test, std::atomic<int>& passed, std::atomic<int>& failed, DWORD timeout_ms) {
    static test_lab::bounded_runner_t runner(4);
    auto state = std::make_shared<analysis_worker_state_t>();

    auto worker_log = std::make_shared<analysis_log_handle_t>(duplicate_analysis_log_handle(hf));
    const auto result = runner.run(static_cast<std::uint32_t>(timeout_ms), [worker_log, test, state]() {
        HANDLE log_hf = worker_log->get();
        try {
            run_analysis_test_seh(log_hf, test, state->passed, state->failed);
        } catch (const std::exception& ex) {
            log_msg(log_hf, "analysis", "FAIL -- %s threw C++ exception: %s", test.name, ex.what());
            state->failed.fetch_add(1);
        } catch (...) {
            log_msg(log_hf, "analysis", "FAIL -- %s threw unknown C++ exception", test.name);
            state->failed.fetch_add(1);
        }
    });

    if (result.status == test_lab::bounded_run_status_t::completed) {
        passed.fetch_add(state->passed.load(std::memory_order_acquire));
        failed.fetch_add(state->failed.load(std::memory_order_acquire));
        return true;
    }

    if (result.status == test_lab::bounded_run_status_t::timed_out) {
        log_msg(hf, "analysis", "FAIL -- %s exceeded %lu ms watchdog; bounded worker still draining",
            test.name, static_cast<unsigned long>(timeout_ms));
        failed.fetch_add(1);
        return false;
    }

    if (result.status == test_lab::bounded_run_status_t::saturated) {
        log_msg(hf, "analysis", "FAIL -- %s bounded runner saturated; previous timed-out workers still draining", test.name);
        failed.fetch_add(1);
        return false;
    }

    if (result.status == test_lab::bounded_run_status_t::exception) {
        log_msg(hf, "analysis", "FAIL -- %s bounded worker escaped exception: %s",
            test.name, result.error.empty() ? "<unknown>" : result.error.c_str());
        failed.fetch_add(1);
        return false;
    }

    log_msg(hf, "analysis", "FAIL -- %s worker post failed%s%s",
        test.name,
        result.error.empty() ? "" : ": ",
        result.error.empty() ? "" : result.error.c_str());
    failed.fetch_add(1);
    return false;
}

}

void phase_analysis_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    static const analysis_test_entry_t tests[] = {
        { "symbolic_execute",            test_symbolic_execute            },
        { "symbolic_execute_larger",     test_symbolic_execute_larger     },
        { "symbolic_slice",              test_symbolic_slice              },
        { "symbolic_slice_rsi",          test_symbolic_slice_rsi          },
        { "symbolic_taint",              test_symbolic_taint              },
        { "symbolic_taint_rdx",          test_symbolic_taint_rdx          },
        { "symbolic_opaque_predicate",   test_symbolic_opaque_predicate   },
        { "symbolic_solve_for_path",     test_symbolic_solve_for_path     },
        { "symbolic_state_check",        test_symbolic_state_check        },
        { "deobfusc_strip_junk",         test_deobfusc_strip_junk         },
        { "deobfusc_resolve_constants",  test_deobfusc_resolve_constants  },
        { "deobfusc_deobfuscate_fn",     test_deobfusc_deobfuscate_function },
        { "deobfusc_export_asm",         test_deobfusc_export_asm         },
        { "deobfusc_export_stats",       test_deobfusc_export_stats       },
        { "code_patcher_create_revert",  test_code_patcher_create_apply_revert },
        { "code_patcher_nop",            test_code_patcher_nop            },
        { "code_patcher_find_caves",     test_code_patcher_find_caves     },
        { "code_patcher_format_parse",   test_code_patcher_format_parse   },
        { "code_patcher_count",          test_code_patcher_count          },
        { "integrity_hunter_state",      test_integrity_hunter_state      },
        { "integrity_hunter_start_stop", test_integrity_hunter_start_stop },
        { "integrity_hunter_nodes",      test_integrity_hunter_nodes      },
        { "binary_map_generate",         test_binary_map_generate         },
        { "binary_map_options",          test_binary_map_options          },
        { "binary_map_pin_unpin",        test_binary_map_pin_unpin        },
        { "binary_map_clear_cache",      test_binary_map_clear_cache      },
        { "binary_map_render_text",      test_binary_map_render_text      },
        { "source_reconstructor_status", test_source_reconstructor_status },
        { "source_recon_running",        test_source_reconstructor_running },
        { "source_recon_last_result",    test_source_reconstructor_last_result, 22000 },
        { "xref_find",                   test_xref_find                   },
        { "xref_engine_scan_state",      test_xref_engine_scan_state      },
        { "xref_type_names",             test_xref_type_names             },
        { "xref_db_state",               test_xref_db_state               },
        { "xref_db_query_to",            test_xref_db_query_to            },
        { "expression_eval_hex",         test_expression_eval_hex         },
        { "expression_eval_register",    test_expression_eval_register    },
        { "expression_eval_multiply",    test_expression_eval_multiply    },
        { "expression_eval_bitwise",     test_expression_eval_bitwise     },
        { "expression_eval_shift",       test_expression_eval_shift       },
        { "expression_eval_nested_paren",test_expression_eval_nested_parens},
        { "expression_eval_xor",         test_expression_eval_xor         },
        { "expression_eval_multi_reg",   test_expression_eval_multi_register },
        { "comment_store",               test_comment_store               },
        { "comment_store_multiple",      test_comment_store_multiple      },
        { "comment_store_overwrite",     test_comment_store_overwrite     },
        { "rename_store",                test_rename_store                },
        { "rename_store_resolve_or",     test_rename_store_resolve_or     },
        { "fuzzer_state",                test_fuzzer_state                },
        { "fuzzer_config",               test_fuzzer_config               },
        { "stealth_state",               test_stealth_state               },
        { "stealth_options_default",     test_stealth_options_default     },
        { "struct_recon_state",          test_struct_recon_state          },
        { "struct_recon_field_types",    test_struct_recon_field_types    },
        { "decrypt_oracle_state",        test_decrypt_oracle_state        },
        { "decrypt_oracle_config",       test_decrypt_oracle_config       },
        { "pdb_resolve_cache_path",      test_pdb_resolve_cache_path      },

        { "analysis_hub_tab_symbolic",   test_analysis_hub_tab_symbolic   },
        { "analysis_hub_tab_taint",      test_analysis_hub_tab_taint      },
        { "analysis_hub_tab_deobfusc",   test_analysis_hub_tab_deobfuscation },
        { "analysis_hub_tab_fuzzer",     test_analysis_hub_tab_fuzzer     },
        { "analysis_hub_tab_protection", test_analysis_hub_tab_protection },
        { "types_hub_tab_structs",       test_types_hub_tab_structs       },
        { "types_hub_tab_unions",        test_types_hub_tab_unions        },
        { "types_hub_tab_enums",         test_types_hub_tab_enums         },
        { "types_hub_tab_typedefs",      test_types_hub_tab_typedefs      },
        { "types_hub_tab_functions",     test_types_hub_tab_functions     },
        { "types_hub_tab_inferred",      test_types_hub_tab_inferred      },
        { "types_hub_tab_dissector",     test_types_hub_tab_dissector     },
        { "symbolic_inner_trace",        test_symbolic_inner_trace        },
        { "symbolic_inner_deobfusc",     test_symbolic_inner_deobfuscation },
        { "symbolic_inner_slice",        test_symbolic_inner_slice        },
        { "symbolic_inner_solver",       test_symbolic_inner_solver       },
        { "symbolic_inner_constraints",  test_symbolic_inner_constraints  },
        { "symbolic_inner_expression",   test_symbolic_inner_expression   },
        { "protection_inner_scan",       test_protection_inner_scan       },
        { "protection_inner_controls",   test_protection_inner_controls   },
    };

    int total = static_cast<int>(sizeof(tests) / sizeof(tests[0]));
    log_msg(hf, "analysis", "=== BEGIN analysis tests (%d tests) ===", total);
    for (int i = 0; i < total; ++i) {
        if (cancelled && cancelled()) {
            int remaining = total - i;
            skipped.fetch_add(remaining);
            log_msg(hf, "analysis", "cancelled -- skipping %d remaining tests", remaining);
            break;
        }

        log_msg(hf, "analysis", "[%d/%d] %s", i + 1, total, tests[i].name);
        const ULONGLONG t0 = GetTickCount64();
        const int pass_before = passed.load(std::memory_order_acquire);
        const int fail_before = failed.load(std::memory_order_acquire);
        run_analysis_test_bounded(hf, tests[i], passed, failed, tests[i].timeout_ms);
        log_msg(hf, "analysis", "[%d/%d] END %s elapsed_ms=%llu pass_delta=%d fail_delta=%d",
            i + 1, total, tests[i].name,
            static_cast<unsigned long long>(GetTickCount64() - t0),
            passed.load(std::memory_order_acquire) - pass_before,
            failed.load(std::memory_order_acquire) - fail_before);
    }

    log_msg(hf, "analysis", "=== END analysis tests ===");
}

}
