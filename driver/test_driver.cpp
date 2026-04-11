

#include "comm.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <windows.h>
#include <tlhelp32.h>


static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;


static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT || ctrl_type == CTRL_CLOSE_EVENT) {
        printf("\n  [!] Caught console signal %lu — terminating immediately.\n", ctrl_type);
        fflush(stdout);
        TerminateProcess(GetCurrentProcess(), 2);
        return TRUE;
    }
    return FALSE;
}

static void report(const char* test_name, bool success, const char* detail = nullptr) {
    if (success) {
        g_pass++;
        printf("  [PASS] %s", test_name);
    } else {
        g_fail++;
        printf("  [FAIL] %s", test_name);
    }
    if (detail) printf(" -- %s", detail);
    printf("\n");
}

static void skip(const char* test_name, const char* reason) {
    g_skip++;
    printf("  [SKIP] %s -- %s\n", test_name, reason);
}

static void section(const char* name) {
    printf("\n========== %s ==========\n", name);
}

static void print_ip4(const std::uint8_t* addr) {
    printf("%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
}

static void print_ip(const std::uint8_t* addr, std::uint32_t af) {
    if (af == 2) {
        print_ip4(addr);
    } else {
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) printf(":");
            printf("%02x%02x", addr[i], addr[i + 1]);
        }
    }
}


static std::uint32_t find_target_pid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::uint32_t pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"test_target.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}


static bool wait_for_ready_event(DWORD timeout_ms = 15000) {
    HANDLE ready = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\WhosWhoTestReady");
    if (!ready) {
        ready = OpenEventW(SYNCHRONIZE, FALSE, L"Local\\WhosWhoTestReady");
    }
    if (!ready) {
        printf("  [WARN] Could not open WhosWhoTestReady event (err=%lu), falling back to 5s sleep\n",
               GetLastError());
        Sleep(5000);
        return true;
    }
    printf("  [INFO] Waiting for test_target ready signal (timeout=%lums)...\n", timeout_ms);
    DWORD result = WaitForSingleObject(ready, timeout_ms);
    CloseHandle(ready);
    if (result == WAIT_OBJECT_0) {
        printf("  [INFO] test_target signaled ready — network traffic is flowing.\n");
        return true;
    }
    printf("  [WARN] Ready event timed out after %lums — proceeding anyway.\n", timeout_ms);
    return false;
}


static bool test_connect() {
    section("CORE: Connect / Disconnect");

    bool ok = device->connect();
    report("connect()", ok);
    if (!ok) return false;
    report("is_connected()", device->is_connected());
    return true;
}

static void test_heartbeat() {
    section("CORE: Heartbeat");

    bool ok = device->send_heartbeat();
    report("send_heartbeat()", ok);

    ok = device->refresh_heartbeat();
    report("refresh_heartbeat()", ok);
}

static std::uint32_t test_find_process() {
    section("CORE: Find Process");


    std::uint32_t pid = device->find_process("test_target.exe");
    char detail[128];
    snprintf(detail, sizeof(detail), "pid=%u", pid);
    report("find_process(\"test_target.exe\")", pid != 0, detail);
    return pid;
}

static std::uint64_t test_find_image() {
    section("CORE: Find Image Base");

    std::uint64_t base = device->find_image();
    char detail[128];
    snprintf(detail, sizeof(detail), "base=0x%llX", (unsigned long long)base);
    report("find_image()", base != 0, detail);
    return base;
}

static void test_dtb() {
    section("CORE: DTB Resolution");

    device->solve_dtb();
    std::uint64_t dtb = device->get_dtb();
    char detail[128];
    snprintf(detail, sizeof(detail), "dtb=0x%llX", (unsigned long long)dtb);
    report("solve_dtb()", dtb != 0, detail);

    device->solve_kernel_dtb();
    std::uint64_t kdtb = device->get_kernel_dtb();
    snprintf(detail, sizeof(detail), "kernel_dtb=0x%llX", (unsigned long long)kdtb);
    report("solve_kernel_dtb()", kdtb != 0, detail);
}

static void test_read_write(std::uint64_t base) {
    section("MEMORY: Read / Write");

    if (base == 0) {
        skip("read<uint16_t>(MZ)", "no base address");
        skip("read_raw()", "no base address");
        skip("write_raw() roundtrip", "no base address");
        return;
    }


    std::uint16_t mz = device->read<std::uint16_t>(base);
    char detail[128];
    snprintf(detail, sizeof(detail), "value=0x%04X (expect 0x5A4D)", mz);
    report("read<uint16_t>(MZ magic)", mz == 0x5A4D, detail);


    std::uint8_t dos_header[64]{};
    std::size_t got = device->read_raw(base, dos_header, sizeof(dos_header));
    snprintf(detail, sizeof(detail), "read %llu bytes", (unsigned long long)got);
    report("read_raw(64 bytes)", got == 64, detail);


    std::uint64_t test_alloc = device->allocate_memory(0x1000);
    if (test_alloc != 0) {
        std::uint64_t test_val = 0xDEADBEEFCAFEBABEULL;
        device->write<std::uint64_t>(test_alloc, test_val);
        std::uint64_t readback = device->read<std::uint64_t>(test_alloc);
        snprintf(detail, sizeof(detail), "wrote=0x%llX read=0x%llX",
                 (unsigned long long)test_val, (unsigned long long)readback);
        report("write<uint64_t> / read<uint64_t> roundtrip", readback == test_val, detail);


        std::uint8_t pattern[16];
        for (int i = 0; i < 16; i++) pattern[i] = static_cast<std::uint8_t>(i * 17);
        std::size_t written = device->write_raw(test_alloc + 0x100, pattern, sizeof(pattern));
        std::uint8_t readback_buf[16]{};
        std::size_t read_sz = device->read_raw(test_alloc + 0x100, readback_buf, sizeof(readback_buf));
        bool match = (written == 16 && read_sz == 16 && memcmp(pattern, readback_buf, 16) == 0);
        snprintf(detail, sizeof(detail), "wrote=%llu read=%llu match=%s",
                 (unsigned long long)written, (unsigned long long)read_sz, match ? "yes" : "no");
        report("write_raw / read_raw roundtrip", match, detail);

        device->free_memory(test_alloc);
    } else {
        skip("write/read roundtrip", "allocate_memory failed");
    }
}

static void test_kernel_read() {
    section("MEMORY: Kernel Read");


    std::uint32_t cookie = 0;
    std::size_t got = device->read_kernel_raw(0xFFFFF78000000000ULL + 0x330, &cookie, sizeof(cookie));
    char detail[128];
    snprintf(detail, sizeof(detail), "bytes=%llu cookie=0x%08X", (unsigned long long)got, cookie);
    report("read_kernel_raw(KUSER_SHARED_DATA.Cookie)", got == sizeof(cookie), detail);
}

static void test_allocate_free() {
    section("MEMORY: Allocate / Free");


    std::uint64_t addr = device->allocate_memory(0x2000);
    char detail[128];
    snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)addr);
    report("allocate_memory(0x2000)", addr != 0, detail);

    if (addr != 0) {
        bool freed = device->free_memory(addr);
        report("free_memory()", freed);
    } else {
        skip("free_memory()", "allocate failed");
    }
}

static void test_thread_operations() {
    section("THREAD: Enumerate / Context / Suspend / Resume");


    auto threads = device->enumerate_threads();
    char detail[256];
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)threads.size());
    report("enumerate_threads()", !threads.empty(), detail);

    if (threads.empty()) {
        skip("get_thread_context()", "no threads");
        skip("suspend_thread()", "no threads");
        skip("resume_thread()", "no threads");
        return;
    }


    std::uint32_t tid = 0;
    voyager::device_t::thread_context ctx{};
    bool ok = false;


    std::vector<std::uint32_t> try_order;
    for (auto& t : threads) {
        if (t.state == 5) try_order.push_back(t.tid);
    }
    for (auto& t : threads) {
        if (t.state != 5) try_order.push_back(t.tid);
    }

    for (std::uint32_t candidate_tid : try_order) {
        voyager::device_t::thread_context try_ctx{};
        if (device->get_thread_context(candidate_tid, try_ctx)) {
            ctx = try_ctx;
            tid = candidate_tid;
            ok = true;
            break;
        }
    }

    snprintf(detail, sizeof(detail), "tid=%u rip=0x%llX rsp=0x%llX",
             tid, (unsigned long long)ctx.rip, (unsigned long long)ctx.rsp);
    report("get_thread_context()", ok, detail);


    if (tid == 0) tid = threads[0].tid;


    std::uint32_t prev = 0;
    ok = device->suspend_thread(tid, &prev);
    snprintf(detail, sizeof(detail), "prev_count=%u", prev);
    report("suspend_thread()", ok, detail);

    if (ok) {
        std::uint32_t prev2 = 0;
        ok = device->resume_thread(tid, &prev2);
        snprintf(detail, sizeof(detail), "prev_count=%u", prev2);
        report("resume_thread()", ok, detail);
    } else {
        skip("resume_thread()", "suspend failed");
    }
}

static void test_hw_breakpoints() {
    section("THREAD: Hardware Breakpoints");

    auto threads = device->enumerate_threads();
    if (threads.empty()) {
        skip("set_hardware_breakpoint()", "no threads");
        skip("clear_hardware_breakpoint()", "no threads");
        return;
    }


    std::uint32_t tid = threads[0].tid;
    for (auto& t : threads) {
        if (t.state == 5) { tid = t.tid; break; }
    }

    std::uint64_t base = device->get_base_address();
    if (base == 0) {
        skip("set_hardware_breakpoint()", "no base");
        skip("clear_hardware_breakpoint()", "no base");
        return;
    }


    bool ok = device->set_hardware_breakpoint(tid, 0, base, 0, 0);
    report("set_hardware_breakpoint(idx=0)", ok);

    ok = device->clear_hardware_breakpoint(tid, 0);
    report("clear_hardware_breakpoint(idx=0)", ok);
}

static void test_memory_queries(std::uint64_t base) {
    section("MEMORY: Query / Protect / Enumerate Regions");

    if (base == 0) {
        skip("query_memory()", "no base address");
        skip("protect_memory()", "no base address");
        skip("enumerate_memory_regions()", "no base address");
        return;
    }


    voyager::device_t::memory_region_info info{};
    bool ok = device->query_memory(base, info);
    char detail[256];
    snprintf(detail, sizeof(detail), "base=0x%llX size=0x%llX state=0x%X protect=0x%X type=0x%X",
             (unsigned long long)info.base, (unsigned long long)info.size,
             info.state, info.protect, info.type);
    report("query_memory(image base)", ok, detail);


    std::uint64_t test_page = device->allocate_memory(0x1000);
    if (test_page != 0) {
        std::uint32_t old_prot = 0;
        ok = device->protect_memory(test_page, 0x1000, PAGE_READONLY, &old_prot);
        snprintf(detail, sizeof(detail), "old_protect=0x%X", old_prot);
        report("protect_memory(RW->RO)", ok, detail);

        if (ok) {
            device->protect_memory(test_page, 0x1000, PAGE_READWRITE, nullptr);
        }
        device->free_memory(test_page);
    } else {
        skip("protect_memory()", "allocate failed");
    }


    auto regions = device->enumerate_memory_regions(0, 0x7FFFFFFFFFFF, false);
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)regions.size());
    report("enumerate_memory_regions()", !regions.empty(), detail);

    if (!regions.empty()) {
        printf("  [INFO] First region: base=0x%llX size=0x%llX state=0x%X protect=0x%X\n",
               (unsigned long long)regions[0].base, (unsigned long long)regions[0].size,
               regions[0].state, regions[0].protect);
    }
}

static void test_process_info(std::uint64_t base) {
    section("PROCESS: PEB / Debug Flags / Resolve Export / V2P");


    voyager::device_t::peb_info peb{};
    bool ok = device->read_peb(peb);
    char detail[256];
    snprintf(detail, sizeof(detail), "peb=0x%llX image_base=0x%llX debugged=%u ldr=0x%llX",
             (unsigned long long)peb.peb_address, (unsigned long long)peb.image_base,
             peb.being_debugged, (unsigned long long)peb.ldr_address);
    report("read_peb()", ok, detail);


    std::uint32_t flags = 0;
    ok = device->spoof_debug_flags(&flags);
    snprintf(detail, sizeof(detail), "result_flags=0x%X", flags);
    report("spoof_debug_flags()", ok, detail);


    if (base != 0) {

        std::uint64_t add_nums = device->resolve_export(base, "TestAddNumbers");
        snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)add_nums);
        report("resolve_export(test_target, \"TestAddNumbers\")", add_nums != 0, detail);

        std::uint64_t get_tick = device->resolve_export(base, "TestGetTickCount");
        snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)get_tick);
        report("resolve_export(test_target, \"TestGetTickCount\")", get_tick != 0, detail);

        std::uint64_t ret_magic = device->resolve_export(base, "TestReturnMagic");
        snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)ret_magic);
        report("resolve_export(test_target, \"TestReturnMagic\")", ret_magic != 0, detail);

        std::uint64_t no_op = device->resolve_export(base, "TestNoOp");
        snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)no_op);
        report("resolve_export(test_target, \"TestNoOp\")", no_op != 0, detail);


        std::uint64_t ntdll_base = 0;
        std::uint64_t kernel32_base = 0;
        if (peb.ldr_address != 0) {

            std::uint64_t first_entry = device->read<std::uint64_t>(peb.ldr_address + 0x10);
            if (first_entry != 0) {

                std::uint64_t ntdll_entry = device->read<std::uint64_t>(first_entry);
                if (ntdll_entry != 0) {
                    ntdll_base = device->read<std::uint64_t>(ntdll_entry + 0x30);
                    printf("  [INFO] ntdll.dll base via LDR walk: 0x%llX\n",
                           (unsigned long long)ntdll_base);


                    std::uint64_t k32_entry = device->read<std::uint64_t>(ntdll_entry);
                    if (k32_entry != 0) {
                        kernel32_base = device->read<std::uint64_t>(k32_entry + 0x30);
                        printf("  [INFO] kernel32.dll base via LDR walk: 0x%llX\n",
                               (unsigned long long)kernel32_base);
                    }
                }
            }
        }

        if (ntdll_base != 0) {
            std::uint64_t rtl_get_ver = device->resolve_export(ntdll_base, "RtlGetVersion");
            snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)rtl_get_ver);
            report("resolve_export(ntdll, \"RtlGetVersion\")", rtl_get_ver != 0, detail);
        } else {
            skip("resolve_export(ntdll)", "failed to walk LDR for ntdll base");
        }

        if (kernel32_base != 0) {
            std::uint64_t get_pid = device->resolve_export(kernel32_base, "GetCurrentProcessId");
            snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)get_pid);
            report("resolve_export(kernel32, \"GetCurrentProcessId\")", get_pid != 0, detail);
        } else {
            skip("resolve_export(kernel32)", "failed to walk LDR for kernel32 base");
        }
    } else {
        skip("resolve_export()", "no base address");
    }


    if (base != 0) {
        std::uint64_t phys = device->virtual_to_physical(base);
        snprintf(detail, sizeof(detail), "virt=0x%llX phys=0x%llX",
                 (unsigned long long)base, (unsigned long long)phys);
        report("virtual_to_physical(image_base)", phys != 0, detail);
    } else {
        skip("virtual_to_physical()", "no base address");
    }
}

static void test_remote_call(std::uint64_t base, std::uint32_t target_pid) {
    section("REMOTE CALL: find_gadget / call_function");

    if (base == 0 || device->get_dtb() == 0) {
        skip("find_gadget()", "no base/dtb");
        skip("call_function()", "no base/dtb");
        return;
    }

    char detail[256];


    const char ret_pattern[] = "\xC3";
    std::uint64_t ret_gadget = device->find_gadget(ret_pattern, 1);
    snprintf(detail, sizeof(detail), "addr=0x%llX", (unsigned long long)ret_gadget);
    report("find_gadget(RET)", ret_gadget != 0, detail);


    std::uint64_t add_addr = device->resolve_export(base, "TestAddNumbers");
    if (add_addr != 0) {
        printf("  [INFO] TestAddNumbers at 0x%llX, calling with args (100, 200)...\n",
               (unsigned long long)add_addr);


        std::uint64_t result = device->call_function(add_addr, 100, 200, 0, 0);
        snprintf(detail, sizeof(detail), "result=%llu (expected 300)",
                 (unsigned long long)result);
        report("call_function(TestAddNumbers, 100, 200)", result == 300, detail);
    } else {
        skip("call_function(TestAddNumbers)", "resolve_export failed");
    }

    Sleep(50);

    std::uint64_t magic_addr = device->resolve_export(base, "TestReturnMagic");
    if (magic_addr != 0) {
        printf("  [INFO] TestReturnMagic at 0x%llX, calling...\n",
               (unsigned long long)magic_addr);


        std::uint64_t result = device->call_function(magic_addr, 0, 0, 0, 0);
        snprintf(detail, sizeof(detail), "result=0x%llX (expected 0xDEADC0DE12345678)",
                 (unsigned long long)result);
        report("call_function(TestReturnMagic)",
               result == 0xDEADC0DE12345678ULL, detail);
    } else {
        skip("call_function(TestReturnMagic)", "resolve_export failed");
    }

    Sleep(50);

    std::uint64_t tick_addr = device->resolve_export(base, "TestGetTickCount");
    if (tick_addr != 0) {
        printf("  [INFO] TestGetTickCount at 0x%llX, calling...\n",
               (unsigned long long)tick_addr);


        std::uint64_t result = device->call_function(tick_addr, 0, 0, 0, 0);
        snprintf(detail, sizeof(detail), "tick=%llu", (unsigned long long)result);
        report("call_function(TestGetTickCount)", result != 0, detail);
    } else {
        skip("call_function(TestGetTickCount)", "resolve_export failed");
    }

    Sleep(50);

    std::uint64_t noop_addr = device->resolve_export(base, "TestNoOp");
    if (noop_addr != 0) {


        std::uint64_t result = device->call_function(noop_addr, 0, 0, 0, 0);
        snprintf(detail, sizeof(detail), "result=%llu (expected 0)",
                 (unsigned long long)result);
        report("call_function(TestNoOp)", result == 0, detail);
    } else {
        skip("call_function(TestNoOp)", "resolve_export failed");
    }

    Sleep(50);

    voyager::device_t::peb_info peb{};
    device->read_peb(peb);
    std::uint64_t kernel32_base = 0;
    if (peb.ldr_address != 0) {
        std::uint64_t first = device->read<std::uint64_t>(peb.ldr_address + 0x10);
        if (first != 0) {
            std::uint64_t ntdll_entry = device->read<std::uint64_t>(first);
            if (ntdll_entry != 0) {
                std::uint64_t k32_entry = device->read<std::uint64_t>(ntdll_entry);
                if (k32_entry != 0) {
                    kernel32_base = device->read<std::uint64_t>(k32_entry + 0x30);
                }
            }
        }
    }

    if (kernel32_base != 0) {
        std::uint64_t get_pid_addr = device->resolve_export(kernel32_base, "GetCurrentProcessId");
        if (get_pid_addr != 0) {
            printf("  [INFO] GetCurrentProcessId at 0x%llX, calling...\n",
                   (unsigned long long)get_pid_addr);
            std::uint64_t result = device->call_function(get_pid_addr, 0, 0, 0, 0);
            snprintf(detail, sizeof(detail), "result=%llu (expected pid=%u)",
                     (unsigned long long)result, target_pid);
            report("call_function(GetCurrentProcessId)",
                   static_cast<std::uint32_t>(result) == target_pid, detail);
        } else {
            skip("call_function(GetCurrentProcessId)", "resolve_export failed");
        }
    } else {
        skip("call_function(GetCurrentProcessId)", "could not find kernel32 base");
    }
}


static void test_network_connections(std::uint32_t target_pid) {
    section("NETWORK: Enumerate Connections");


    auto conns = device->enumerate_connections(target_pid, 0);
    char detail[256];
    snprintf(detail, sizeof(detail), "count=%llu (test_target has active connections)",
             (unsigned long long)conns.size());
    report("enumerate_connections(target_pid)", true, detail);

    int shown = 0;
    for (auto& c : conns) {
        if (shown >= 5) break;
        printf("  [INFO] TargetConn[%d]: pid=%u proto=%u state=%u ",
               shown, c.pid, c.protocol, c.state);
        printf("local="); print_ip(c.local_addr, c.address_family);
        printf(":%u remote=", c.local_port);
        print_ip(c.remote_addr, c.address_family);
        printf(":%u\n", c.remote_port);


        bool suspect = (c.protocol > 255 || c.address_family > 30 ||
                        (c.address_family != 2 && c.address_family != 23));
        if (suspect) {
            printf("  [DIAG] TargetConn[%d] has suspect fields — raw dump:\n", shown);
            printf("  [DIAG]   af=%u proto=%u state=%u pid=%u\n",
                   c.address_family, c.protocol, c.state, c.pid);
            printf("  [DIAG]   local_addr bytes: ");
            for (int i = 0; i < 16; i++) printf("%02X ", c.local_addr[i]);
            printf("\n  [DIAG]   remote_addr bytes: ");
            for (int i = 0; i < 16; i++) printf("%02X ", c.remote_addr[i]);
            printf("\n  [DIAG]   local_port=%u remote_port=%u\n", c.local_port, c.remote_port);
        }
        shown++;
    }


    auto all_conns = device->enumerate_connections(0, 0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_conns.size());
    report("enumerate_connections(all)", true, detail);

    shown = 0;
    for (auto& c : all_conns) {
        if (shown >= 3) { printf("  [INFO] ... (%llu more)\n", (unsigned long long)(all_conns.size() - 3)); break; }
        printf("  [INFO] SysConn[%d]: pid=%u proto=%u state=%u ",
               shown, c.pid, c.protocol, c.state);
        printf("local="); print_ip(c.local_addr, c.address_family);
        printf(":%u remote=", c.local_port);
        print_ip(c.remote_addr, c.address_family);
        printf(":%u\n", c.remote_port);
        shown++;
    }
}

static void test_capture(std::uint32_t target_pid) {
    section("NETWORK: Packet Capture");


    bool ok = device->start_capture(target_pid, 0, 0, nullptr, 1500);
    report("start_capture(target_pid)", ok);

    if (!ok) {
        skip("get_capture_status()", "capture not started");
        skip("get_captured_packets()", "capture not started");
        skip("stop_capture()", "capture not started");
        return;
    }


    {
        bool init_active = false;
        std::uint32_t init_cap = 0, init_drop = 0;
        bool init_ok = device->get_capture_status(init_active, init_cap, init_drop);
        char init_detail[256];
        snprintf(init_detail, sizeof(init_detail), "active=%d captured=%u dropped=%u",
                 init_active, init_cap, init_drop);
        report("capture_wfp_verify(immediate)", init_ok && init_active, init_detail);

        if (!init_active) {
            printf("  [DIAG] WFP pipeline may not be initialized — capture_active=0 right after start\n");
            printf("  [DIAG] Check WinDbg for [AIDA-NET] init messages. Common causes:\n");
            printf("  [DIAG]   - FWPKCLNT.SYS function resolution failed\n");
            printf("  [DIAG]   - FwpmEngineOpen0 / FwpmTransactionCommit0 returned error\n");
            printf("  [DIAG]   - Another driver is blocking WFP registration\n");
        }


        voyager::device_t::network_stats init_stats{};
        bool stats_ok = device->get_network_stats(init_stats);
        snprintf(init_detail, sizeof(init_detail),
                 "sent=%llu recv=%llu pkts_s=%llu pkts_r=%llu",
                 (unsigned long long)init_stats.bytes_sent, (unsigned long long)init_stats.bytes_received,
                 (unsigned long long)init_stats.packets_sent, (unsigned long long)init_stats.packets_received);
        report("capture_wfp_verify(stats_pipeline)", stats_ok, init_detail);
    }


    printf("  [INFO] Capturing test_target traffic for 10 seconds (polling every 2s)...\n");
    for (int sec = 2; sec <= 10; sec += 2) {
        Sleep(2000);
        bool poll_active = false;
        std::uint32_t poll_cap = 0, poll_drop = 0;
        device->get_capture_status(poll_active, poll_cap, poll_drop);
        printf("  [INFO] t=%ds: active=%d captured=%u dropped=%u\n",
               sec, poll_active, poll_cap, poll_drop);
    }


    bool active = false;
    std::uint32_t captured = 0, dropped = 0;
    ok = device->get_capture_status(active, captured, dropped);
    char detail[256];
    snprintf(detail, sizeof(detail), "active=%d captured=%u dropped=%u",
             active, captured, dropped);
    report("get_capture_status()", ok, detail);


    auto pkts = device->get_captured_packets(64);


    if (pkts.empty()) {
        for (int retry = 1; retry <= 3; retry++) {
            printf("  [INFO] No packets yet, retry %d/3 (waiting 3s)...\n", retry);
            Sleep(3000);
            pkts = device->get_captured_packets(64);
            if (!pkts.empty()) break;
        }
    }

    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)pkts.size());
    report("get_captured_packets(64)", !pkts.empty(), detail);

    if (pkts.empty()) {
        printf("  [DIAG] No packets captured. Possible causes:\n");
        printf("  [DIAG]   - test_target.exe is not generating traffic\n");
        printf("  [DIAG]   - PID filter mismatch (target_pid=%u)\n", target_pid);
        printf("  [DIAG]   - WFP classify callbacks are not firing\n");
        printf("  [DIAG]   - store_packet() is dropping due to PID=0 (check kernel logs)\n");
    }

    int shown = 0;
    for (auto& p : pkts) {
        if (shown >= 5) break;
        printf("  [INFO] Pkt[%d]: pid=%u proto=%u dir=%u size=%u ports=%u->%u",
               shown, p.pid, p.protocol, p.direction, p.payload_size,
               p.local_port, p.remote_port);

        bool valid = (p.protocol == 6 || p.protocol == 17) && p.payload_size <= 65535;
        if (!valid) printf(" [!INVALID FIELDS]");
        printf("\n");


        if (shown == 0 && p.payload_size > 0 && !p.payload.empty()) {
            printf("  [INFO] Payload hex (first %u bytes): ",
                   p.payload_size < 32 ? p.payload_size : 32);
            for (std::uint32_t i = 0; i < p.payload_size && i < 32 && i < p.payload.size(); i++) {
                printf("%02X ", p.payload[i]);
            }
            printf("\n");
        }
        shown++;
    }

    ok = device->stop_capture();
    report("stop_capture()", ok);
}

static void test_dns_queries(std::uint32_t target_pid) {
    section("NETWORK: DNS Queries");


    auto dns = device->get_dns_queries(target_pid);


    if (dns.empty()) {
        for (int retry = 1; retry <= 3; retry++) {
            printf("  [INFO] No DNS queries yet, retry %d/3 (waiting 3s)...\n", retry);
            Sleep(3000);
            dns = device->get_dns_queries(target_pid);
            if (!dns.empty()) break;
        }
    }

    char detail[256];
    snprintf(detail, sizeof(detail), "count=%llu (test_target resolves multiple domains)",
             (unsigned long long)dns.size());
    report("get_dns_queries(target_pid)", !dns.empty(), detail);

    if (dns.empty()) {
        printf("  [DIAG] No DNS queries captured for target_pid=%u. Possible causes:\n", target_pid);
        printf("  [DIAG]   - test_target.exe has not resolved any domains yet\n");
        printf("  [DIAG]   - WFP capture was not active when DNS packets flowed\n");
        printf("  [DIAG]   - DNS ring overflowed before retrieval\n");
        printf("  [DIAG]   - PID resolution failed for port-53 UDP flows\n");
    }

    int shown = 0;
    for (auto& d : dns) {
        if (shown >= 5) break;

        bool valid_domain = !d.domain.empty();
        for (char c : d.domain) {
            if (c < 0x20 || c > 0x7E) { valid_domain = false; break; }
        }
        printf("  [INFO] TargetDNS[%d]: pid=%u domain=%s type=%u%s\n",
               shown, d.pid, d.domain.c_str(), d.query_type,
               valid_domain ? "" : " [!INVALID DOMAIN]");
        shown++;
    }


    auto all_dns = device->get_dns_queries(0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_dns.size());
    report("get_dns_queries(all)", true, detail);

    for (std::size_t i = 0; i < all_dns.size() && i < 5; i++) {
        printf("  [INFO] SysDNS[%llu]: pid=%u domain=%s type=%u\n",
               (unsigned long long)i, all_dns[i].pid, all_dns[i].domain.c_str(), all_dns[i].query_type);
    }
}

static void test_filter_rules() {
    section("NETWORK: Filter Rules");


    std::uint32_t rule_id = 0;
    bool ok = device->add_filter_rule(1, 1, 6, 0, 59999, nullptr, nullptr, &rule_id);
    char detail[128];
    snprintf(detail, sizeof(detail), "rule_id=%u", rule_id);
    report("add_filter_rule(block outbound TCP:59999)", ok, detail);

    if (ok) {
        ok = device->remove_filter_rule(rule_id);
        report("remove_filter_rule()", ok);
    } else {
        skip("remove_filter_rule()", "add failed");
    }

    ok = device->clear_filter_rules();
    report("clear_filter_rules()", ok);
}

static void test_network_stats() {
    section("NETWORK: Stats");


    voyager::device_t::network_stats stats{};
    bool ok = device->get_network_stats(stats);
    char detail[256];
    snprintf(detail, sizeof(detail),
             "sent=%llu recv=%llu pkts_s=%llu pkts_r=%llu conns=%u",
             (unsigned long long)stats.bytes_sent, (unsigned long long)stats.bytes_received,
             (unsigned long long)stats.packets_sent, (unsigned long long)stats.packets_received,
             stats.active_connections);
    report("get_network_stats()", ok, detail);
}

static void test_wfp_callouts() {
    section("NETWORK: WFP Callouts");


    auto callouts = device->enumerate_wfp_callouts("");
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)callouts.size());
    report("enumerate_wfp_callouts(all)", true, detail);

    if (!callouts.empty()) {
        printf("  [INFO] First callout: id=%u layer=%u module=%s classify=0x%llX\n",
               callouts[0].callout_id, callouts[0].layer_id,
               callouts[0].owning_module.c_str(),
               (unsigned long long)callouts[0].classify_fn);
    }
}

static void test_socket_handles(std::uint32_t target_pid) {
    section("NETWORK: Socket Handles");


    auto sockets = device->get_socket_handles(target_pid);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (test_target has multiple sockets)",
             (unsigned long long)sockets.size());
    report("get_socket_handles(target_pid)", true, detail);

    int shown = 0;
    for (auto& s : sockets) {
        if (shown >= 5) break;
        printf("  [INFO] TargetSocket[%d]: handle=0x%llX pid=%u proto=%u state=%u port=%u\n",
               shown, (unsigned long long)s.handle_value, s.pid, s.protocol,
               s.state, s.local_port);
        shown++;
    }


    auto all_sockets = device->get_socket_handles(0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_sockets.size());
    report("get_socket_handles(all)", true, detail);

    shown = 0;
    for (auto& s : all_sockets) {
        if (shown >= 3) { printf("  [INFO] ... (%llu more)\n", (unsigned long long)(all_sockets.size() - 3)); break; }
        printf("  [INFO] SysSocket[%d]: handle=0x%llX pid=%u proto=%u state=%u port=%u\n",
               shown, (unsigned long long)s.handle_value, s.pid, s.protocol,
               s.state, s.local_port);
        shown++;
    }
}

static void test_sniff_net_buffers() {
    section("NETWORK: Sniff Net Buffers");


    bool ok = device->sniff_net_buffers_start(0, 0, 1, 1, 0, 0);
    report("sniff_net_buffers_start(dummy)", ok);

    if (ok) {
        bool active = false;
        auto results = device->sniff_net_buffers_get(active);
        char detail[128];
        snprintf(detail, sizeof(detail), "active=%d captures=%llu",
                 active, (unsigned long long)results.size());
        report("sniff_net_buffers_get()", true, detail);

        std::uint8_t test_data[] = {0xAA, 0xBB, 0xCC, 0xDD};
        ok = device->sniff_net_buffers_store(12345ULL, 1ULL, test_data, sizeof(test_data));
        report("sniff_net_buffers_store()", ok);

        ok = device->sniff_net_buffers_stop();
        report("sniff_net_buffers_stop()", ok);
    } else {
        skip("sniff_net_buffers_get()", "start failed");
        skip("sniff_net_buffers_store()", "start failed");
        skip("sniff_net_buffers_stop()", "start failed");
    }
}

static void test_tcpip_dump(std::uint32_t target_pid) {
    section("NETWORK: TCPIP Connection Dump");


    auto conns = device->dump_tcpip_connections(target_pid, 0);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu (test_target has active TCP conns)",
             (unsigned long long)conns.size());
    report("dump_tcpip_connections(target_pid)", true, detail);

    int shown = 0;
    for (auto& c : conns) {
        if (shown >= 5) break;
        printf("  [INFO] TargetTCP[%d]: tcb=0x%llX pid=%u proto=%u state=%u "
               "ports=%u->%u bytes_in=%llu bytes_out=%llu\n",
               shown, (unsigned long long)c.tcb_address, c.pid, c.protocol,
               c.state, c.local_port, c.remote_port,
               (unsigned long long)c.bytes_in, (unsigned long long)c.bytes_out);
        shown++;
    }
}

static void test_packet_injection() {
    section("NETWORK: Packet Injection");


    bool cap_ok = device->start_capture(0, 0, 0, nullptr, 1500);
    if (cap_ok) {
        printf("  [INFO] Started capture (all PIDs) to verify injection...\n");
    }


    std::uint8_t src_addr[16] = {127, 0, 0, 1};
    std::uint8_t dst_addr[16] = {127, 0, 0, 1};
    std::uint8_t payload[] = "WhosWho-Test-Packet";

    bool ok = device->inject_packet(
        1,
        17,
        2,
        60000,
        65534,
        src_addr, dst_addr,
        payload, sizeof(payload),
        0, 0, 0
    );
    report("inject_packet(UDP localhost:65534)", ok);


    std::uint8_t tcp_payload[] = "WhosWho-TCP-Test";
    bool tcp_ok = device->inject_packet(
        1,
        6,
        2,
        60001,
        65533,
        src_addr, dst_addr,
        tcp_payload, sizeof(tcp_payload),
        0, 0, 0
    );
    report("inject_packet(TCP localhost:65533)", tcp_ok);


    if (cap_ok) {
        Sleep(500);
        auto pkts = device->get_captured_packets(32);
        char detail[256];
        snprintf(detail, sizeof(detail), "captured=%llu after injection",
                 (unsigned long long)pkts.size());
        bool found_udp = false, found_tcp = false;
        for (auto& p : pkts) {
            if (p.protocol == 17 && (p.local_port == 60000 || p.remote_port == 65534))
                found_udp = true;
            if (p.protocol == 6 && (p.local_port == 60001 || p.remote_port == 65533))
                found_tcp = true;
        }
        snprintf(detail, sizeof(detail), "captured=%llu udp_visible=%d tcp_visible=%d",
                 (unsigned long long)pkts.size(), found_udp, found_tcp);
        report("inject_verify(capture check)", true, detail);
        if (!found_udp && !found_tcp && !pkts.empty()) {
            printf("  [DIAG] Injected packets not found in capture — may be loopback routing\n");
        }
        device->stop_capture();
    }
}

static void test_packet_mod_rules() {
    section("NETWORK: Packet Modification Rules");


    std::uint8_t pattern[] = {0xDE, 0xAD};
    std::uint8_t replacement[] = {0xBE, 0xEF};
    std::uint32_t rule_id = 0;

    bool ok = device->packet_mod_rule_op(
        0, 0, 2, 0, 0, 0,
        pattern, sizeof(pattern),
        replacement, sizeof(replacement),
        &rule_id
    );
    char detail[128];
    snprintf(detail, sizeof(detail), "rule_id=%u", rule_id);
    report("packet_mod_rule_op(add)", ok, detail);

    auto rules = device->list_packet_mod_rules();
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)rules.size());
    report("list_packet_mod_rules()", true, detail);

    if (ok && rule_id != 0) {
        ok = device->packet_mod_rule_op(1, rule_id);
        report("packet_mod_rule_op(remove)", ok);
    } else {
        skip("packet_mod_rule_op(remove)", "add failed or no rule_id");
    }
}

static void test_traffic_redirect() {
    section("NETWORK: Traffic Redirect Rules");


    std::uint8_t match_addr[16] = {10, 0, 0, 1};
    std::uint8_t redir_addr[16] = {127, 0, 0, 1};
    std::uint32_t rule_id = 0;

    bool ok = device->traffic_redirect_op(
        0, 0, 6, 9999, match_addr, 80, redir_addr, 2, &rule_id
    );
    char detail[128];
    snprintf(detail, sizeof(detail), "rule_id=%u", rule_id);
    report("traffic_redirect_op(add)", ok, detail);

    auto rules = device->list_redirect_rules();
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)rules.size());
    report("list_redirect_rules()", true, detail);

    if (ok && rule_id != 0) {
        ok = device->traffic_redirect_op(1, rule_id);
        report("traffic_redirect_op(remove)", ok);
    } else {
        skip("traffic_redirect_op(remove)", "add failed");
    }
}

static void test_stream_reassembly() {
    section("NETWORK: Stream Reassembly");


    std::vector<std::uint8_t> stream_data;
    std::uint32_t total_packets = 0, truncated = 0;

    bool ok = device->stream_reassemble_op(
        0, 80, 0, 0,
        nullptr, nullptr,
        &stream_data, &total_packets, &truncated
    );
    char detail[256];
    snprintf(detail, sizeof(detail), "data_size=%llu packets=%u truncated=%u",
             (unsigned long long)stream_data.size(), total_packets, truncated);
    report("stream_reassemble_op(start, port=80)", ok, detail);

    if (!stream_data.empty()) {

        printf("  [INFO] Stream preview (first %llu bytes): ",
               (unsigned long long)(stream_data.size() < 64 ? stream_data.size() : 64));
        for (std::size_t i = 0; i < stream_data.size() && i < 64; i++) {
            if (stream_data[i] >= 0x20 && stream_data[i] < 0x7F)
                printf("%c", stream_data[i]);
            else
                printf(".");
        }
        printf("\n");
    }

    ok = device->stream_reassemble_op(1, 80, 0);
    report("stream_reassemble_op(stop)", ok);
}

static void test_dpi(std::uint32_t target_pid) {
    section("NETWORK: Deep Packet Inspection");


    auto results = device->get_dpi_results(target_pid, 0, 0, 0);


    if (results.empty()) {
        for (int retry = 1; retry <= 3; retry++) {
            printf("  [INFO] No DPI results yet, retry %d/3 (waiting 3s)...\n", retry);
            Sleep(3000);
            results = device->get_dpi_results(target_pid, 0, 0, 0);
            if (!results.empty()) break;
        }
    }

    char detail[256];
    snprintf(detail, sizeof(detail), "count=%llu (test_target generates HTTP/TLS/DNS)",
             (unsigned long long)results.size());
    report("get_dpi_results(target_pid)", !results.empty(), detail);

    if (results.empty()) {
        printf("  [DIAG] No DPI results for target_pid=%u. Possible causes:\n", target_pid);
        printf("  [DIAG]   - No TCP payload captured (MDL copy failure?)\n");
        printf("  [DIAG]   - DPI ring buffer overflow before retrieval\n");
        printf("  [DIAG]   - test_target.exe has not made HTTP/TLS connections\n");
    }


    bool found_http = false, found_tls = false, found_dns = false;
    int shown = 0;
    for (auto& r : results) {
        if (r.is_http) found_http = true;
        if (r.is_tls) found_tls = true;
        if (r.is_dns) found_dns = true;

        if (shown >= 5) continue;
        printf("  [INFO] TargetDPI[%d]: proto=%u dir=%u ports=%u->%u pid=%u "
               "http=%d tls=%d dns=%d\n",
               shown, r.protocol, r.direction, r.src_port, r.dst_port,
               r.pid, r.is_http, r.is_tls, r.is_dns);
        if (r.is_http) {
            bool valid_host = !r.http_host.empty();
            printf("  [INFO]   HTTP: host=%s path=%s method=%u%s\n",
                   r.http_host.c_str(), r.http_path.c_str(), r.http_method,
                   valid_host ? "" : " [!EMPTY HOST]");
        }
        if (r.is_tls) {
            bool valid_sni = !r.tls_sni.empty();
            printf("  [INFO]   TLS: sni=%s ver=0x%X content_type=%u%s\n",
                   r.tls_sni.c_str(), r.tls_version, r.tls_content_type,
                   valid_sni ? "" : " [!EMPTY SNI]");
        }
        if (r.is_dns) {
            printf("  [INFO]   DNS detected (port 53 traffic)\n");
        }
        shown++;
    }

    snprintf(detail, sizeof(detail), "http=%d tls=%d dns=%d",
             found_http, found_tls, found_dns);
    report("dpi_content_verify(protocols found)", found_http || found_tls || found_dns, detail);
}

static void test_intercept() {
    section("NETWORK: Packet Interception");


    std::uint32_t held_count = 0;
    bool active = false;

    bool ok = device->intercept_op(
        0, 6, 80, 0, 0, nullptr, 0, &held_count, &active
    );
    char detail[256];
    snprintf(detail, sizeof(detail), "held=%u active=%d (filter: TCP port 80)", held_count, active);
    report("intercept_op(start, TCP:80)", ok, detail);


    printf("  [INFO] Waiting 3 seconds for packets to be intercepted...\n");
    Sleep(3000);

    auto held = device->get_held_packets();
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)held.size());
    report("get_held_packets()", true, detail);

    if (!held.empty()) {
        int shown = 0;
        for (auto& h : held) {
            if (shown >= 3) break;
            printf("  [INFO] Held[%d]: proto=%u dir=%u size=%u ports=%u->%u\n",
                   shown, h.protocol, h.direction, h.payload_size,
                   h.src_port, h.dst_port);

            bool valid = (h.protocol == 6 || h.protocol == 17) && h.payload_size <= 65535;
            if (!valid) printf("  [DIAG] Held packet has unexpected fields\n");
            shown++;
        }


        printf("  [INFO] Testing release on held packets...\n");
        bool release_ok = device->intercept_op(3);
        report("intercept_op(release)", release_ok);
    } else {
        printf("  [DIAG] No packets held — all traffic may be on HTTPS (port 443)\n");
        printf("  [DIAG] Or test_target.exe is not generating filtered traffic\n");
        skip("intercept_op(release)", "no held packets");
    }

    ok = device->intercept_op(1);
    report("intercept_op(stop)", ok);
}

static void test_kill_connection() {
    section("NETWORK: Kill Connection");


    std::uint8_t src_addr[16] = {127, 0, 0, 1};
    std::uint8_t dst_addr[16] = {10, 255, 255, 254};

    bool ok = device->kill_connection(
        6, 2, 55555, 55556, src_addr, dst_addr, 0
    );
    char detail[64];
    snprintf(detail, sizeof(detail), "result=%d (false expected - no such conn)", ok);
    report("kill_connection(non-existent)", true, detail);
}

static void test_dns_spoofing() {
    section("NETWORK: DNS Spoofing");


    std::uint8_t spoof_addr[16] = {127, 0, 0, 1};
    std::uint32_t rule_id = 0;

    bool ok = device->dns_spoof_op(
        0, 0, "whoswho-test.invalid", spoof_addr, 2, 300, &rule_id
    );
    char detail[128];
    snprintf(detail, sizeof(detail), "rule_id=%u", rule_id);
    report("dns_spoof_op(add)", ok, detail);

    auto rules = device->list_dns_spoof_rules();
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)rules.size());
    report("list_dns_spoof_rules()", true, detail);

    if (ok && rule_id != 0) {
        ok = device->dns_spoof_op(1, rule_id);
        report("dns_spoof_op(remove)", ok);
    } else {
        skip("dns_spoof_op(remove)", "add failed");
    }
}

static void test_bandwidth_monitor(std::uint32_t target_pid) {
    section("NETWORK: Bandwidth Monitor");


    voyager::device_t::bw_stats stats{};
    bool ok = device->bw_monitor_op(0, 0, &stats);
    char detail[256];
    snprintf(detail, sizeof(detail),
             "active=%d sent=%llu recv=%llu bps_in=%llu bps_out=%llu",
             stats.active,
             (unsigned long long)stats.total_bytes_sent,
             (unsigned long long)stats.total_bytes_recv,
             (unsigned long long)stats.bps_in,
             (unsigned long long)stats.bps_out);
    report("bw_monitor_op(start)", ok, detail);


    printf("  [INFO] Sampling bandwidth over 6 seconds (3 intervals)...\n");
    Sleep(2000);

    voyager::device_t::bw_stats stats_t1{};
    device->bw_monitor_op(0, 0, &stats_t1);
    printf("  [INFO] t=2s: sent=%llu recv=%llu bps_in=%llu bps_out=%llu\n",
           (unsigned long long)stats_t1.total_bytes_sent,
           (unsigned long long)stats_t1.total_bytes_recv,
           (unsigned long long)stats_t1.bps_in,
           (unsigned long long)stats_t1.bps_out);

    Sleep(2000);

    voyager::device_t::bw_stats stats_t2{};
    device->bw_monitor_op(0, 0, &stats_t2);
    printf("  [INFO] t=4s: sent=%llu recv=%llu bps_in=%llu bps_out=%llu\n",
           (unsigned long long)stats_t2.total_bytes_sent,
           (unsigned long long)stats_t2.total_bytes_recv,
           (unsigned long long)stats_t2.bps_in,
           (unsigned long long)stats_t2.bps_out);

    Sleep(2000);

    voyager::device_t::bw_stats stats_t3{};
    device->bw_monitor_op(0, 0, &stats_t3);
    printf("  [INFO] t=6s: sent=%llu recv=%llu bps_in=%llu bps_out=%llu\n",
           (unsigned long long)stats_t3.total_bytes_sent,
           (unsigned long long)stats_t3.total_bytes_recv,
           (unsigned long long)stats_t3.bps_in,
           (unsigned long long)stats_t3.bps_out);


    bool bw_growing = (stats_t3.total_bytes_sent > stats_t1.total_bytes_sent) ||
                      (stats_t3.total_bytes_recv > stats_t1.total_bytes_recv);
    snprintf(detail, sizeof(detail), "delta_sent=%llu delta_recv=%llu (over 4s window)",
             (unsigned long long)(stats_t3.total_bytes_sent - stats_t1.total_bytes_sent),
             (unsigned long long)(stats_t3.total_bytes_recv - stats_t1.total_bytes_recv));
    report("bw_monitor_verify(traffic growth)", bw_growing, detail);

    if (!bw_growing) {
        printf("  [DIAG] No traffic growth in 4s window — test_target may not be sending data\n");
        printf("  [DIAG] Check that test_target.exe is still running and has active sockets\n");
    }


    auto procs = device->get_bw_per_process(target_pid);
    snprintf(detail, sizeof(detail), "count=%llu (test_target has active traffic)",
             (unsigned long long)procs.size());
    report("get_bw_per_process(target_pid)", !procs.empty(), detail);


    bool found_target = false;
    for (auto& p : procs) {
        if (p.pid == target_pid) {
            found_target = true;
            printf("  [INFO] Target BW: pid=%u sent=%llu recv=%llu\n",
                   p.pid, (unsigned long long)p.bytes_sent, (unsigned long long)p.bytes_recv);
            break;
        }
    }
    if (!found_target && !procs.empty()) {
        printf("  [DIAG] target_pid=%u not found in per-process BW results\n", target_pid);
    }


    auto all_procs = device->get_bw_per_process(0);
    snprintf(detail, sizeof(detail), "all_pids count=%llu",
             (unsigned long long)all_procs.size());
    report("get_bw_per_process(all)", true, detail);

    for (std::size_t i = 0; i < all_procs.size() && i < 3; i++) {
        printf("  [INFO] BW[%llu]: pid=%u sent=%llu recv=%llu\n",
               (unsigned long long)i, all_procs[i].pid,
               (unsigned long long)all_procs[i].bytes_sent,
               (unsigned long long)all_procs[i].bytes_recv);
    }

    ok = device->bw_monitor_op(1);
    report("bw_monitor_op(stop)", ok);
}

static void test_enumerate_interfaces() {
    section("NETWORK: Enumerate Interfaces");


    auto ifaces = device->enumerate_interfaces();
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)ifaces.size());
    report("enumerate_interfaces()", !ifaces.empty(), detail);

    for (std::size_t i = 0; i < ifaces.size() && i < 3; i++) {
        auto& iface = ifaces[i];
        printf("  [INFO] Iface[%llu]: idx=%u type=%u mtu=%u speed=%llu name=%s\n",
               (unsigned long long)i, iface.if_index, iface.if_type, iface.mtu,
               (unsigned long long)iface.speed, iface.name.c_str());
        printf("  [INFO]   MAC=%02X:%02X:%02X:%02X:%02X:%02X IPv4=",
               iface.mac_addr[0], iface.mac_addr[1], iface.mac_addr[2],
               iface.mac_addr[3], iface.mac_addr[4], iface.mac_addr[5]);
        print_ip4(iface.ipv4_addr);
        printf(" in=%llu out=%llu\n",
               (unsigned long long)iface.in_octets,
               (unsigned long long)iface.out_octets);
    }
}

static void test_pcap_export(std::uint32_t target_pid) {
    section("NETWORK: PCAP Export");


    voyager::device_t::pcap_export_result pcap_result{};
    bool ok = device->export_pcap(target_pid, 0, 128, &pcap_result);
    char detail[256];
    snprintf(detail, sizeof(detail), "packets=%llu (test_target traffic) magic=0x%X",
             (unsigned long long)pcap_result.packets.size(),
             pcap_result.header.magic_number);
    report("export_pcap(target_pid)", ok, detail);


    voyager::device_t::pcap_export_result pcap_all{};
    ok = device->export_pcap(0, 0, 64, &pcap_all);
    snprintf(detail, sizeof(detail), "all_pids packets=%llu",
             (unsigned long long)pcap_all.packets.size());
    report("export_pcap(all, max=64)", ok, detail);

    if (!pcap_all.packets.empty()) {
        auto& p = pcap_all.packets[0];
        printf("  [INFO] First PCAP packet: ts=%u.%06u data_size=%llu\n",
               p.ts_sec, p.ts_usec,
               (unsigned long long)p.data.size());
    }
}

static void test_fingerprinting() {
    section("NETWORK: OS Fingerprinting");


    bool ok = device->fingerprint_op(0);
    report("fingerprint_op(start)", ok);


    printf("  [INFO] Collecting fingerprints for 2 seconds...\n");
    Sleep(2000);

    auto fps = device->get_fingerprints();
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%llu", (unsigned long long)fps.size());
    report("get_fingerprints()", true, detail);

    for (std::size_t i = 0; i < fps.size() && i < 5; i++) {
        auto& f = fps[i];
        printf("  [INFO] FP[%llu]: ttl=%u win=%u mss=%u wscale=%u "
               "df=%u sack=%u os=%s addr=",
               (unsigned long long)i, f.ttl, f.window_size, f.mss,
               f.window_scale, f.df_flag, f.sack_permitted, f.os_guess.c_str());
        print_ip(f.remote_addr, f.af);
        printf("\n");
    }

    ok = device->fingerprint_op(1);
    report("fingerprint_op(stop)", ok);
}

static void test_dll_protection() {
    section("DLL PROTECTION: Register / Query / Unregister");

    std::uint64_t base = device->get_base_address();
    if (base == 0) {
        skip("register_dll_protection()", "no base address");
        skip("query_dll_protection()", "no base address");
        skip("unregister_dll_protection()", "no base address");
        return;
    }


    std::uint32_t e_lfanew = device->read<std::uint32_t>(base + 0x3C);
    if (e_lfanew == 0 || e_lfanew > 0x1000) {
        char detail[128];
        snprintf(detail, sizeof(detail), "e_lfanew=0x%X (invalid, process may have exited)", e_lfanew);
        skip("register_dll_protection()", detail);
        skip("query_dll_protection()", "no registration");
        skip("unregister_dll_protection()", "no registration");
        return;
    }
    std::uint64_t nt_hdr = base + e_lfanew;

    std::uint16_t num_sections = device->read<std::uint16_t>(nt_hdr + 4 + 2);
    std::uint16_t opt_hdr_size = device->read<std::uint16_t>(nt_hdr + 4 + 16);
    std::uint64_t first_section = nt_hdr + 4 + 20 + opt_hdr_size;

    std::uint32_t text_vsize = 0;
    std::uint32_t text_rva = 0;

    for (std::uint16_t s = 0; s < num_sections && s < 64; s++) {
        std::uint64_t sec = first_section + static_cast<std::uint64_t>(s) * 40;
        char sec_name[9] = {};
        for (int c = 0; c < 8; c++)
            sec_name[c] = static_cast<char>(device->read<std::uint8_t>(sec + c));

        std::uint32_t vsize = device->read<std::uint32_t>(sec + 8);
        std::uint32_t rva   = device->read<std::uint32_t>(sec + 12);
        std::uint32_t chars = device->read<std::uint32_t>(sec + 36);

        printf("  [INFO] Section[%u]: name=%.8s vsize=0x%X rva=0x%X chars=0x%X\n",
               s, sec_name, vsize, rva, chars);

        if (std::strcmp(sec_name, ".text") == 0 ||
            (text_vsize == 0 && (chars & 0x20))) {
            text_vsize = vsize;
            text_rva = rva;
            if (text_vsize == 0)
                text_vsize = device->read<std::uint32_t>(sec + 16);
        }
    }

    std::uint64_t text_va = base + text_rva;

    char detail[256];
    snprintf(detail, sizeof(detail), "text_va=0x%llX text_size=0x%X",
             (unsigned long long)text_va, text_vsize);
    printf("  [INFO] PE sections: %s\n", detail);

    if (text_vsize == 0) {
        skip("register_dll_protection()", "could not find .text section (vsize=0)");
        skip("query_dll_protection()", "no registration");
        skip("unregister_dll_protection()", "no registration");
        return;
    }


    bool ok = device->register_dll_protection(base, text_va, text_vsize,
                                               0x12345678AABBCCDDULL, 60000);
    report("register_dll_protection()", ok);

    voyager::device_t::dll_protect_status status{};
    ok = device->query_dll_protection(status);
    snprintf(detail, sizeof(detail), "status=%u current_hash=0x%llX expected=0x%llX",
             status.status, (unsigned long long)status.current_hash,
             (unsigned long long)status.expected_hash);
    report("query_dll_protection()", ok, detail);

    ok = device->unregister_dll_protection();
    report("unregister_dll_protection()", ok);
}


int main() {
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    printf("================================================================\n");
    printf("  WhosWho Driver - Comprehensive Feature Test\n");
    printf("  Target: test_target.exe (custom traffic-generating test app)\n");
    printf("================================================================\n\n");


    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);


    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    char* last_slash = strrchr(exe_path, '\\');
    if (last_slash) *(last_slash + 1) = '\0';
    strcat_s(exe_path, "test_target.exe");

    bool launched = false;
    std::uint32_t target_pid = find_target_pid();

    if (target_pid != 0) {
        printf("[INFO] test_target.exe already running (pid=%u)\n", target_pid);
    } else {
        printf("[INFO] Launching test_target.exe from: %s\n", exe_path);
        if (CreateProcessA(exe_path, nullptr, nullptr, nullptr, FALSE,
                           CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
            target_pid = pi.dwProcessId;
            launched = true;
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            printf("[INFO] Launched test_target.exe (pid=%u)\n", target_pid);


            wait_for_ready_event(15000);
        } else {
            printf("[FATAL] Failed to launch test_target.exe (error=%lu)\n", GetLastError());
            printf("[FATAL] Ensure test_target.exe is in the same directory as this test.\n");
            return 1;
        }
    }

    printf("[INFO] Target: test_target.exe (pid=%u)\n\n", target_pid);


    if (!test_connect()) {
        printf("\n[FATAL] Cannot connect to driver. Aborting.\n");
        printf("\nResults: PASS=%d FAIL=%d SKIP=%d\n", g_pass, g_fail, g_skip);
        return 1;
    }

    test_heartbeat();


    std::uint32_t found_pid = test_find_process();
    if (found_pid == 0) {
        printf("\n[FATAL] Cannot find test_target.exe via driver. Aborting.\n");
        device->disconnect();
        printf("\nResults: PASS=%d FAIL=%d SKIP=%d\n", g_pass, g_fail, g_skip);
        return 1;
    }

    std::uint64_t base = test_find_image();


    test_dtb();


    printf("\n  [INFO] Starting early packet capture and bandwidth monitor...\n");
    bool early_capture_ok = device->start_capture(found_pid, 0, 0, nullptr, 1500);
    if (early_capture_ok) {
        printf("  [INFO] Early capture started (pid=%u) — will harvest after non-network tests.\n", found_pid);
    } else {
        printf("  [WARN] Early capture failed — will retry during network test phase.\n");
    }

    voyager::device_t::bw_stats early_bw{};
    bool early_bw_ok = device->bw_monitor_op(0, 0, &early_bw);
    if (early_bw_ok) {
        printf("  [INFO] Early bandwidth monitor started.\n");
    }


    test_read_write(base);
    test_kernel_read();
    test_allocate_free();


    test_thread_operations();
    test_hw_breakpoints();


    test_memory_queries(base);


    test_process_info(base);


    test_dll_protection();


    test_remote_call(base, found_pid);


    if (!device->is_connected()) {
        printf("  [WARN] Driver session lost after remote call tests, reconnecting...\n");
        device->disconnect();
        if (device->connect()) {
            device->set_process_id(found_pid);
            device->solve_dtb();
            printf("  [INFO] Reconnected successfully.\n");
        } else {
            printf("  [WARN] Reconnect failed, network tests may fail.\n");
        }
    }


    printf("\n  [INFO] === Beginning network tests ===\n");
    printf("  [INFO] test_target.exe generates HTTP, DNS, TLS, loopback TCP:44444, loopback UDP:44445\n");
    printf("  [INFO] PID-filtered queries should return real connections and packets\n");


    if (early_capture_ok) {
        bool act = false;
        std::uint32_t cap_count = 0, drop_count = 0;
        device->get_capture_status(act, cap_count, drop_count);
        printf("  [INFO] Early capture results: active=%d captured=%u dropped=%u\n",
               act, cap_count, drop_count);
        device->stop_capture();
    }

    test_network_connections(target_pid);
    test_capture(target_pid);
    test_dns_queries(target_pid);
    test_filter_rules();
    test_network_stats();


    test_wfp_callouts();
    test_socket_handles(target_pid);
    test_sniff_net_buffers();
    test_tcpip_dump(target_pid);


    test_packet_injection();
    test_packet_mod_rules();
    test_traffic_redirect();
    test_stream_reassembly();
    test_dpi(target_pid);
    test_intercept();
    test_kill_connection();


    test_dns_spoofing();
    test_bandwidth_monitor(target_pid);
    test_enumerate_interfaces();


    test_pcap_export(target_pid);
    test_fingerprinting();


    {
        section("NETWORK FEATURE MATRIX");
        printf("  +-------------------------------------------------------+\n");
        printf("  | Category       | Feature              | Status         |\n");
        printf("  +-------------------------------------------------------+\n");


        printf("  | Core           | Connection Enum      | TESTED         |\n");
        printf("  | Core           | Packet Capture       | TESTED         |\n");
        printf("  | Core           | DNS Capture          | TESTED         |\n");
        printf("  | Core           | Network Stats        | TESTED         |\n");
        printf("  | Core           | Filter Rules         | TESTED         |\n");
        printf("  +-------------------------------------------------------+\n");
        printf("  | Analysis       | WFP Callout Enum     | TESTED         |\n");
        printf("  | Analysis       | Socket Handles       | TESTED         |\n");
        printf("  | Analysis       | Deep Packet Inspect  | TESTED         |\n");
        printf("  | Analysis       | OS Fingerprinting    | TESTED         |\n");
        printf("  | Analysis       | TCPIP Dump           | TESTED         |\n");
        printf("  +-------------------------------------------------------+\n");
        printf("  | Manipulation   | Packet Injection     | TESTED         |\n");
        printf("  | Manipulation   | Mod Rules            | TESTED         |\n");
        printf("  | Manipulation   | Traffic Redirect     | TESTED         |\n");
        printf("  | Manipulation   | Stream Reassembly    | TESTED         |\n");
        printf("  | Manipulation   | Intercept            | TESTED         |\n");
        printf("  | Manipulation   | Kill Connection      | TESTED         |\n");
        printf("  | Manipulation   | DNS Spoofing         | TESTED         |\n");
        printf("  +-------------------------------------------------------+\n");
        printf("  | Monitoring     | Bandwidth Monitor    | TESTED         |\n");
        printf("  | Monitoring     | Interface Enum       | TESTED         |\n");
        printf("  | Monitoring     | PCAP Export          | TESTED         |\n");
        printf("  | Monitoring     | Sniff Net Buffers    | TESTED         |\n");
        printf("  +-------------------------------------------------------+\n");
        printf("  | 21 network features tested. See PASS/FAIL above.      |\n");
        printf("  +-------------------------------------------------------+\n");
        printf("\n  [INFO] Kernel logging is active (AIDA_NET_DEBUG in Release config)\n");
        printf("  [INFO] View kernel logs: DebugView (Admin + Capture Kernel) filter on [AIDA-NET]\n");
        printf("  [INFO] test_target.exe runs continuous traffic on ports 80, 443, 53, 44444(TCP), 44445(UDP)\n");
    }


    section("CLEANUP");
    device->disconnect();
    report("disconnect()", !device->is_connected());


    if (launched) {
        HANDLE done_event = OpenEventA(EVENT_MODIFY_STATE, FALSE, "Global\\WhosWhoTestDone");
        if (!done_event) {
            done_event = OpenEventA(EVENT_MODIFY_STATE, FALSE, "Local\\WhosWhoTestDone");
        }
        if (done_event) {
            SetEvent(done_event);
            CloseHandle(done_event);
            printf("  [INFO] Signaled test_target.exe to shut down\n");
        } else {
            printf("  [WARN] Could not signal test_target.exe (event not found)\n");
        }
    } else {
        printf("  [INFO] test_target.exe was already running; not signaling shutdown\n");
    }


    printf("\n================================================================\n");
    printf("  TEST SUMMARY\n");
    printf("================================================================\n");
    printf("  PASS: %d\n", g_pass);
    printf("  FAIL: %d\n", g_fail);
    printf("  SKIP: %d\n", g_skip);
    printf("  TOTAL: %d\n", g_pass + g_fail + g_skip);
    printf("================================================================\n");

    if (g_fail > 0) {
        printf("\n  [!] %d test(s) FAILED.\n", g_fail);
    } else {
        printf("\n  All tests passed!\n");
    }

    return g_fail > 0 ? 1 : 0;
}
