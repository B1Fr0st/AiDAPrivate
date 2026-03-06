#include <cstdio>
#include <cstdint>
#include <cstring>
#include <windows.h>
#include "../comm.h"

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

static void report(const char* test, bool passed) {
    if (passed) {
        printf("[PASS] %s\n", test);
        g_pass++;
    } else {
        printf("[FAIL] %s\n", test);
        g_fail++;
    }
}

static void skip(const char* test) {
    printf("[SKIP] %s\n", test);
    g_skip++;
}

int main() {
    printf("========================================\n");
    printf("   WhosWho Driver Test Suite\n");
    printf("========================================\n\n");

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(L"C:\\Windows\\notepad.exe", nullptr, nullptr, nullptr,
        FALSE, 0, nullptr, nullptr, &si, &pi)) {
        printf("FATAL: Failed to start notepad.exe (error=%u)\n", GetLastError());
        return 1;
    }
    CloseHandle(pi.hThread);
    Sleep(2000);
    printf("Target: notepad.exe (PID: %u)\n\n", pi.dwProcessId);

    bool connected = device->connect();
    report("1. Connect to driver", connected);
    if (!connected) {
        printf("FATAL: Cannot proceed without driver connection.\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 1;
    }

    std::uint32_t pid = device->find_process("notepad.exe");
    report("2. Find process (notepad.exe)", pid != 0);
    printf("   PID: %u\n", pid);
    if (pid == 0) {
        printf("FATAL: Cannot proceed without finding the process.\n");
        device->disconnect();
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 1;
    }

    device->solve_dtb();
    std::uint64_t dtb = device->get_dtb();
    report("3. Solve DTB", dtb != 0);
    printf("   DTB: 0x%llX\n", dtb);
    if (dtb == 0) {
        printf("FATAL: Cannot proceed without DTB.\n");
        device->disconnect();
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 1;
    }

    std::uint64_t base = device->find_image();
    report("4. Find image base", base != 0);
    printf("   Base: 0x%llX\n", base);
    if (base == 0) {
        printf("FATAL: Cannot proceed without image base.\n");
        device->disconnect();
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 1;
    }

    std::uint16_t mz = device->read<std::uint16_t>(base);
    report("5. Read memory (DOS header)", mz == 0x5A4D);
    printf("   MZ signature: 0x%04X\n", mz);

    std::uint64_t write_addr = base + 0x02;
    std::uint16_t original_val = device->read<std::uint16_t>(write_addr);
    std::uint16_t test_val = 0x1337;
    device->write<std::uint16_t>(write_addr, test_val);
    std::uint16_t readback = device->read<std::uint16_t>(write_addr);
    device->write<std::uint16_t>(write_addr, original_val);
    report("6. Write memory (write+verify+restore)", readback == test_val);
    printf("   Wrote: 0x%04X  Read: 0x%04X  Restored: 0x%04X\n", test_val, readback, original_val);

    std::uint64_t alloc_addr = device->allocate_memory(0x1000);
    report("7. Allocate memory (0x1000)", alloc_addr != 0);
    printf("   Allocated at: 0x%llX\n", alloc_addr);

    if (alloc_addr != 0) {
        bool freed = device->free_memory(alloc_addr);
        report("8. Free memory", freed);
    } else {
        skip("8. Free memory (no allocation to free)");
    }

    auto threads = device->enumerate_threads();
    report("9. Enumerate threads", !threads.empty());
    printf("   Thread count: %zu\n", threads.size());
    for (std::size_t i = 0; i < threads.size() && i < 5; i++) {
        printf("   [%zu] TID=%u\n", i, threads[i].tid);
    }

    std::uint32_t first_tid = 0;
    if (!threads.empty()) {
        first_tid = threads[0].tid;

        voyager::device_t::thread_context ctx = {};
        bool ctx_ok = device->get_thread_context(first_tid, ctx);
        report("10. Get thread context", ctx_ok);
        printf("    TID=%u RIP=0x%llX RSP=0x%llX RAX=0x%llX\n", first_tid, ctx.rip, ctx.rsp, ctx.rax);
    } else {
        skip("10. Get thread context (no threads found)");
    }

    if (first_tid != 0) {
        std::uint32_t prev = 0;
        bool suspended = device->suspend_thread(first_tid, &prev);
        report("11. Suspend thread", suspended);
        printf("    TID=%u prev_count=%u\n", first_tid, prev);

        bool resumed = device->resume_thread(first_tid, &prev);
        report("12. Resume thread", resumed);
        printf("    TID=%u prev_count=%u\n", first_tid, prev);
    } else {
        skip("11. Suspend thread (no threads)");
        skip("12. Resume thread (no threads)");
    }

    voyager::device_t::memory_region_info mem_info = {};
    bool qm_ok = device->query_memory(base, mem_info);
    report("13. Query memory", qm_ok && mem_info.base != 0);
    printf("    Base=0x%llX Size=0x%llX State=0x%X Protect=0x%X Type=0x%X\n",
        mem_info.base, mem_info.size, mem_info.state, mem_info.protect, mem_info.type);

    std::uint64_t prot_alloc = device->allocate_memory(0x1000);
    if (prot_alloc != 0) {
        std::uint32_t old_prot = 0;
        bool pm_ok = device->protect_memory(prot_alloc, 0x1000, PAGE_EXECUTE_READWRITE, &old_prot);
        report("14. Protect memory", pm_ok);
        printf("    Address=0x%llX old_protect=0x%X\n", prot_alloc, old_prot);
        device->free_memory(prot_alloc);
    } else {
        skip("14. Protect memory (allocation failed)");
    }

    auto regions = device->enumerate_memory_regions(0, 0, false);
    report("15. Enumerate memory regions", !regions.empty());
    printf("    Region count: %zu\n", regions.size());
    if (!regions.empty()) {
        printf("    First region: base=0x%llX size=0x%llX protect=0x%X\n",
            regions[0].base, regions[0].size, regions[0].protect);
    }

    voyager::device_t::peb_info peb = {};
    bool peb_ok = device->read_peb(peb);
    report("16. Read PEB", peb_ok && peb.peb_address != 0);
    printf("    PEB=0x%llX ImageBase=0x%llX Debugged=%u NtGlobalFlag=0x%X\n",
        peb.peb_address, peb.image_base, peb.being_debugged, peb.nt_global_flag);
    printf("    Ldr=0x%llX Heap=0x%llX NumHeaps=%u\n",
        peb.ldr_address, peb.process_heap, peb.number_of_heaps);

    std::uint32_t spoof_flags = 0;
    bool spoof_ok = device->spoof_debug_flags(&spoof_flags);
    report("17. Spoof debug flags", spoof_ok);
    printf("    Cleared flags: 0x%X\n", spoof_flags);

    HMODULE ntdll_local = GetModuleHandleW(L"ntdll.dll");
    std::uint64_t ntdll_base = reinterpret_cast<std::uint64_t>(ntdll_local);
    std::uint64_t resolved = device->resolve_export(ntdll_base, "NtClose");
    report("18. Resolve export (ntdll!NtClose)", resolved != 0);
    printf("    ntdll base: 0x%llX  NtClose: 0x%llX\n", ntdll_base, resolved);

    std::uint64_t phys = device->virtual_to_physical(base);
    report("19. Virtual to physical", phys != 0);
    printf("    Virt=0x%llX -> Phys=0x%llX\n", base, phys);

    POINT pt_before;
    GetCursorPos(&pt_before);
    device->move_mouse(5, 0, 0);
    Sleep(100);
    POINT pt_after;
    GetCursorPos(&pt_after);
    bool mouse_moved = (pt_after.x != pt_before.x || pt_after.y != pt_before.y);
    report("20. Mouse movement", mouse_moved);
    printf("    Before: (%ld, %ld)  After: (%ld, %ld)\n",
        pt_before.x, pt_before.y, pt_after.x, pt_after.y);

    HMODULE k32_local = GetModuleHandleW(L"kernel32.dll");
    std::uint64_t k32_base = reinterpret_cast<std::uint64_t>(k32_local);
    std::uint64_t get_pid_addr = device->resolve_export(k32_base, "GetCurrentProcessId");
    if (get_pid_addr != 0) {
        printf("    Calling GetCurrentProcessId at 0x%llX in notepad...\n", get_pid_addr);
        std::uint64_t remote_pid = device->call_function(get_pid_addr);
        bool match = (static_cast<std::uint32_t>(remote_pid) == pid);
        report("21. Remote call (GetCurrentProcessId)", match);
        printf("    Expected PID=%u  Got PID=%llu\n", pid, remote_pid);
    } else {
        skip("21. Remote call (could not resolve GetCurrentProcessId)");
    }

    if (first_tid != 0) {
        std::uint32_t prev_s = 0;
        bool susp = device->suspend_thread(first_tid, &prev_s);
        if (susp) {
            voyager::device_t::thread_context orig_ctx = {};
            bool got = device->get_thread_context(first_tid, orig_ctx);
            if (got) {
                voyager::device_t::thread_context mod_ctx = orig_ctx;
                mod_ctx.r15 = 0xDEADBEEFCAFE1234ULL;
                bool set_ok = device->set_thread_context(first_tid, mod_ctx, (1ULL << 15));
                report("22. Set thread context (R15)", set_ok);
                if (set_ok) {
                    voyager::device_t::thread_context verify_ctx = {};
                    device->get_thread_context(first_tid, verify_ctx);
                    printf("    R15 set=0x%llX readback=0x%llX\n", mod_ctx.r15, verify_ctx.r15);
                }
                device->set_thread_context(first_tid, orig_ctx, (1ULL << 15));
            } else {
                skip("22. Set thread context (get_thread_context failed)");
            }
            device->resume_thread(first_tid, &prev_s);
        } else {
            skip("22. Set thread context (suspend failed)");
        }
    } else {
        skip("22. Set thread context (no threads)");
    }

    if (first_tid != 0) {
        bool bp_set = device->set_hardware_breakpoint(first_tid, 0, base, 0, 0);
        report("23. Set hardware breakpoint (DR0)", bp_set);
        printf("    TID=%u index=0 address=0x%llX\n", first_tid, base);

        if (bp_set) {
            voyager::device_t::thread_context bp_ctx = {};
            device->get_thread_context(first_tid, bp_ctx);
            printf("    DR0=0x%llX DR7=0x%llX\n", bp_ctx.dr0, bp_ctx.dr7);
        }

        bool bp_clear = device->clear_hardware_breakpoint(first_tid, 0);
        report("24. Clear hardware breakpoint (DR0)", bp_clear);

        if (bp_clear) {
            voyager::device_t::thread_context bp_ctx2 = {};
            device->get_thread_context(first_tid, bp_ctx2);
            printf("    DR0=0x%llX DR7=0x%llX (should be cleared)\n", bp_ctx2.dr0, bp_ctx2.dr7);
        }
    } else {
        skip("23. Set hardware breakpoint (no threads)");
        skip("24. Clear hardware breakpoint (no threads)");
    }

    printf("\n========================================\n");
    printf("   Results: %d PASS  %d FAIL  %d SKIP\n", g_pass, g_fail, g_skip);
    printf("========================================\n");

    device->disconnect();
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);

    return g_fail > 0 ? 1 : 0;
}
