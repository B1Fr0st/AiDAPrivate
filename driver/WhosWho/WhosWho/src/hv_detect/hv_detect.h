#pragma once
#include "includes.h"
#include "func_defs.h"
#include "hv_structs.h"
#include "physmem_structs.h"
#include "page_table_helpers.h"
#include "win_helpers.h"
#include "physmem.h"
#include "safety_net.h"
#include "idt_detect.h"
#include "ve_detect.h"

#pragma pack(push, 1)
typedef struct _HV_DETECT_REQUEST_K {
    UINT64 flags;
} hv_detect_request_k, *p_hv_detect_request_k;
static_assert(sizeof(hv_detect_request_k) == 8, "hv_detect_request_k must be 8 bytes");

typedef struct _HV_DETECT_RESULT_K {
    UINT8 sidt_lock_prefix;
    UINT8 sidt_invalid_pf;
    UINT8 sidt_tlb_only;
    UINT8 sidt_timing;
    UINT8 sidt_compat_mode;
    UINT8 sidt_noncanonical_gp;
    UINT8 sidt_noncanonical_ss;
    UINT8 sidt_cpl3_umip_off;
    UINT8 sidt_cpl3_umip_on;

    UINT8 lidt_lock_prefix;
    UINT8 lidt_invalid_pf;
    UINT8 lidt_tlb_only;
    UINT8 lidt_timing;
    UINT8 lidt_noncanonical_gp;
    UINT8 lidt_noncanonical_ss;
    UINT8 lidt_cpl3_gp;

    UINT8 ve_trigger;
    UINT8 ve_lbr_stack;
    UINT8 ve_xsetbv_gp;
    UINT8 ve_cr4_vmxe;

    UINT8 vmf_cpuid_vendor;
    UINT8 vmf_hyperv_guest;
    UINT8 vmf_smbios_vm;
    UINT8 vmf_acpi_vm;
    UINT8 vmf_pci_vm;
    UINT8 vmf_disk_vm;
    UINT8 vmf_mac_vm;
    UINT8 vmf_registry_vm;

    UINT8 total_run;
    UINT8 total_failed;
    UINT8 ms_hv_root;
    UINT8 is_virtual_machine;

    CHAR  vm_vendor_name[16];
    UINT8 measurements_hmac[16];
    UINT8 reserved_pad[16];
} hv_detect_result_k, *p_hv_detect_result_k;
static_assert(sizeof(hv_detect_result_k) == 80, "hv_detect_result_k must be 80 bytes");
#pragma pack(pop)

namespace hv_detect {

    typedef bool (*bool_probe_fn)(void);
    typedef vm_fingerprint::vm_vendor_e (*vendor_probe_fn)(void);

    struct trace_stamp_t {
        LARGE_INTEGER qpc;
        LARGE_INTEGER freq;
        UINT64 tsc;
    };

    inline trace_stamp_t trace_stamp(void) {
        trace_stamp_t stamp{};
        stamp.qpc = KeQueryPerformanceCounter(&stamp.freq);
        stamp.tsc = __rdtsc();
        return stamp;
    }

    inline UINT64 elapsed_us(const trace_stamp_t& start, const trace_stamp_t& end) {
        LONGLONG freq = start.freq.QuadPart != 0 ? start.freq.QuadPart : end.freq.QuadPart;
        if (freq <= 0 || end.qpc.QuadPart < start.qpc.QuadPart)
            return 0;
        return static_cast<UINT64>(((end.qpc.QuadPart - start.qpc.QuadPart) * 1000000ULL) / static_cast<UINT64>(freq));
    }

    inline ULONG current_cpu(void) {
        return KeGetCurrentProcessorNumber();
    }

    inline UINT64 current_pid(void) {
        return static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
    }

    inline UINT64 current_tid(void) {
        return static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()));
    }

    inline UINT64 image_rva(UINT64 address) {
        if (safety_net::g_image_base == 0 || safety_net::g_image_size == 0)
            return 0;
        if (address < safety_net::g_image_base || address >= safety_net::g_image_base + safety_net::g_image_size)
            return 0;
        return address - safety_net::g_image_base;
    }

    inline bool is_microsoft_hyperv_root() {
        int regs[4] = {};
        __cpuid(regs, 1);
        if ((regs[2] & (1 << 31)) == 0)
            return false;

        __cpuid(regs, 0x40000000);
        char vendor[12];
        *(int*)(vendor + 0) = regs[1];
        *(int*)(vendor + 4) = regs[2];
        *(int*)(vendor + 8) = regs[3];

        const char expected[12] = {
            'M','i','c','r','o','s','o','f','t',' ','H','v'
        };
        for (int i = 0; i < 12; i++) {
            if (vendor[i] != expected[i])
                return false;
        }

        __cpuid(regs, 0x40000001);
        if ((uint32_t)regs[0] != 0x31237648u)
            return false;

        __cpuid(regs, 0x40000003);
        uint32_t priv = (uint32_t)regs[0];
        return (priv & ((1u << 0) | (1u << 1) | (1u << 5))) != 0;
    }

    inline void copy_vendor_name(hv_detect_result_k* out, vm_fingerprint::vm_vendor_e v) {
        const char* name = vm_fingerprint::vendor_name(v);
        SIZE_T i = 0;
        for (; i < sizeof(out->vm_vendor_name) - 1 && name[i] != 0; ++i) {
            out->vm_vendor_name[i] = name[i];
        }
        out->vm_vendor_name[i] = 0;
    }

    inline bool run_plain_bool_probe(const char* name, UINT64 flags, bool_probe_fn fn, bool exception_value) {
        trace_stamp_t start = trace_stamp();
        HVD_LOG_IMMEDIATE("probe_pre kind=bool name=%s flags=0x%llx qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
            name,
            flags,
            start.qpc.QuadPart,
            start.tsc,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        bool value = exception_value;
        ULONG exception_seen = 0;
        ULONG seh_code = 0;
        __try {
            value = fn ? fn() : exception_value;
        }
        __except ((seh_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
            exception_seen = 1;
            value = exception_value;
        }

        trace_stamp_t end = trace_stamp();
        HVD_LOG_IMMEDIATE("probe_post kind=bool name=%s flags=0x%llx result=%u exception=%lu exception_code=0x%08lx elapsed_us=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
            name,
            flags,
            value ? 1u : 0u,
            exception_seen,
            seh_code,
            elapsed_us(start, end),
            end.qpc.QuadPart,
            end.tsc,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        return value;
    }

    inline vm_fingerprint::vm_vendor_e run_vendor_probe(const char* name, UINT64 flags, vendor_probe_fn fn, bool* forced_hit) {
        if (forced_hit)
            *forced_hit = false;

        trace_stamp_t start = trace_stamp();
        HVD_LOG_IMMEDIATE("probe_pre kind=vendor name=%s flags=0x%llx qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
            name,
            flags,
            start.qpc.QuadPart,
            start.tsc,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        vm_fingerprint::vm_vendor_e vendor = vm_fingerprint::VM_VENDOR_NONE;
        ULONG exception_seen = 0;
        ULONG seh_code = 0;
        __try {
            vendor = fn ? fn() : vm_fingerprint::VM_VENDOR_NONE;
        }
        __except ((seh_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
            exception_seen = 1;
            if (forced_hit)
                *forced_hit = true;
        }

        trace_stamp_t end = trace_stamp();
        HVD_LOG_IMMEDIATE("probe_post kind=vendor name=%s flags=0x%llx vendor=%u hit=%u forced_hit=%u exception=%lu exception_code=0x%08lx elapsed_us=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
            name,
            flags,
            static_cast<ULONG>(vendor),
            vendor != vm_fingerprint::VM_VENDOR_NONE ? 1u : 0u,
            forced_hit && *forced_hit ? 1u : 0u,
            exception_seen,
            seh_code,
            elapsed_us(start, end),
            end.qpc.QuadPart,
            end.tsc,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        return vendor;
    }

    inline bool run_safety_subtest(const char* group, int index, const char* name, UINT64 flags, bool_probe_fn fn) {
        safety_net::idt::consume_probe_recovery_count();
        safety_net::idt::consume_unresolved_exception_count();

        trace_stamp_t start = trace_stamp();
        HVD_LOG_IMMEDIATE("subtest_pre group=%s index=%d name=%s flags=0x%llx qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
            group,
            index,
            name,
            flags,
            start.qpc.QuadPart,
            start.tsc,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        safety_net_t storage{};
        bool detected = true;
        ULONG exception_seen = 0;
        ULONG seh_code = 0;
        ULONG safety_started = 0;

        if (safety_net::start_safety_net(storage)) {
            safety_started = 1;
            detected = false;
            __try {
                detected = fn ? fn() : true;
            }
            __except ((seh_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
                exception_seen = 1;
                detected = true;
            }
            safety_net::stop_safety_net(storage);
        } else {
            seh_code = static_cast<ULONG>(STATUS_UNSUCCESSFUL);
            detected = true;
        }

        LONG recoveries = safety_net::idt::consume_probe_recovery_count();
        LONG unresolved = safety_net::idt::consume_unresolved_exception_count();
        if (recoveries != 0 || unresolved != 0)
            detected = true;

        uint64_t last_vector = 0;
        uint64_t last_error = 0;
        uint64_t last_rip = 0;
        uint64_t last_rsp = 0;
        safety_net::idt::get_last_exception_snapshot(&last_vector, &last_error, &last_rip, &last_rsp);

        trace_stamp_t end = trace_stamp();
        HVD_LOG_IMMEDIATE("subtest_post group=%s index=%d name=%s flags=0x%llx safety_started=%lu result=%u exception=%lu exception_code=0x%08lx recoveries=%ld unresolved=%ld interrupts=%llu last_vector=0x%llx last_error=0x%llx last_rip_rva=0x%llx last_rsp=0x%llx elapsed_us=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
            group,
            index,
            name,
            flags,
            safety_started,
            detected ? 1u : 0u,
            exception_seen,
            seh_code,
            recoveries,
            unresolved,
            safety_net::idt::get_interrupt_count(),
            last_vector,
            last_error,
            image_rva(last_rip),
            last_rsp,
            elapsed_us(start, end),
            end.qpc.QuadPart,
            end.tsc,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        return detected;
    }

    inline void log_result_summary(const char* phase, UINT64 flags, const hv_detect_result_k* result, NTSTATUS status, const trace_stamp_t& start) {
        trace_stamp_t end = trace_stamp();
        HVD_LOG_IMMEDIATE("%s flags=0x%llx status=0x%08lx total_run=%u total_failed=%u is_vm=%u ms_hv_root=%u sidt=%u%u%u%u%u%u%u%u%u lidt=%u%u%u%u%u%u%u ve=%u%u%u%u vmf=%u%u%u%u%u%u%u%u vendor=%s elapsed_us=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
            phase,
            flags,
            status,
            result ? result->total_run : 0,
            result ? result->total_failed : 0,
            result ? result->is_virtual_machine : 0,
            result ? result->ms_hv_root : 0,
            result ? result->sidt_lock_prefix : 0,
            result ? result->sidt_invalid_pf : 0,
            result ? result->sidt_tlb_only : 0,
            result ? result->sidt_timing : 0,
            result ? result->sidt_compat_mode : 0,
            result ? result->sidt_noncanonical_gp : 0,
            result ? result->sidt_noncanonical_ss : 0,
            result ? result->sidt_cpl3_umip_off : 0,
            result ? result->sidt_cpl3_umip_on : 0,
            result ? result->lidt_lock_prefix : 0,
            result ? result->lidt_invalid_pf : 0,
            result ? result->lidt_tlb_only : 0,
            result ? result->lidt_timing : 0,
            result ? result->lidt_noncanonical_gp : 0,
            result ? result->lidt_noncanonical_ss : 0,
            result ? result->lidt_cpl3_gp : 0,
            result ? result->ve_trigger : 0,
            result ? result->ve_lbr_stack : 0,
            result ? result->ve_xsetbv_gp : 0,
            result ? result->ve_cr4_vmxe : 0,
            result ? result->vmf_cpuid_vendor : 0,
            result ? result->vmf_hyperv_guest : 0,
            result ? result->vmf_smbios_vm : 0,
            result ? result->vmf_acpi_vm : 0,
            result ? result->vmf_pci_vm : 0,
            result ? result->vmf_disk_vm : 0,
            result ? result->vmf_mac_vm : 0,
            result ? result->vmf_registry_vm : 0,
            result ? result->vm_vendor_name : "",
            elapsed_us(start, end),
            end.qpc.QuadPart,
            end.tsc,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());
    }

    inline void run_all(hv_detect_result_k* result, UINT64 flags) {
        if (!result)
            return;

        trace_stamp_t run_start = trace_stamp();
        HVD_LOG_IMMEDIATE("run_all_enter flags=0x%llx result_present=1 qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
            flags,
            run_start.qpc.QuadPart,
            run_start.tsc,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        RtlZeroMemory(result, sizeof(hv_detect_result_k));

        const bool ms_hv_root = run_plain_bool_probe("microsoft_hyperv_root", flags, is_microsoft_hyperv_root, false);
        result->ms_hv_root = ms_hv_root ? 1 : 0;

        const bool kernel_probe_allowed = KeGetCurrentIrql() == PASSIVE_LEVEL;
        const bool physmem_supported = physmem::support::is_physmem_supported();

        bool kernel_path_completed = false;

        HVD_LOG_IMMEDIATE("kernel_path_gate flags=0x%llx passive=%u physmem_supported=%u ms_hv_root=%u cpu=%lu irql=%lu pid=%llu tid=%llu",
            flags,
            kernel_probe_allowed ? 1u : 0u,
            physmem_supported ? 1u : 0u,
            ms_hv_root ? 1u : 0u,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        bool physmem_initialized = false;
        if (kernel_probe_allowed && physmem_supported) {
            trace_stamp_t phys_start = trace_stamp();
            HVD_LOG_IMMEDIATE("physmem_init_pre flags=0x%llx qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
                flags,
                phys_start.qpc.QuadPart,
                phys_start.tsc,
                current_cpu(),
                (ULONG)KeGetCurrentIrql(),
                current_pid(),
                current_tid());
            physmem_initialized = physmem::init_physmem();
            trace_stamp_t phys_end = trace_stamp();
            HVD_LOG_IMMEDIATE("physmem_init_post flags=0x%llx ok=%u status=0x%08lx elapsed_us=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
                flags,
                physmem_initialized ? 1u : 0u,
                physmem_initialized ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL,
                elapsed_us(phys_start, phys_end),
                phys_end.qpc.QuadPart,
                phys_end.tsc,
                current_cpu(),
                (ULONG)KeGetCurrentIrql(),
                current_pid(),
                current_tid());
        }

        if (kernel_probe_allowed && physmem_initialized) {
            UNICODE_STRING func_name;
            RtlInitUnicodeString(&func_name, L"PsGetCurrentProcess");
            PVOID kernel_func = MmGetSystemRoutineAddress(&func_name);
            uint64_t image_base = 0;
            uint64_t image_size = 0;
            ULONG image_scan_exception = 0;

            {
                uint64_t search_addr = kernel_func ? (uint64_t)kernel_func : (uint64_t)&run_all;
                trace_stamp_t image_start = trace_stamp();
                HVD_LOG_IMMEDIATE("image_scan_pre flags=0x%llx routine_present=%u search_page=0x%llx qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
                    flags,
                    kernel_func ? 1u : 0u,
                    search_addr & ~0xFFFULL,
                    image_start.qpc.QuadPart,
                    image_start.tsc,
                    current_cpu(),
                    (ULONG)KeGetCurrentIrql(),
                    current_pid(),
                    current_tid());
                __try {
                    uint64_t scan = search_addr & ~0xFFFULL;
                    for (int i = 0; i < 0x1000; i++) {
                        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)scan;
                        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)dos + dos->e_lfanew);
                            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                                image_base = scan;
                                image_size = nt->OptionalHeader.SizeOfImage;
                                break;
                            }
                        }
                        scan -= 0x1000;
                    }
                } __except ((image_scan_exception = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
                }
                trace_stamp_t image_end = trace_stamp();
                HVD_LOG_IMMEDIATE("image_scan_post flags=0x%llx found=%u image_size=0x%llx exception=0x%08lx elapsed_us=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
                    flags,
                    image_base != 0 ? 1u : 0u,
                    image_size,
                    image_scan_exception,
                    elapsed_us(image_start, image_end),
                    image_end.qpc.QuadPart,
                    image_end.tsc,
                    current_cpu(),
                    (ULONG)KeGetCurrentIrql(),
                    current_pid(),
                    current_tid());
            }

            bool safety_initialized = false;
            if (!ms_hv_root && image_base != 0) {
                trace_stamp_t safety_init_start = trace_stamp();
                HVD_LOG_IMMEDIATE("safety_init_pre flags=0x%llx image_found=1 image_size=0x%llx qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
                    flags,
                    image_size,
                    safety_init_start.qpc.QuadPart,
                    safety_init_start.tsc,
                    current_cpu(),
                    (ULONG)KeGetCurrentIrql(),
                    current_pid(),
                    current_tid());
                safety_initialized = safety_net::init_safety_net(image_base, image_size);
                trace_stamp_t safety_init_end = trace_stamp();
                HVD_LOG_IMMEDIATE("safety_init_post flags=0x%llx ok=%u status=0x%08lx elapsed_us=%llu qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
                    flags,
                    safety_initialized ? 1u : 0u,
                    safety_initialized ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL,
                    elapsed_us(safety_init_start, safety_init_end),
                    safety_init_end.qpc.QuadPart,
                    safety_init_end.tsc,
                    current_cpu(),
                    (ULONG)KeGetCurrentIrql(),
                    current_pid(),
                    current_tid());
            } else {
                HVD_LOG_IMMEDIATE("safety_init_skip flags=0x%llx reason=%s ms_hv_root=%u image_found=%u cpu=%lu irql=%lu pid=%llu tid=%llu",
                    flags,
                    ms_hv_root ? "microsoft_hyperv_root" : "image_not_found",
                    ms_hv_root ? 1u : 0u,
                    image_base != 0 ? 1u : 0u,
                    current_cpu(),
                    (ULONG)KeGetCurrentIrql(),
                    current_pid(),
                    current_tid());
            }

            if (!ms_hv_root && image_base != 0 && safety_initialized) {
                safety_net::set_safety_net_kpcr(KeGetPcr());

                {
                    bool sidt_results[9] = {};
                    bool_probe_fn sidt_detections[] = {
                        idt::storing::detection_1, idt::storing::detection_2,
                        idt::storing::detection_3, idt::storing::detection_4,
                        idt::storing::detection_5, idt::storing::detection_6,
                        idt::storing::detection_7, idt::storing::detection_8,
                        idt::storing::detection_9
                    };
                    const char* sidt_names[] = {
                        "sidt_lock_prefix",
                        "sidt_invalid_pf",
                        "sidt_tlb_only",
                        "sidt_timing",
                        "sidt_compat_mode",
                        "sidt_noncanonical_gp",
                        "sidt_noncanonical_ss",
                        "sidt_cpl3_umip_off",
                        "sidt_cpl3_umip_on"
                    };
                    for (int i = 0; i < 9; ++i)
                        sidt_results[i] = run_safety_subtest("sidt", i + 1, sidt_names[i], flags, sidt_detections[i]);

                    result->sidt_lock_prefix     = sidt_results[0] ? 1 : 0;
                    result->sidt_invalid_pf      = sidt_results[1] ? 1 : 0;
                    result->sidt_tlb_only        = sidt_results[2] ? 1 : 0;
                    result->sidt_timing          = sidt_results[3] ? 1 : 0;
                    result->sidt_compat_mode     = sidt_results[4] ? 1 : 0;
                    result->sidt_noncanonical_gp = sidt_results[5] ? 1 : 0;
                    result->sidt_noncanonical_ss = sidt_results[6] ? 1 : 0;
                    result->sidt_cpl3_umip_off   = sidt_results[7] ? 1 : 0;
                    result->sidt_cpl3_umip_on    = sidt_results[8] ? 1 : 0;

                    bool lidt_results[7] = {};
                    bool_probe_fn lidt_detections[] = {
                        idt::loading::detection_1, idt::loading::detection_2,
                        idt::loading::detection_3, idt::loading::detection_4,
                        idt::loading::detection_5, idt::loading::detection_6,
                        idt::loading::detection_7
                    };
                    const char* lidt_names[] = {
                        "lidt_lock_prefix",
                        "lidt_invalid_pf",
                        "lidt_tlb_only",
                        "lidt_timing",
                        "lidt_noncanonical_gp",
                        "lidt_noncanonical_ss",
                        "lidt_cpl3_gp"
                    };
                    for (int i = 0; i < 7; ++i)
                        lidt_results[i] = run_safety_subtest("lidt", i + 1, lidt_names[i], flags, lidt_detections[i]);

                    result->lidt_lock_prefix     = lidt_results[0] ? 1 : 0;
                    result->lidt_invalid_pf      = lidt_results[1] ? 1 : 0;
                    result->lidt_tlb_only        = lidt_results[2] ? 1 : 0;
                    result->lidt_timing          = lidt_results[3] ? 1 : 0;
                    result->lidt_noncanonical_gp = lidt_results[4] ? 1 : 0;
                    result->lidt_noncanonical_ss = lidt_results[5] ? 1 : 0;
                    result->lidt_cpl3_gp         = lidt_results[6] ? 1 : 0;
                }

                if (!ms_hv_root) {
                    ve::image_base = safety_net::g_image_base;
                    ve::image_size = safety_net::g_image_size;

                    bool_probe_fn ve_detections[] = {
                        ve::detection_1,
                        ve::detection_2,
                        ve::detection_xsetbv_gp,
                        ve::detection_cr4_vmxe,
                    };
                    const char* ve_names[] = {
                        "ve_trigger",
                        "ve_lbr_stack",
                        "ve_xsetbv_gp",
                        "ve_cr4_vmxe",
                    };
                    bool ve_results[4] = {};
                    for (int i = 0; i < 4; ++i)
                        ve_results[i] = run_safety_subtest("ve", i + 1, ve_names[i], flags, ve_detections[i]);

                    result->ve_trigger   = ve_results[0] ? 1 : 0;
                    result->ve_lbr_stack = ve_results[1] ? 1 : 0;
                    result->ve_xsetbv_gp = ve_results[2] ? 1 : 0;
                    result->ve_cr4_vmxe  = ve_results[3] ? 1 : 0;
                }

                safety_net::free_safety_net();
                kernel_path_completed = true;
            }
        }

        HVD_LOG_IMMEDIATE("kernel_path_post flags=0x%llx completed=%u physmem_initialized=%u cpu=%lu irql=%lu pid=%llu tid=%llu",
            flags,
            kernel_path_completed ? 1u : 0u,
            physmem_initialized ? 1u : 0u,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        bool forced_hit = false;
        vm_fingerprint::vm_vendor_e cpuid_vendor = run_vendor_probe("vmf_cpuid_vendor", flags, vm_fingerprint::detect_cpuid_vendor, &forced_hit);
        if (cpuid_vendor != vm_fingerprint::VM_VENDOR_NONE || forced_hit) {
            result->vmf_cpuid_vendor = 1;
            if (cpuid_vendor != vm_fingerprint::VM_VENDOR_NONE)
                copy_vendor_name(result, cpuid_vendor);
        }

        if (run_plain_bool_probe("vmf_hyperv_guest", flags, vm_fingerprint::detect_hyperv_guest_partition, true)) {
            result->vmf_hyperv_guest = 1;
            if (result->vm_vendor_name[0] == 0)
                copy_vendor_name(result, vm_fingerprint::VM_VENDOR_HYPERV_GUEST);
        }

        forced_hit = false;
        vm_fingerprint::vm_vendor_e smbios_vendor = run_vendor_probe("vmf_smbios", flags, vm_fingerprint::detect_smbios_string, &forced_hit);
        if (smbios_vendor != vm_fingerprint::VM_VENDOR_NONE || forced_hit) {
            result->vmf_smbios_vm = 1;
            if (result->vm_vendor_name[0] == 0 && smbios_vendor != vm_fingerprint::VM_VENDOR_NONE)
                copy_vendor_name(result, smbios_vendor);
        }

        forced_hit = false;
        vm_fingerprint::vm_vendor_e acpi_vendor = run_vendor_probe("vmf_acpi", flags, vm_fingerprint::detect_acpi_oem, &forced_hit);
        if (acpi_vendor != vm_fingerprint::VM_VENDOR_NONE || forced_hit) {
            result->vmf_acpi_vm = 1;
            if (result->vm_vendor_name[0] == 0 && acpi_vendor != vm_fingerprint::VM_VENDOR_NONE)
                copy_vendor_name(result, acpi_vendor);
        }

        forced_hit = false;
        vm_fingerprint::vm_vendor_e pci_vendor = run_vendor_probe("vmf_pci", flags, vm_fingerprint::detect_pci_device, &forced_hit);
        if (pci_vendor != vm_fingerprint::VM_VENDOR_NONE || forced_hit) {
            result->vmf_pci_vm = 1;
            if (result->vm_vendor_name[0] == 0 && pci_vendor != vm_fingerprint::VM_VENDOR_NONE)
                copy_vendor_name(result, pci_vendor);
        }

        forced_hit = false;
        vm_fingerprint::vm_vendor_e disk_vendor = run_vendor_probe("vmf_disk", flags, vm_fingerprint::detect_disk_model, &forced_hit);
        if (disk_vendor != vm_fingerprint::VM_VENDOR_NONE || forced_hit) {
            result->vmf_disk_vm = 1;
            if (result->vm_vendor_name[0] == 0 && disk_vendor != vm_fingerprint::VM_VENDOR_NONE)
                copy_vendor_name(result, disk_vendor);
        }

        forced_hit = false;
        vm_fingerprint::vm_vendor_e mac_vendor = run_vendor_probe("vmf_mac", flags, vm_fingerprint::detect_mac_oui, &forced_hit);
        if (mac_vendor != vm_fingerprint::VM_VENDOR_NONE || forced_hit) {
            result->vmf_mac_vm = 1;
            if (result->vm_vendor_name[0] == 0 && mac_vendor != vm_fingerprint::VM_VENDOR_NONE)
                copy_vendor_name(result, mac_vendor);
        }

        if (run_plain_bool_probe("vmf_registry", flags, vm_fingerprint::detect_registry_artifact, true)) {
            result->vmf_registry_vm = 1;
        }

        if (run_plain_bool_probe("vmf_qemu_fwcfg", flags, vm_fingerprint::detect_qemu_fwcfg, true)) {
            result->vmf_registry_vm = 1;
            if (result->vm_vendor_name[0] == 0)
                copy_vendor_name(result, vm_fingerprint::VM_VENDOR_QEMU_KVM);
        }

        UINT8 hv_total_run = 16;
        UINT8 hv_total_failed = 0;

        hv_total_failed += result->sidt_lock_prefix;
        hv_total_failed += result->sidt_invalid_pf;
        hv_total_failed += result->sidt_tlb_only;
        hv_total_failed += result->sidt_timing;
        hv_total_failed += result->sidt_compat_mode;
        hv_total_failed += result->sidt_noncanonical_gp;
        hv_total_failed += result->sidt_noncanonical_ss;
        hv_total_failed += result->sidt_cpl3_umip_off;
        hv_total_failed += result->sidt_cpl3_umip_on;
        hv_total_failed += result->lidt_lock_prefix;
        hv_total_failed += result->lidt_invalid_pf;
        hv_total_failed += result->lidt_tlb_only;
        hv_total_failed += result->lidt_timing;
        hv_total_failed += result->lidt_noncanonical_gp;
        hv_total_failed += result->lidt_noncanonical_ss;
        hv_total_failed += result->lidt_cpl3_gp;

        if (!ms_hv_root) {
            hv_total_run += 4;
            hv_total_failed += result->ve_trigger;
            hv_total_failed += result->ve_lbr_stack;
            hv_total_failed += result->ve_xsetbv_gp;
            hv_total_failed += result->ve_cr4_vmxe;
        }

        UINT8 vmf_total_run = 8;
        UINT8 vmf_total_hit = 0;
        vmf_total_hit += result->vmf_cpuid_vendor;
        vmf_total_hit += result->vmf_hyperv_guest;
        vmf_total_hit += result->vmf_smbios_vm;
        vmf_total_hit += result->vmf_acpi_vm;
        vmf_total_hit += result->vmf_pci_vm;
        vmf_total_hit += result->vmf_disk_vm;
        vmf_total_hit += result->vmf_mac_vm;
        vmf_total_hit += result->vmf_registry_vm;

        result->total_run = (UINT8)(hv_total_run + vmf_total_run);
        result->total_failed = (UINT8)(hv_total_failed + vmf_total_hit);

        const bool hard_vm_signal = (result->vmf_cpuid_vendor != 0) ||
                                     (result->vmf_hyperv_guest != 0) ||
                                     (result->vmf_smbios_vm != 0) ||
                                     (result->vmf_acpi_vm != 0) ||
                                     (result->vmf_disk_vm != 0) ||
                                     (result->vmf_registry_vm != 0);

        const uint8_t soft_vm_count = (uint8_t)(result->vmf_pci_vm + result->vmf_mac_vm);

        result->is_virtual_machine = (hard_vm_signal || soft_vm_count >= 2) ? 1 : 0;

        ve::seal_measurements_hmac(result, FIELD_OFFSET(hv_detect_result_k, measurements_hmac), FIELD_OFFSET(hv_detect_result_k, measurements_hmac));

        log_result_summary("run_all_exit", flags, result, STATUS_SUCCESS, run_start);
    }

    inline void run_all(hv_detect_result_k* result) {
        run_all(result, 0);
    }

    inline NTSTATUS handle_request(hv_detect_request_k* request, hv_detect_result_k* out_result) {
        const UINT64 flags = request ? request->flags : 0;
        trace_stamp_t start = trace_stamp();
        HVD_LOG_IMMEDIATE("handle_request_enter flags=0x%llx request_present=%u out_present=%u qpc=%lld tsc=%llu cpu=%lu irql=%lu pid=%llu tid=%llu",
            flags,
            request ? 1u : 0u,
            out_result ? 1u : 0u,
            start.qpc.QuadPart,
            start.tsc,
            current_cpu(),
            (ULONG)KeGetCurrentIrql(),
            current_pid(),
            current_tid());

        if (!out_result) {
            HVD_LOG_IMMEDIATE("handle_request_exit flags=0x%llx status=0x%08lx reason=missing_output elapsed_us=0 cpu=%lu irql=%lu pid=%llu tid=%llu",
                flags,
                STATUS_INVALID_PARAMETER,
                current_cpu(),
                (ULONG)KeGetCurrentIrql(),
                current_pid(),
                current_tid());
            return STATUS_INVALID_PARAMETER;
        }

        const ULONG request_irql = (ULONG)KeGetCurrentIrql();
        const UINT64 request_rflags = __readeflags();
        if (request_irql != PASSIVE_LEVEL || (request_rflags & 0x200ULL) == 0) {
            RtlZeroMemory(out_result, sizeof(hv_detect_result_k));
            out_result->total_run = 1;
            out_result->total_failed = 1;
            HVD_LOG_IMMEDIATE("handle_request_exit flags=0x%llx status=0x%08lx reason=unsafe_precondition passive=%u interrupts_enabled=%u cpu=%lu irql=%lu pid=%llu tid=%llu",
                flags,
                STATUS_INVALID_DEVICE_STATE,
                request_irql == PASSIVE_LEVEL ? 1u : 0u,
                (request_rflags & 0x200ULL) != 0 ? 1u : 0u,
                current_cpu(),
                request_irql,
                current_pid(),
                current_tid());
            return STATUS_INVALID_DEVICE_STATE;
        }

        NTSTATUS status = STATUS_SUCCESS;
        ULONG seh_code = 0;
        __try {
            run_all(out_result, flags);
        }
        __except ((seh_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
            RtlZeroMemory(out_result, sizeof(hv_detect_result_k));
            out_result->total_run = 1;
            out_result->total_failed = 1;
            status = STATUS_UNHANDLED_EXCEPTION;
            HVD_LOG_IMMEDIATE("handle_request_exception flags=0x%llx exception_code=0x%08lx status=0x%08lx cpu=%lu irql=%lu pid=%llu tid=%llu",
                flags,
                seh_code,
                status,
                current_cpu(),
                (ULONG)KeGetCurrentIrql(),
                current_pid(),
                current_tid());
        }

        log_result_summary("handle_request_exit", flags, out_result, status, start);
        return status;
    }
}
