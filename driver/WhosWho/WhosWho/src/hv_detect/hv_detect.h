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
    UINT8 ve_garbage_msr;
    UINT8 ve_xsetbv_gp;
    UINT8 ve_synthetic_msr;
    UINT8 ve_cpuid_leaf_cmp;
    UINT8 ve_rdtsc_cpuid;
    UINT8 ve_aperf_divergence;
    UINT8 ve_invd_cache;
    UINT8 ve_cr4_vmxe;
    UINT8 ve_lbr_tos;

    UINT8 total_failed;
    UINT8 total_run;
    UINT8 ms_hv_skipped;
    UINT8 padding[2];
} hv_detect_result_k, *p_hv_detect_result_k;
static_assert(sizeof(hv_detect_result_k) == 32, "hv_detect_result_k must be 32 bytes");
#pragma pack(pop)

namespace hv_detect {

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

    inline void run_all(hv_detect_result_k* result) {
        if (!result)
            return;

        RtlZeroMemory(result, sizeof(hv_detect_result_k));

        KIRQL old_irql = KeRaiseIrqlToDpcLevel();

        if (!physmem::support::is_physmem_supported()) {
            KeLowerIrql(old_irql);
            return;
        }

        if (!physmem::init_physmem()) {
            KeLowerIrql(old_irql);
            return;
        }

        UNICODE_STRING func_name;
        RtlInitUnicodeString(&func_name, L"PsGetCurrentProcess");
        PVOID kernel_func = MmGetSystemRoutineAddress(&func_name);
        uint64_t image_base = 0;
        uint64_t image_size = 0;

        {
            uint64_t search_addr = kernel_func ? (uint64_t)kernel_func : (uint64_t)&run_all;
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
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (!safety_net::init_safety_net(image_base, image_size)) {
            KeLowerIrql(old_irql);
            return;
        }

        safety_net::set_safety_net_kpcr(KeGetPcr());

        bool ms_hv = is_microsoft_hyperv_root();
        result->ms_hv_skipped = ms_hv ? 1 : 0;

        {
            safety_net_t storage;
            if (safety_net::start_safety_net(storage)) {

                bool sidt_results[9] = {};
                bool (*sidt_detections[])(void) = {
                    idt::storing::detection_1, idt::storing::detection_2,
                    idt::storing::detection_3, idt::storing::detection_4,
                    idt::storing::detection_5, idt::storing::detection_6,
                    idt::storing::detection_7, idt::storing::detection_8,
                    idt::storing::detection_9
                };
                for (int i = 0; i < 9; ++i)
                    sidt_results[i] = sidt_detections[i]();

                result->sidt_lock_prefix    = sidt_results[0] ? 1 : 0;
                result->sidt_invalid_pf     = sidt_results[1] ? 1 : 0;
                result->sidt_tlb_only       = sidt_results[2] ? 1 : 0;
                result->sidt_timing         = sidt_results[3] ? 1 : 0;
                result->sidt_compat_mode    = sidt_results[4] ? 1 : 0;
                result->sidt_noncanonical_gp = sidt_results[5] ? 1 : 0;
                result->sidt_noncanonical_ss = sidt_results[6] ? 1 : 0;
                result->sidt_cpl3_umip_off  = sidt_results[7] ? 1 : 0;
                result->sidt_cpl3_umip_on   = sidt_results[8] ? 1 : 0;

                bool lidt_results[7] = {};
                bool (*lidt_detections[])(void) = {
                    idt::loading::detection_1, idt::loading::detection_2,
                    idt::loading::detection_3, idt::loading::detection_4,
                    idt::loading::detection_5, idt::loading::detection_6,
                    idt::loading::detection_7
                };
                for (int i = 0; i < 7; ++i)
                    lidt_results[i] = lidt_detections[i]();

                result->lidt_lock_prefix     = lidt_results[0] ? 1 : 0;
                result->lidt_invalid_pf      = lidt_results[1] ? 1 : 0;
                result->lidt_tlb_only        = lidt_results[2] ? 1 : 0;
                result->lidt_timing          = lidt_results[3] ? 1 : 0;
                result->lidt_noncanonical_gp = lidt_results[4] ? 1 : 0;
                result->lidt_noncanonical_ss = lidt_results[5] ? 1 : 0;
                result->lidt_cpl3_gp         = lidt_results[6] ? 1 : 0;

                safety_net::stop_safety_net(storage);
            }
        }

        if (!ms_hv) {
            safety_net_t storage;
            if (safety_net::start_safety_net(storage)) {

                ve::image_base = safety_net::g_image_base;
                ve::image_size = safety_net::g_image_size;

                bool ve_results[11] = {};
                bool (*ve_detections[])(void) = {
                    ve::detection_1, ve::detection_2, ve::detection_3,
                    ve::detection_4, ve::detection_5, ve::detection_6,
                    ve::detection_7, ve::detection_8, ve::detection_9,
                    ve::detection_10, ve::detection_11
                };
                for (int i = 0; i < 11; ++i)
                    ve_results[i] = ve_detections[i]();

                result->ve_trigger         = ve_results[0] ? 1 : 0;
                result->ve_lbr_stack       = ve_results[1] ? 1 : 0;
                result->ve_garbage_msr     = ve_results[2] ? 1 : 0;
                result->ve_xsetbv_gp       = ve_results[3] ? 1 : 0;
                result->ve_synthetic_msr   = ve_results[4] ? 1 : 0;
                result->ve_cpuid_leaf_cmp  = ve_results[5] ? 1 : 0;
                result->ve_rdtsc_cpuid     = ve_results[6] ? 1 : 0;
                result->ve_aperf_divergence = ve_results[7] ? 1 : 0;
                result->ve_invd_cache      = ve_results[8] ? 1 : 0;
                result->ve_cr4_vmxe        = ve_results[9] ? 1 : 0;
                result->ve_lbr_tos         = ve_results[10] ? 1 : 0;

                safety_net::stop_safety_net(storage);
            }
        }

        UINT8 total_run = 16;
        UINT8 total_failed = 0;

        total_failed += result->sidt_lock_prefix;
        total_failed += result->sidt_invalid_pf;
        total_failed += result->sidt_tlb_only;
        total_failed += result->sidt_timing;
        total_failed += result->sidt_compat_mode;
        total_failed += result->sidt_noncanonical_gp;
        total_failed += result->sidt_noncanonical_ss;
        total_failed += result->sidt_cpl3_umip_off;
        total_failed += result->sidt_cpl3_umip_on;
        total_failed += result->lidt_lock_prefix;
        total_failed += result->lidt_invalid_pf;
        total_failed += result->lidt_tlb_only;
        total_failed += result->lidt_timing;
        total_failed += result->lidt_noncanonical_gp;
        total_failed += result->lidt_noncanonical_ss;
        total_failed += result->lidt_cpl3_gp;

        if (!ms_hv) {
            total_run += 11;
            total_failed += result->ve_trigger;
            total_failed += result->ve_lbr_stack;
            total_failed += result->ve_garbage_msr;
            total_failed += result->ve_xsetbv_gp;
            total_failed += result->ve_synthetic_msr;
            total_failed += result->ve_cpuid_leaf_cmp;
            total_failed += result->ve_rdtsc_cpuid;
            total_failed += result->ve_aperf_divergence;
            total_failed += result->ve_invd_cache;
            total_failed += result->ve_cr4_vmxe;
            total_failed += result->ve_lbr_tos;
        }

        result->total_run = total_run;
        result->total_failed = total_failed;

        safety_net::free_safety_net();

        KeLowerIrql(old_irql);
    }

    inline NTSTATUS handle_request(hv_detect_request_k* request, hv_detect_result_k* out_result) {
        UNREFERENCED_PARAMETER(request);

        if (!out_result)
            return STATUS_INVALID_PARAMETER;

        run_all(out_result);

        return STATUS_SUCCESS;
    }
}
