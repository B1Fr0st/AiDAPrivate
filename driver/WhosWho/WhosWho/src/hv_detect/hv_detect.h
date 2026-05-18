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

    inline void run_all(hv_detect_result_k* result) {
        if (!result)
            return;

        RtlZeroMemory(result, sizeof(hv_detect_result_k));

        const bool ms_hv_root = is_microsoft_hyperv_root();
        result->ms_hv_root = ms_hv_root ? 1 : 0;

        KIRQL old_irql = KeRaiseIrqlToDpcLevel();

        bool kernel_path_completed = false;

        if (physmem::support::is_physmem_supported() && physmem::init_physmem()) {
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

            if (!ms_hv_root && image_base != 0 && safety_net::init_safety_net(image_base, image_size)) {
                safety_net::set_safety_net_kpcr(KeGetPcr());

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

                if (!ms_hv_root) {
                    safety_net_t storage;
                    if (safety_net::start_safety_net(storage)) {

                        ve::image_base = safety_net::g_image_base;
                        ve::image_size = safety_net::g_image_size;

                        result->ve_trigger    = ve::detection_1() ? 1 : 0;
                        result->ve_lbr_stack  = ve::detection_2() ? 1 : 0;
                        result->ve_xsetbv_gp  = ve::detection_xsetbv_gp() ? 1 : 0;
                        result->ve_cr4_vmxe   = ve::detection_cr4_vmxe() ? 1 : 0;

                        safety_net::stop_safety_net(storage);
                    }
                }

                safety_net::free_safety_net();
                kernel_path_completed = true;
            }
        }

        UNREFERENCED_PARAMETER(kernel_path_completed);

        KeLowerIrql(old_irql);

        vm_fingerprint::vm_vendor_e cpuid_vendor = vm_fingerprint::detect_cpuid_vendor();
        if (cpuid_vendor != vm_fingerprint::VM_VENDOR_NONE) {
            result->vmf_cpuid_vendor = 1;
            copy_vendor_name(result, cpuid_vendor);
        }

        if (vm_fingerprint::detect_hyperv_guest_partition()) {
            result->vmf_hyperv_guest = 1;
            if (result->vm_vendor_name[0] == 0)
                copy_vendor_name(result, vm_fingerprint::VM_VENDOR_HYPERV_GUEST);
        }

        vm_fingerprint::vm_vendor_e smbios_vendor = vm_fingerprint::detect_smbios_string();
        if (smbios_vendor != vm_fingerprint::VM_VENDOR_NONE) {
            result->vmf_smbios_vm = 1;
            if (result->vm_vendor_name[0] == 0)
                copy_vendor_name(result, smbios_vendor);
        }

        vm_fingerprint::vm_vendor_e acpi_vendor = vm_fingerprint::detect_acpi_oem();
        if (acpi_vendor != vm_fingerprint::VM_VENDOR_NONE) {
            result->vmf_acpi_vm = 1;
            if (result->vm_vendor_name[0] == 0)
                copy_vendor_name(result, acpi_vendor);
        }

        vm_fingerprint::vm_vendor_e pci_vendor = vm_fingerprint::detect_pci_device();
        if (pci_vendor != vm_fingerprint::VM_VENDOR_NONE) {
            result->vmf_pci_vm = 1;
            if (result->vm_vendor_name[0] == 0)
                copy_vendor_name(result, pci_vendor);
        }

        vm_fingerprint::vm_vendor_e disk_vendor = vm_fingerprint::detect_disk_model();
        if (disk_vendor != vm_fingerprint::VM_VENDOR_NONE) {
            result->vmf_disk_vm = 1;
            if (result->vm_vendor_name[0] == 0)
                copy_vendor_name(result, disk_vendor);
        }

        vm_fingerprint::vm_vendor_e mac_vendor = vm_fingerprint::detect_mac_oui();
        if (mac_vendor != vm_fingerprint::VM_VENDOR_NONE) {
            result->vmf_mac_vm = 1;
            if (result->vm_vendor_name[0] == 0)
                copy_vendor_name(result, mac_vendor);
        }

        if (vm_fingerprint::detect_registry_artifact()) {
            result->vmf_registry_vm = 1;
        }

        if (vm_fingerprint::detect_qemu_fwcfg()) {
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
    }

    inline NTSTATUS handle_request(hv_detect_request_k* request, hv_detect_result_k* out_result) {
        UNREFERENCED_PARAMETER(request);

        if (!out_result)
            return STATUS_INVALID_PARAMETER;

        run_all(out_result);

        return STATUS_SUCCESS;
    }
}
