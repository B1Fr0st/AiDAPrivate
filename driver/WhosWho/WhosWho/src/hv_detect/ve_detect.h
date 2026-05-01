#pragma once
#include "includes.h"
#include "func_defs.h"
#include "physmem_decl.h"
#include <bcrypt.h>

namespace ve {
    inline uint64_t image_base = 0;
    inline uint64_t image_size = 0;

    typedef struct
    {
        union
        {
            struct
            {
                uint32_t max_lbr_records : 8;
#define CPUID1C_EAX_MAX_LBR_RECORDS_BIT   0
#define CPUID1C_EAX_MAX_LBR_RECORDS_MASK  0x000000FFu
#define CPUID1C_EAX_MAX_LBR_RECORDS(x)    ((uint32_t)((x) & 0xFFu))

                uint32_t reserved0 : 23;

                uint32_t lip : 1;
#define CPUID1C_EAX_LIP_BIT   31
#define CPUID1C_EAX_LIP_FLAG  0x80000000u
#define CPUID1C_EAX_LIP(x)    (((uint32_t)(x) >> 31) & 0x1u)
            };
            uint32_t flags;
        } eax;

        union
        {
            uint32_t flags;
        } ebx;

        union
        {
            struct
            {
                uint32_t reserved0 : 16;
                uint32_t evlog_bitmap : 4;
#define CPUID1C_ECX_EVLOG_BITMAP_BIT   16
#define CPUID1C_ECX_EVLOG_BITMAP_MASK  0x000F0000u
#define CPUID1C_ECX_EVLOG_BITMAP(x)    (((uint32_t)(x) >> 16) & 0xFu)

                uint32_t reserved1 : 12;
            };
            uint32_t flags;
        } ecx;

        union {
            uint32_t flags;
        } edx;
    } cpuid_eax_1c;

    typedef union _ia32_lbr_ctl_register
    {
        struct
        {
            uint64_t lbr_en : 1;
            uint64_t cond : 1;
            uint64_t near_ind_jmp : 1;
            uint64_t near_rel_jmp : 1;
            uint64_t near_ind_call : 1;
            uint64_t near_rel_call : 1;
            uint64_t near_ret : 1;
            uint64_t other_branch : 1;
            uint64_t call_stack : 1;
            uint64_t os : 1;
            uint64_t usr : 1;
            uint64_t reserved : 53;
        };

        uint64_t flags;

    } ia32_lbr_ctl_register;

    typedef enum _lbr_mode_t {
        LBR_MODE_NONE = 0,
        LBR_MODE_LEGACY,
        LBR_MODE_ARCH
    } lbr_mode_t;

    struct legacy_lbr_caps_t {
        bool supported;
        uint8_t depth;
        bool has_info1;
    };

    typedef struct {
        lbr_mode_t mode;
        uint32_t depth;
    } lbr_config_t;

#define IA32_LBR_CTL               0x14CE
#define IA32_LBR_DEPTH             0x14CF

#define IA32_ARCH_LBR_0_FROM_IP         0x1500
#define IA32_ARCH_LBR_0_TO_IP           0x1600

#define IA32_LBR_0_FROM_IP 0x680
#define IA32_LBR_0_TO_IP 0x6C0
#define IA32_LASTBRANCH_TOS 0x1C9

#define LBR_FORMAT_32              0x0
#define LBR_FORMAT_LIP             0x1
#define LBR_FORMAT_EIP             0x2
#define LBR_FORMAT_EIP_FLAGS       0x3
#define LBR_FORMAT_EIP_FLAGS2      0x4
#define LBR_FORMAT_INFO            0x5
#define LBR_FORMAT_TIME            0x6
#define LBR_FORMAT_INFO2           0x7
#define LBR_PERF_UNSSUPORTED       0x3F


    inline legacy_lbr_caps_t get_legacy_lbr_caps() {
        legacy_lbr_caps_t caps{};
        caps.supported = false;
        caps.depth = 0;
        caps.has_info1 = false;

        cpuid_eax_01 cpuid_1{};
        __cpuid((int*)&cpuid_1, 1);

        uint32_t fam = cpuid_1.cpuid_version_information.family_id;
        uint32_t extfam = cpuid_1.cpuid_version_information.extended_family_id;
        if (fam == 0x0F)
            fam += extfam;

        uint32_t model = cpuid_1.cpuid_version_information.model;
        uint32_t extmodel = cpuid_1.cpuid_version_information.extended_model_id;
        if (cpuid_1.cpuid_version_information.family_id == 0x06 ||
            cpuid_1.cpuid_version_information.family_id == 0x0F) {
            model |= (extmodel << 4);
        }
        if (fam != 0x06)
            return caps;

        static constexpr uint8_t depth32_noinfo[] = { 0x5C, 0x5F };

        static constexpr uint8_t depth32_info1[] = {
            0x4E, 0x5E, 0x8E, 0x9E, 0x55,
            0x66, 0x7A, 0x67, 0x6A, 0x6C,
            0x7D, 0x7E, 0x8C, 0x8D, 0x6A,
            0xA5, 0xA6, 0xA7, 0xA8, 0x86,
            0x8A, 0x96, 0x9C
        };

        static constexpr uint8_t depth16[] = {
            0x3D, 0x47, 0x4F, 0x56, 0x3C,
            0x45, 0x46, 0x3F, 0x2A, 0x2D,
            0x3A, 0x3E, 0x1A, 0x1E, 0x1F,
            0x2E, 0x25, 0x2C, 0x2F
        };

        static constexpr uint8_t depth4[] = { 0x17, 0x1D, 0x0F };

        static constexpr uint8_t depth8[] = {
            0x37, 0x4A, 0x4C, 0x4D, 0x5A,
            0x5D, 0x1C, 0x26, 0x27, 0x35,
            0x36
        };

        for (uint32_t i = 0; i < sizeof(depth32_noinfo); ++i) {
            if (model == depth32_noinfo[i]) {
                caps.supported = true;
                caps.depth = 32;
                caps.has_info1 = false;
                return caps;
            }
        }

        for (uint32_t i = 0; i < sizeof(depth32_info1); ++i) {
            if (model == depth32_info1[i]) {
                caps.supported = true;
                caps.depth = 32;
                caps.has_info1 = true;
                return caps;
            }
        }

        for (uint32_t i = 0; i < sizeof(depth16); ++i) {
            if (model == depth16[i]) {
                caps.supported = true;
                caps.depth = 16;
                caps.has_info1 = false;
                return caps;
            }
        }

        for (uint32_t i = 0; i < sizeof(depth8); ++i) {
            if (model == depth8[i]) {
                caps.supported = true;
                caps.depth = 8;
                caps.has_info1 = false;
                return caps;
            }
        }

        for (uint32_t i = 0; i < sizeof(depth4); ++i) {
            if (model == depth4[i]) {
                caps.supported = true;
                caps.depth = 4;
                caps.has_info1 = false;
                return caps;
            }
        }

        return caps;
    }


    inline bool detection_1(void) {
        safety_net::idt::reset_interrupt_count();

        bool hypervisor_detected = false;
        uint64_t curr_interrupt_count = safety_net::idt::get_interrupt_count();

        __try {
            __cause_ve();
            hypervisor_detected = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            uint64_t new_interrupt_count = safety_net::idt::get_interrupt_count();
            idt_regs_ecode_t* last_int = safety_net::idt::get_core_last_interrupt_record();

            if (last_int->exception_vector != virtualization_exception ||
                curr_interrupt_count == new_interrupt_count)
                hypervisor_detected = true;
        }

        return hypervisor_detected;
    }


    inline bool detection_2(void) {

        cpuid_eax_01 cpuid_1;
        __cpuid((int*)&cpuid_1, 1);
        if (!cpuid_1.cpuid_feature_information_ecx.perfmon_and_debug_capability) {
            return false;
        }

        ia32_perf_capabilities_register cap;
        cap.flags = __readmsr(IA32_PERF_CAPABILITIES);

        bool lbr_supported = (cap.lbr_format != LBR_PERF_UNSSUPORTED);

        lbr_config_t config;

        cpuid_eax_07 cpuid_7;
        __cpuid((int*)&cpuid_7, CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS);
        if (cpuid_7.edx.arch_lbr) {
            config.mode = lbr_mode_t::LBR_MODE_ARCH;

            if (!lbr_supported) {
                return true;
            }
        }
        else {
            config.mode = lbr_mode_t::LBR_MODE_LEGACY;
        }

        bool hv_detected = false;

        if (lbr_supported && config.mode == lbr_mode_t::LBR_MODE_LEGACY) {
            legacy_lbr_caps_t lbr_caps = get_legacy_lbr_caps();
            if (!lbr_caps.has_info1)
                return false;

            uint32_t depth = (uint32_t)lbr_caps.depth;

            ia32_debugctl_register debug_ctl{};
            ia32_debugctl_register old_debug_ctl{};
            uint64_t old_lbr_select = 0;

            __try { old_debug_ctl.flags = __readmsr(IA32_DEBUGCTL); }
            __except (EXCEPTION_EXECUTE_HANDLER) { return true; }

            uint64_t new_lbr_select = old_lbr_select;
            new_lbr_select = ~0ull;

            __try {
                __try { __writemsr(IA32_DEBUGCTL, 0); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }

                for (uint32_t i = 0; i < depth; ++i) {
                    __try { __writemsr(IA32_LBR_0_FROM_IP + i, 0); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }

                    __try { __writemsr(IA32_LBR_0_TO_IP + i, 0); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }
                }

                debug_ctl.flags = 0;
                debug_ctl.lbr = 1;
                debug_ctl.freeze_lbrs_on_pmi = 1;

                __try { __writemsr(IA32_DEBUGCTL, debug_ctl.flags); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }

                safety_net::idt::set_should_disable_lbr_in_handler(true);

                __cause_ve();

                __try { __writemsr(IA32_DEBUGCTL, 0); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                safety_net::idt::set_should_disable_lbr_in_handler(false);

                __try { __writemsr(IA32_DEBUGCTL, 0); }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
                __try { __writemsr(IA32_DEBUGCTL, old_debug_ctl.flags); }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            uint64_t tos = 0;
            __try { tos = __readmsr(IA32_LASTBRANCH_TOS); }
            __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; }

            const uint64_t image_end = image_base + image_size;

            const uint32_t tos_idx = (depth != 0) ? (uint32_t)(tos % depth) : 0;

            for (uint32_t k = 0; k < depth; ++k) {
                const uint32_t idx = (uint32_t)((tos_idx + depth - k) % depth);

                uint64_t from = 0, to = 0;

                __try { from = __readmsr(IA32_LBR_0_FROM_IP + idx); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; break; }

                __try { to = __readmsr(IA32_LBR_0_TO_IP + idx); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; break; }

                if ((from | to) == 0)
                    continue;

                if (from != 0 && from != MAXUINT64) {
                    if (from < image_base || from >= image_end) {
                        hv_detected = true;
                    }
                }

                if (to != 0) {
                    if (to < image_base || to >= image_end) {
                        hv_detected = true;
                    }
                }
            }

            __try { __writemsr(IA32_DEBUGCTL, 0); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}

            __try { __writemsr(IA32_DEBUGCTL, old_debug_ctl.flags); }
            __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; }

            return hv_detected;
        }
        else if (lbr_supported && config.mode == lbr_mode_t::LBR_MODE_ARCH) {
            cpuid_eax_1c cpuid_1c;
            __cpuid((int*)&cpuid_1c, 0x1c);

            uint64_t max_lbr_record_count = cpuid_1c.eax.max_lbr_records;
            if (lbr_supported && (max_lbr_record_count == 0 || max_lbr_record_count > 32)) {
                return true;
            }

            uint64_t old_ctl = 0, old_depth = 0;

            __try {
                old_ctl = __readmsr(IA32_LBR_CTL);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return true;
            }

            __try {
                old_depth = __readmsr(IA32_LBR_DEPTH);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return true;
            }

            ia32_lbr_ctl_register new_ctl{};
            new_ctl.flags = 0;
            new_ctl.lbr_en = 1;
            new_ctl.cond = 1;
            new_ctl.near_ind_jmp = 1;
            new_ctl.near_rel_jmp = 1;
            new_ctl.near_ind_call = 1;
            new_ctl.near_rel_call = 1;
            new_ctl.near_ret = 1;
            new_ctl.other_branch = 1;
            new_ctl.os = 1;

            __try {

                __try { __writemsr(IA32_LBR_CTL, 0); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }


                __try { __writemsr(IA32_LBR_DEPTH, max_lbr_record_count); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }


                for (uint32_t i = 0; i < (uint32_t)max_lbr_record_count; ++i) {
                    __try { __writemsr(IA32_ARCH_LBR_0_FROM_IP + i, 0); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }

                    __try { __writemsr(IA32_ARCH_LBR_0_TO_IP + i, 0); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }
                }

                __try { __writemsr(IA32_LBR_CTL, new_ctl.flags); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }


                __cause_ve();

                __try { __writemsr(IA32_LBR_CTL, 0); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {

                __try { __writemsr(IA32_LBR_CTL, 0); }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            const uint64_t image_end = image_base + image_size;

            for (uint32_t i = 0; i < (uint32_t)max_lbr_record_count; ++i) {
                uint64_t from = 0, to = 0;

                __try {
                    from = __readmsr(IA32_LBR_0_FROM_IP + i);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; break; }

                __try {
                    to = __readmsr(IA32_LBR_0_TO_IP + i);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; break; }

                if ((from | to) == 0)
                    continue;

                if (from != 0 && from != MAXUINT64) {
                    if (from < image_base || from >= image_end) {
                        hv_detected = true;
                        break;
                    }
                }

                if (to != 0) {
                    if (to < image_base || to >= image_end) {
                        hv_detected = true;
                        break;
                    }
                }
            }


            __try { __writemsr(IA32_LBR_CTL, 0); }
            __except (EXCEPTION_EXECUTE_HANDLER) {  }

            __try { __writemsr(IA32_LBR_DEPTH, old_depth); }
            __except (EXCEPTION_EXECUTE_HANDLER) {  }

            __try { __writemsr(IA32_LBR_CTL, old_ctl); }
            __except (EXCEPTION_EXECUTE_HANDLER) {  }

            return hv_detected;
        }
        else {
            return false;
        }
    }


    inline bool detection_xsetbv_gp(void) {
        int regs[4] = {};
        __cpuid(regs, 1);
        bool osxsave = (regs[2] & (1 << 27)) != 0;
        if (!osxsave)
            return false;

        uint64_t xcr0 = 0;
        __try {
            xcr0 = _xgetbv(0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        if ((xcr0 & 1ULL) == 0)
            return false;

        bool got_gp = false;
        __try {
            _xsetbv(0, xcr0 & ~1ULL);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            got_gp = true;
        }

        __try {
            _xsetbv(0, xcr0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        return !got_gp;
    }


    inline bool detection_cr4_vmxe(void) {
        uint64_t cr4 = __readcr4();
        bool vmxe_visible = (cr4 & (1ULL << 13)) != 0;

        if (vmxe_visible)
            return false;

        bool got_ud = false;
        size_t field_val = 0;
        __try {
            __vmx_vmread(0x4800, &field_val);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            got_ud = true;
        }

        return !got_ud;
    }


    inline bool is_microsoft_hyperv_root_local() {
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

    inline void seal_measurements_hmac(void* result_ptr, SIZE_T body_length, SIZE_T hmac_offset) {
        if (!result_ptr)
            return;

        UCHAR* base = static_cast<UCHAR*>(result_ptr);
        constexpr SIZE_T HMAC_LEN = 16;

        UCHAR session_key[32] = {
            0x9E, 0x37, 0x79, 0xB9, 0x7F, 0x4A, 0x7C, 0x15,
            0xF3, 0x9C, 0xC0, 0x60, 0x5C, 0xED, 0xC8, 0x34,
            0x10, 0x82, 0x76, 0xBC, 0x4F, 0x90, 0x6B, 0x42,
            0x95, 0xD0, 0xC1, 0x06, 0x67, 0x4F, 0xB7, 0x21
        };

        BCRYPT_ALG_HANDLE alg = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!NT_SUCCESS(st)) {
            RtlZeroMemory(base + hmac_offset, HMAC_LEN);
            return;
        }

        BCRYPT_HASH_HANDLE hh = nullptr;
        st = BCryptCreateHash(alg, &hh, nullptr, 0, session_key, sizeof(session_key), 0);
        if (!NT_SUCCESS(st)) {
            BCryptCloseAlgorithmProvider(alg, 0);
            RtlZeroMemory(base + hmac_offset, HMAC_LEN);
            return;
        }

        st = BCryptHashData(hh, base, static_cast<ULONG>(body_length), 0);
        if (NT_SUCCESS(st)) {
            UCHAR full_hash[32] = {};
            st = BCryptFinishHash(hh, full_hash, sizeof(full_hash), 0);
            if (NT_SUCCESS(st)) {
                RtlCopyMemory(base + hmac_offset, full_hash, HMAC_LEN);
            }
            else {
                RtlZeroMemory(base + hmac_offset, HMAC_LEN);
            }
        }
        else {
            RtlZeroMemory(base + hmac_offset, HMAC_LEN);
        }

        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    inline void execute_ve_detections(void) {
        if (is_microsoft_hyperv_root_local())
            return;

        safety_net_t storage;
        if (!safety_net::start_safety_net(storage))
            return;

        image_base = safety_net::g_image_base;
        image_size = safety_net::g_image_size;

        const int num_detections = 4;
        bool detection_results[num_detections];
        bool (*detections[])(void) = {
            detection_1,
            detection_2,
            detection_xsetbv_gp,
            detection_cr4_vmxe,
        };

        const char* detection_names[] = {
            "VE trigger",
            "LBR stack after VE",
            "XSETBV GP injection",
            "CR4.VMXE + VMX check",
        };

        for (int i = 0; i < num_detections; ++i) {
            detection_results[i] = detections[i]();
        }

        safety_net::stop_safety_net(storage);

        int failed = 0;
        for (int i = 0; i < num_detections; ++i) {
            if (detection_results[i]) {
                log_error_indent(2, "Failed detection %d (%s)", i + 1, detection_names[i]);
                ++failed;
            }
            else {
                log_success_indent(2, "Passed detection %d (%s)", i + 1, detection_names[i]);
            }
        }

        if (failed > 0) {
            log_error_indent(2, "%d / %d detections failed", failed, num_detections);
        }
    }
};


namespace vm_fingerprint {

#define VMF_FIRMWARE_RSMB 0x52534D42u
#define VMF_FIRMWARE_ACPI 0x41435049u

    enum vm_vendor_e : uint8_t {
        VM_VENDOR_NONE = 0,
        VM_VENDOR_KVM,
        VM_VENDOR_QEMU_TCG,
        VM_VENDOR_VMWARE,
        VM_VENDOR_VIRTUALBOX,
        VM_VENDOR_XEN,
        VM_VENDOR_PARALLELS,
        VM_VENDOR_BHYVE,
        VM_VENDOR_HYPERV_GUEST,
        VM_VENDOR_BOCHS,
        VM_VENDOR_QEMU_KVM,
    };

    inline const char* vendor_name(vm_vendor_e v) {
        switch (v) {
            case VM_VENDOR_KVM:           return "KVM";
            case VM_VENDOR_QEMU_TCG:      return "QEMU-TCG";
            case VM_VENDOR_QEMU_KVM:      return "QEMU/KVM";
            case VM_VENDOR_VMWARE:        return "VMware";
            case VM_VENDOR_VIRTUALBOX:    return "VirtualBox";
            case VM_VENDOR_XEN:           return "Xen";
            case VM_VENDOR_PARALLELS:     return "Parallels";
            case VM_VENDOR_BHYVE:         return "bhyve";
            case VM_VENDOR_HYPERV_GUEST:  return "HyperV-Guest";
            case VM_VENDOR_BOCHS:         return "Bochs";
            default:                      return "";
        }
    }

    inline bool ascii_iequal(const char* a, const char* b, SIZE_T n) {
        for (SIZE_T i = 0; i < n; ++i) {
            char ca = a[i];
            char cb = b[i];
            if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 0x20);
            if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 0x20);
            if (ca != cb) return false;
        }
        return true;
    }

    inline bool buffer_contains_ci(const uint8_t* buf, SIZE_T size, const char* needle) {
        SIZE_T nl = 0;
        while (needle[nl]) ++nl;
        if (nl == 0 || size < nl) return false;
        for (SIZE_T i = 0; i + nl <= size; ++i) {
            if (ascii_iequal((const char*)(buf + i), needle, nl))
                return true;
        }
        return false;
    }

    inline vm_vendor_e detect_cpuid_vendor(void) {
        int regs[4] = {};
        __cpuid(regs, 1);
        if ((regs[2] & (1 << 31)) == 0)
            return VM_VENDOR_NONE;

        __cpuid(regs, 0x40000000);
        char vendor[13] = {};
        *(int*)(vendor + 0) = regs[1];
        *(int*)(vendor + 4) = regs[2];
        *(int*)(vendor + 8) = regs[3];
        vendor[12] = 0;

        static const struct {
            const char* sig;
            vm_vendor_e vendor;
        } known[] = {
            { "KVMKVMKVM\0\0\0", VM_VENDOR_KVM },
            { "TCGTCGTCGTCG",    VM_VENDOR_QEMU_TCG },
            { "VMwareVMware",    VM_VENDOR_VMWARE },
            { "VBoxVBoxVBox",    VM_VENDOR_VIRTUALBOX },
            { "XenVMMXenVMM",    VM_VENDOR_XEN },
            { "prl hyperv ",     VM_VENDOR_PARALLELS },
            { " lrpepyh vr",     VM_VENDOR_PARALLELS },
            { "bhyve bhyve ",    VM_VENDOR_BHYVE },
            { "ACRNACRNACRN",    VM_VENDOR_BHYVE },
        };

        for (const auto& k : known) {
            if (memcmp(vendor, k.sig, 12) == 0)
                return k.vendor;
        }

        char hv[12] = { 'M','i','c','r','o','s','o','f','t',' ','H','v' };
        if (memcmp(vendor, hv, 12) == 0) {
            __cpuid(regs, 0x40000001);
            if ((uint32_t)regs[0] != 0x31237648u)
                return VM_VENDOR_QEMU_KVM;

            __cpuid(regs, 0x40000003);
            uint32_t partition_priv = (uint32_t)regs[0];
            const uint32_t root_bits = (1u << 0) | (1u << 1) | (1u << 5);
            if ((partition_priv & root_bits) == 0)
                return VM_VENDOR_HYPERV_GUEST;
        }

        return VM_VENDOR_NONE;
    }

    inline bool detect_hyperv_guest_partition(void) {
        int regs[4] = {};
        __cpuid(regs, 1);
        if ((regs[2] & (1 << 31)) == 0)
            return false;

        __cpuid(regs, 0x40000000);
        char vendor[12];
        *(int*)(vendor + 0) = regs[1];
        *(int*)(vendor + 4) = regs[2];
        *(int*)(vendor + 8) = regs[3];

        char hv[12] = { 'M','i','c','r','o','s','o','f','t',' ','H','v' };
        if (memcmp(vendor, hv, 12) != 0)
            return false;

        __cpuid(regs, 0x40000001);
        if ((uint32_t)regs[0] != 0x31237648u)
            return false;

        __cpuid(regs, 0x40000003);
        uint32_t partition_priv = (uint32_t)regs[0];
        const uint32_t root_bits = (1u << 0) | (1u << 1) | (1u << 5);
        return (partition_priv & root_bits) == 0;
    }

    inline NTSTATUS get_firmware_table(ULONG provider, ULONG table_id, void** out_buf, ULONG* out_size) {
        *out_buf = nullptr;
        *out_size = 0;

        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_UNSUCCESSFUL;

        UNICODE_STRING fn_name;
        RtlInitUnicodeString(&fn_name, L"ExGetSystemFirmwareTable");
        using ExGetSystemFirmwareTable_t = NTSTATUS(NTAPI*)(ULONG, ULONG, PVOID, ULONG, PULONG);
        auto fn = reinterpret_cast<ExGetSystemFirmwareTable_t>(MmGetSystemRoutineAddress(&fn_name));
        if (!fn)
            return STATUS_NOT_IMPLEMENTED;

        ULONG size_needed = 0;
        NTSTATUS qst = fn(provider, table_id, nullptr, 0, &size_needed);
        if (size_needed == 0 || size_needed > 0x200000)
            return STATUS_BUFFER_TOO_SMALL;

        PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size_needed, 'fmVH');
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;

        ULONG written = 0;
        qst = fn(provider, table_id, buf, size_needed, &written);
        if (!NT_SUCCESS(qst) || written == 0) {
            ExFreePoolWithTag(buf, 'fmVH');
            return qst;
        }

        *out_buf = buf;
        *out_size = written;
        return STATUS_SUCCESS;
    }

    inline vm_vendor_e detect_smbios_string(void) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return VM_VENDOR_NONE;

        void* buf = nullptr;
        ULONG size = 0;
        NTSTATUS st = get_firmware_table(VMF_FIRMWARE_RSMB, 0, &buf, &size);
        if (!NT_SUCCESS(st) || !buf || size == 0)
            return VM_VENDOR_NONE;

        const uint8_t* data = static_cast<const uint8_t*>(buf);

        vm_vendor_e found = VM_VENDOR_NONE;

        if (buffer_contains_ci(data, size, "QEMU") ||
            buffer_contains_ci(data, size, "BXPC") ||
            buffer_contains_ci(data, size, "OVMF") ||
            buffer_contains_ci(data, size, "EDK II") ||
            buffer_contains_ci(data, size, "Tianocore") ||
            buffer_contains_ci(data, size, "Standard PC (Q35") ||
            buffer_contains_ci(data, size, "SeaBIOS")) {
            found = VM_VENDOR_QEMU_KVM;
        }
        else if (buffer_contains_ci(data, size, "Bochs") ||
                 buffer_contains_ci(data, size, "BOCHS")) {
            found = VM_VENDOR_BOCHS;
        }
        else if (buffer_contains_ci(data, size, "innotek GmbH") ||
                 buffer_contains_ci(data, size, "innotek") ||
                 buffer_contains_ci(data, size, "VirtualBox") ||
                 buffer_contains_ci(data, size, "VBOX")) {
            found = VM_VENDOR_VIRTUALBOX;
        }
        else if (buffer_contains_ci(data, size, "VMware, Inc.") ||
                 buffer_contains_ci(data, size, "VMware Virtual") ||
                 buffer_contains_ci(data, size, "VMware7,1")) {
            found = VM_VENDOR_VMWARE;
        }
        else if (buffer_contains_ci(data, size, "Xen") &&
                 (buffer_contains_ci(data, size, "HVM") ||
                  buffer_contains_ci(data, size, "domU"))) {
            found = VM_VENDOR_XEN;
        }
        else if (buffer_contains_ci(data, size, "Parallels Software") ||
                 buffer_contains_ci(data, size, "Parallels Virtual")) {
            found = VM_VENDOR_PARALLELS;
        }

        ExFreePoolWithTag(buf, 'fmVH');
        return found;
    }

    inline vm_vendor_e detect_acpi_oem(void) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return VM_VENDOR_NONE;

        void* enum_buf = nullptr;
        ULONG enum_size = 0;
        NTSTATUS st = get_firmware_table(VMF_FIRMWARE_ACPI, 0, &enum_buf, &enum_size);
        if (!NT_SUCCESS(st) || !enum_buf || enum_size < 4) {
            return VM_VENDOR_NONE;
        }

        const uint32_t* sigs = static_cast<const uint32_t*>(enum_buf);
        ULONG sig_count = enum_size / sizeof(uint32_t);

        vm_vendor_e found = VM_VENDOR_NONE;
        bool has_waet = false;
        const uint32_t waet_sig = 0x54454157u;

        for (ULONG i = 0; i < sig_count; ++i) {
            if (sigs[i] == waet_sig) {
                has_waet = true;
                break;
            }
        }

        for (ULONG i = 0; i < sig_count && found == VM_VENDOR_NONE; ++i) {
            uint32_t table_id = sigs[i];
            void* table_buf = nullptr;
            ULONG table_size = 0;
            NTSTATUS qst = get_firmware_table(VMF_FIRMWARE_ACPI, table_id, &table_buf, &table_size);
            if (!NT_SUCCESS(qst) || !table_buf || table_size < 36) {
                if (table_buf) ExFreePoolWithTag(table_buf, 'fmVH');
                continue;
            }

            const uint8_t* hdr = static_cast<const uint8_t*>(table_buf);
            char oem_id[7] = {};
            char oem_table_id[9] = {};
            memcpy(oem_id, hdr + 10, 6);
            memcpy(oem_table_id, hdr + 16, 8);

            if (memcmp(oem_id, "BOCHS ", 6) == 0 || memcmp(oem_id, "BOCHS\0", 6) == 0) {
                found = VM_VENDOR_QEMU_KVM;
            }
            else if (memcmp(oem_id, "BXPC  ", 6) == 0 || memcmp(oem_id, "BXPC\0\0", 6) == 0) {
                found = VM_VENDOR_QEMU_KVM;
            }
            else if (memcmp(oem_id, "KVMKVM", 6) == 0) {
                found = VM_VENDOR_QEMU_KVM;
            }
            else if (memcmp(oem_id, "VRTUAL", 6) == 0) {
                found = VM_VENDOR_QEMU_KVM;
            }
            else if (memcmp(oem_id, "VBOX  ", 6) == 0 || memcmp(oem_id, "VBOX\0\0", 6) == 0 ||
                     memcmp(oem_id, "VBOXVB", 6) == 0) {
                found = VM_VENDOR_VIRTUALBOX;
            }
            else if (memcmp(oem_id, "VMWARE", 6) == 0) {
                found = VM_VENDOR_VMWARE;
            }
            else if (memcmp(oem_id, "Xen   ", 6) == 0 || memcmp(oem_id, "XEN   ", 6) == 0) {
                found = VM_VENDOR_XEN;
            }
            else if (memcmp(oem_id, "PRLS  ", 6) == 0 || memcmp(oem_id, "Parall", 6) == 0) {
                found = VM_VENDOR_PARALLELS;
            }
            else if (memcmp(oem_id, "INTEL ", 6) == 0 &&
                     (memcmp(oem_table_id, "BOCHS", 5) == 0 ||
                      memcmp(oem_table_id, "BXPC", 4) == 0)) {
                found = VM_VENDOR_QEMU_KVM;
            }
            else if (memcmp(oem_table_id, "BXPC", 4) == 0) {
                found = VM_VENDOR_QEMU_KVM;
            }
            else if (memcmp(oem_table_id, "VBOX", 4) == 0) {
                found = VM_VENDOR_VIRTUALBOX;
            }
            else if (memcmp(oem_table_id, "VMW ", 4) == 0 ||
                     memcmp(oem_table_id, "VMWARE", 6) == 0) {
                found = VM_VENDOR_VMWARE;
            }

            ExFreePoolWithTag(table_buf, 'fmVH');
        }

        if (found == VM_VENDOR_NONE && has_waet && !ve::is_microsoft_hyperv_root_local()) {
            found = VM_VENDOR_QEMU_KVM;
        }

        ExFreePoolWithTag(enum_buf, 'fmVH');
        return found;
    }

    inline vm_vendor_e detect_pci_device(void) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return VM_VENDOR_NONE;

        UNICODE_STRING reg_path;
        RtlInitUnicodeString(&reg_path, L"\\Registry\\Machine\\System\\CurrentControlSet\\Enum\\PCI");

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &reg_path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE root = nullptr;
        NTSTATUS st = ZwOpenKey(&root, KEY_READ, &oa);
        if (!NT_SUCCESS(st))
            return VM_VENDOR_NONE;

        vm_vendor_e found = VM_VENDOR_NONE;

        const ULONG name_buf_size = 1024;
        UCHAR* name_buf = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, name_buf_size, 'pcVH'));
        if (!name_buf) {
            ZwClose(root);
            return VM_VENDOR_NONE;
        }

        for (ULONG idx = 0; idx < 1024 && found == VM_VENDOR_NONE; ++idx) {
            ULONG ret_len = 0;
            NTSTATUS est = ZwEnumerateKey(root, idx, KeyBasicInformation, name_buf, name_buf_size, &ret_len);
            if (est == STATUS_NO_MORE_ENTRIES)
                break;
            if (!NT_SUCCESS(est))
                continue;

            auto* basic = reinterpret_cast<KEY_BASIC_INFORMATION*>(name_buf);
            if (basic->NameLength == 0)
                continue;

            wchar_t lower[256] = {};
            ULONG copy = basic->NameLength / sizeof(wchar_t);
            if (copy >= 255) copy = 255;
            for (ULONG i = 0; i < copy; ++i) {
                wchar_t c = basic->Name[i];
                if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 0x20);
                lower[i] = c;
            }
            lower[copy] = 0;

            if (wcsstr(lower, L"ven_1af4") || wcsstr(lower, L"ven_1b36") || wcsstr(lower, L"ven_1b21"))
                found = VM_VENDOR_QEMU_KVM;
            else if (wcsstr(lower, L"ven_80ee"))
                found = VM_VENDOR_VIRTUALBOX;
            else if (wcsstr(lower, L"ven_15ad"))
                found = VM_VENDOR_VMWARE;
            else if (wcsstr(lower, L"ven_5853"))
                found = VM_VENDOR_XEN;
            else if (wcsstr(lower, L"ven_1ab8"))
                found = VM_VENDOR_PARALLELS;
        }

        ExFreePoolWithTag(name_buf, 'pcVH');
        ZwClose(root);
        return found;
    }

    inline vm_vendor_e match_disk_identifier(const wchar_t* lower) {
        if (wcsstr(lower, L"qemu") ||
            wcsstr(lower, L"qemu harddisk") ||
            wcsstr(lower, L"qemu dvd-rom") ||
            wcsstr(lower, L"qemu qemu harddisk") ||
            wcsstr(lower, L"ata qemu") ||
            wcsstr(lower, L"qm00"))
            return VM_VENDOR_QEMU_KVM;
        if (wcsstr(lower, L"vbox") ||
            wcsstr(lower, L"vbox harddisk") ||
            wcsstr(lower, L"vbox cd-rom"))
            return VM_VENDOR_VIRTUALBOX;
        if (wcsstr(lower, L"vmware"))
            return VM_VENDOR_VMWARE;
        if (wcsstr(lower, L"xen virtual"))
            return VM_VENDOR_XEN;
        if (wcsstr(lower, L"prl_"))
            return VM_VENDOR_PARALLELS;
        return VM_VENDOR_NONE;
    }

    inline vm_vendor_e probe_disk_identifier_value(HANDLE key_h) {
        UNICODE_STRING ident_name;
        RtlInitUnicodeString(&ident_name, L"Identifier");

        UCHAR ident_buf[512] = {};
        ULONG ident_ret = 0;
        NTSTATUS qst = ZwQueryValueKey(key_h, &ident_name, KeyValuePartialInformation,
                                       ident_buf, sizeof(ident_buf), &ident_ret);
        if (!NT_SUCCESS(qst))
            return VM_VENDOR_NONE;

        auto* val = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION*>(ident_buf);
        if (val->Type != REG_SZ || val->DataLength < 4)
            return VM_VENDOR_NONE;

        wchar_t ident_lower[256] = {};
        ULONG copy = val->DataLength / sizeof(wchar_t);
        if (copy >= 255) copy = 255;
        const wchar_t* src = reinterpret_cast<const wchar_t*>(val->Data);
        for (ULONG i = 0; i < copy; ++i) {
            wchar_t c = src[i];
            if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 0x20);
            ident_lower[i] = c;
        }
        ident_lower[copy] = 0;

        return match_disk_identifier(ident_lower);
    }

    inline vm_vendor_e detect_disk_model(void) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return VM_VENDOR_NONE;

        UNICODE_STRING reg_path;
        RtlInitUnicodeString(&reg_path, L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi");

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &reg_path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE root = nullptr;
        NTSTATUS st = ZwOpenKey(&root, KEY_READ, &oa);
        if (!NT_SUCCESS(st))
            return VM_VENDOR_NONE;

        vm_vendor_e found = VM_VENDOR_NONE;

        const ULONG buf_size = 2048;
        UCHAR* enum_buf = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, buf_size, 'dkVH'));
        if (!enum_buf) {
            ZwClose(root);
            return VM_VENDOR_NONE;
        }

        UNICODE_STRING bus_relative;
        RtlInitUnicodeString(&bus_relative, L"Scsi Bus 0\\Target Id 0\\Logical Unit Id 0");

        for (ULONG p = 0; p < 32 && found == VM_VENDOR_NONE; ++p) {
            ULONG ret = 0;
            NTSTATUS est = ZwEnumerateKey(root, p, KeyBasicInformation, enum_buf, buf_size, &ret);
            if (est == STATUS_NO_MORE_ENTRIES)
                break;
            if (!NT_SUCCESS(est))
                continue;

            auto* port_info = reinterpret_cast<KEY_BASIC_INFORMATION*>(enum_buf);
            UNICODE_STRING port_us;
            port_us.Buffer = port_info->Name;
            port_us.Length = static_cast<USHORT>(port_info->NameLength);
            port_us.MaximumLength = port_us.Length;

            OBJECT_ATTRIBUTES port_oa;
            InitializeObjectAttributes(&port_oa, &port_us,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, root, nullptr);

            HANDLE port_h = nullptr;
            NTSTATUS pst = ZwOpenKey(&port_h, KEY_READ, &port_oa);
            if (!NT_SUCCESS(pst))
                continue;

            OBJECT_ATTRIBUTES bus_oa;
            InitializeObjectAttributes(&bus_oa, &bus_relative,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, port_h, nullptr);

            HANDLE bus_h = nullptr;
            NTSTATUS bst = ZwOpenKey(&bus_h, KEY_READ, &bus_oa);
            ZwClose(port_h);
            if (!NT_SUCCESS(bst))
                continue;

            vm_vendor_e v = probe_disk_identifier_value(bus_h);
            ZwClose(bus_h);

            if (v != VM_VENDOR_NONE)
                found = v;
        }

        ExFreePoolWithTag(enum_buf, 'dkVH');
        ZwClose(root);
        return found;
    }

    inline vm_vendor_e probe_mac_value(HANDLE sub_h) {
        UNICODE_STRING net_name;
        UCHAR net_buf[256] = {};
        ULONG net_ret = 0;

        RtlInitUnicodeString(&net_name, L"NetworkAddress");
        NTSTATUS nst = ZwQueryValueKey(sub_h, &net_name, KeyValuePartialInformation,
                                        net_buf, sizeof(net_buf), &net_ret);

        if (!NT_SUCCESS(nst)) {
            RtlInitUnicodeString(&net_name, L"PermanentAddress");
            nst = ZwQueryValueKey(sub_h, &net_name, KeyValuePartialInformation,
                                   net_buf, sizeof(net_buf), &net_ret);
        }

        if (!NT_SUCCESS(nst))
            return VM_VENDOR_NONE;

        auto* val = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION*>(net_buf);
        if (val->DataLength < 6)
            return VM_VENDOR_NONE;

        char hex_lower[16] = {};
        ULONG hcopy = (val->Type == REG_SZ) ? val->DataLength / sizeof(wchar_t) : val->DataLength;
        if (hcopy >= 15) hcopy = 15;
        if (val->Type == REG_SZ) {
            const wchar_t* wsrc = reinterpret_cast<const wchar_t*>(val->Data);
            for (ULONG i = 0; i < hcopy; ++i) {
                wchar_t c = wsrc[i];
                if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 0x20);
                hex_lower[i] = (char)(c & 0x7F);
            }
        }
        else {
            const char* csrc = reinterpret_cast<const char*>(val->Data);
            for (ULONG i = 0; i < hcopy; ++i) {
                char c = csrc[i];
                if (c >= 'A' && c <= 'Z') c = (char)(c + 0x20);
                hex_lower[i] = c;
            }
        }
        hex_lower[hcopy] = 0;

        if (hex_lower[0] == 0)
            return VM_VENDOR_NONE;

        char prefix[7] = {};
        for (int i = 0; i < 6; ++i) prefix[i] = hex_lower[i];
        prefix[6] = 0;

        if (memcmp(prefix, "525400", 6) == 0)
            return VM_VENDOR_QEMU_KVM;
        if (memcmp(prefix, "080027", 6) == 0 ||
            memcmp(prefix, "0a0027", 6) == 0)
            return VM_VENDOR_VIRTUALBOX;
        if (memcmp(prefix, "000c29", 6) == 0 ||
            memcmp(prefix, "005056", 6) == 0 ||
            memcmp(prefix, "000569", 6) == 0 ||
            memcmp(prefix, "001c14", 6) == 0)
            return VM_VENDOR_VMWARE;
        if (memcmp(prefix, "00163e", 6) == 0)
            return VM_VENDOR_XEN;
        if (memcmp(prefix, "001c42", 6) == 0)
            return VM_VENDOR_PARALLELS;
        if (memcmp(prefix, "00155d", 6) == 0 || memcmp(prefix, "001553", 6) == 0) {
            if (ve::is_microsoft_hyperv_root_local())
                return VM_VENDOR_NONE;
            return VM_VENDOR_HYPERV_GUEST;
        }

        return VM_VENDOR_NONE;
    }

    inline vm_vendor_e detect_mac_oui(void) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return VM_VENDOR_NONE;

        UNICODE_STRING reg_path;
        RtlInitUnicodeString(&reg_path,
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &reg_path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE root = nullptr;
        NTSTATUS st = ZwOpenKey(&root, KEY_READ, &oa);
        if (!NT_SUCCESS(st))
            return VM_VENDOR_NONE;

        vm_vendor_e found = VM_VENDOR_NONE;

        const ULONG buf_size = 1024;
        UCHAR* enum_buf = static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, buf_size, 'mcVH'));
        if (!enum_buf) {
            ZwClose(root);
            return VM_VENDOR_NONE;
        }

        for (ULONG idx = 0; idx < 64 && found == VM_VENDOR_NONE; ++idx) {
            ULONG ret = 0;
            NTSTATUS est = ZwEnumerateKey(root, idx, KeyBasicInformation, enum_buf, buf_size, &ret);
            if (est == STATUS_NO_MORE_ENTRIES)
                break;
            if (!NT_SUCCESS(est))
                continue;

            auto* basic = reinterpret_cast<KEY_BASIC_INFORMATION*>(enum_buf);
            if (basic->NameLength == 0 || basic->NameLength / sizeof(wchar_t) > 8)
                continue;

            UNICODE_STRING sub_us;
            sub_us.Buffer = basic->Name;
            sub_us.Length = static_cast<USHORT>(basic->NameLength);
            sub_us.MaximumLength = sub_us.Length;

            OBJECT_ATTRIBUTES sub_oa;
            InitializeObjectAttributes(&sub_oa, &sub_us,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, root, nullptr);

            HANDLE sub_h = nullptr;
            NTSTATUS sst = ZwOpenKey(&sub_h, KEY_READ, &sub_oa);
            if (!NT_SUCCESS(sst))
                continue;

            vm_vendor_e v = probe_mac_value(sub_h);
            ZwClose(sub_h);

            if (v != VM_VENDOR_NONE)
                found = v;
        }

        ExFreePoolWithTag(enum_buf, 'mcVH');
        ZwClose(root);
        return found;
    }

    inline bool detect_registry_artifact(void) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return false;

        static const wchar_t* services[] = {
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\VBoxGuest",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\VBoxMouse",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\VBoxSF",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\VBoxVideo",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vmhgfs",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vmmouse",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vmrawdsk",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vmusbmouse",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vm3dmp",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vmgid",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\prl_tg",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\prl_pv32",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\prl_sound",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\prl_strg",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\xenevtchn",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\xenbus",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\xennet",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\xenvbd",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\viostor",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vioscsi",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NetKVM",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Balloon",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\pvpanic",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\qemupciserial",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\qemufwcfg",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vioinput",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vioserial",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\viogpudo",
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\viorng",
        };

        for (const auto& svc : services) {
            UNICODE_STRING us;
            RtlInitUnicodeString(&us, svc);

            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, &us, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            HANDLE h = nullptr;
            NTSTATUS st = ZwOpenKey(&h, KEY_READ, &oa);
            if (NT_SUCCESS(st)) {
                ZwClose(h);
                return true;
            }
        }
        return false;
    }

    inline bool detect_qemu_fwcfg(void) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return false;

        UNICODE_STRING us;
        RtlInitUnicodeString(&us, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\qemufwcfg");

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE h = nullptr;
        NTSTATUS st = ZwOpenKey(&h, KEY_READ, &oa);
        if (!NT_SUCCESS(st))
            return false;

        ZwClose(h);
        return true;
    }
};
