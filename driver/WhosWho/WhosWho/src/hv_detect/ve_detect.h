#pragma once
#include "includes.h"
#include "func_defs.h"
#include "physmem_decl.h"

namespace ve {
    inline uint64_t image_base = 0;
    inline uint64_t image_size = 0;

    typedef struct
    {
        union
        {
            struct
            {
                uint32_t max_lbr_records : 8;   // [7:0]
#define CPUID1C_EAX_MAX_LBR_RECORDS_BIT   0
#define CPUID1C_EAX_MAX_LBR_RECORDS_MASK  0x000000FFu
#define CPUID1C_EAX_MAX_LBR_RECORDS(x)    ((uint32_t)((x) & 0xFFu))

                uint32_t reserved0 : 23;        // [30:8]

                uint32_t lip : 1;         // [31] 1=linear IP, 0=effective IP
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
                uint32_t reserved0 : 16;            // [15:0]
                uint32_t evlog_bitmap : 4;          // [19:16] Event Logging Supported bitmap
#define CPUID1C_ECX_EVLOG_BITMAP_BIT   16
#define CPUID1C_ECX_EVLOG_BITMAP_MASK  0x000F0000u
#define CPUID1C_ECX_EVLOG_BITMAP(x)    (((uint32_t)(x) >> 16) & 0xFu)

                uint32_t reserved1 : 12;            // [31:20]
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
            //
            // Bit 0
            // Enable LBR recording
            //
            uint64_t lbr_en : 1;

            //
            // Bit 1
            // Enable Conditional Branch logging (Jcc, LOOP*, J*CXZ)
            //
            uint64_t cond : 1;

            //
            // Bit 2
            // Enable Near Indirect JMP logging (JMP r/m*)
            //
            uint64_t near_ind_jmp : 1;

            //
            // Bit 3
            // Enable Near Relative JMP logging (JMP rel*)
            //
            uint64_t near_rel_jmp : 1;

            //
            // Bit 4
            // Enable Near Indirect CALL logging (CALL r/m*)
            //
            uint64_t near_ind_call : 1;

            //
            // Bit 5
            // Enable Near Relative CALL logging (CALL rel*)
            // (excluding displacement-0 calls to next RIP)
            //
            uint64_t near_rel_call : 1;

            //
            // Bit 6
            // Enable Near RET logging (RET 0xC3)
            //
            uint64_t near_ret : 1;

            //
            // Bit 7
            // Enable OTHER_BRANCH logging:
            //   - far CALL/JMP
            //   - interrupts
            //   - exceptions (except #DB)
            //   - INTn/INT3/INTO
            //   - IRET
            //   - TSX abort
            //   - EENTER/ERESUME/EEXIT/AEX
            //   - INIT/SIPI/RSM
            //
            uint64_t other_branch : 1;

            //
            // Bit 8
            // Enable Call Stack mode (LIFO pop behavior on RET)
            //
            uint64_t call_stack : 1;

            //
            // Bit 9
            // Record CPL=0 (kernel) branches
            //
            uint64_t os : 1;

            //
            // Bit 10
            // Record CPL>0 (user) branches
            //
            uint64_t usr : 1;

            //
            // Bits 11ï¿½63
            // Reserved (must be zero)
            //
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

    /*
        Helpers
    */

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

        /*
            Table ripped straight out of the sdm
        */

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

    /*
        Detections
    */

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

            // If an incorrect interrupt or no interrupt at all was raised this means incorrect idt shadowing
            if (last_int->exception_vector != virtualization_exception ||
                curr_interrupt_count == new_interrupt_count)
                hypervisor_detected = true;
        }

        return hypervisor_detected;
    }

    /*
        Basically the idea is to cause a #ve and check whether the LBR layout contains an out of range address or not
    */
    inline bool detection_2(void) {
        /*
            First check the CPU family via cpuid and then check if we should support lbr in some way or form?
            Table documenting valid from and to ranges in cpu families: SDM: Vol3:19.4.8
        */

        cpuid_eax_01 cpuid_1;
        __cpuid((int*)&cpuid_1, 1);
        if (!cpuid_1.cpuid_feature_information_ecx.perfmon_and_debug_capability) {
            return false;
        }

        ia32_perf_capabilities_register cap;
        cap.flags = __readmsr(IA32_PERF_CAPABILITIES);

        // As per Vol3:Chapter 20.4.3 this also defines non supported lbr features
        bool lbr_supported = (cap.lbr_format != LBR_PERF_UNSSUPORTED);

        lbr_config_t config;

        cpuid_eax_07 cpuid_7;
        __cpuid((int*)&cpuid_7, CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS);
        if (cpuid_7.edx.arch_lbr) {
            config.mode = lbr_mode_t::LBR_MODE_ARCH;

            // contradiction
            if (!lbr_supported) {
                return true;
            }
        }
        else {
            config.mode = lbr_mode_t::LBR_MODE_LEGACY;
        }

        bool hv_detected = false;

        // Most processors will still have legacy lbr tracing
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
                // Disable LBR first
                __try { __writemsr(IA32_LBR_CTL, 0); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }

                // Program depth
                __try { __writemsr(IA32_LBR_DEPTH, max_lbr_record_count); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }

                // Clear LBR stack entries
                for (uint32_t i = 0; i < (uint32_t)max_lbr_record_count; ++i) {
                    __try { __writemsr(IA32_ARCH_LBR_0_FROM_IP + i, 0); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }

                    __try { __writemsr(IA32_ARCH_LBR_0_TO_IP + i, 0); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }
                }

                __try { __writemsr(IA32_LBR_CTL, new_ctl.flags); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }

                /*
                    This should throw in the shadowed hv info etc.
                */
                __cause_ve();

                __try { __writemsr(IA32_LBR_CTL, 0); }
                __except (EXCEPTION_EXECUTE_HANDLER) { hv_detected = true; __leave; }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Payload fault or something else; best-effort disable
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

            // Restore
            __try { __writemsr(IA32_LBR_CTL, 0); }
            __except (EXCEPTION_EXECUTE_HANDLER) {  }

            __try { __writemsr(IA32_LBR_DEPTH, old_depth); }
            __except (EXCEPTION_EXECUTE_HANDLER) {  }

            __try { __writemsr(IA32_LBR_CTL, old_ctl); }
            __except (EXCEPTION_EXECUTE_HANDLER) {  }

            return hv_detected;
        }
        else {
            // Can happen cause we can't rly assume we don't hit a new / other CPU generation, also what about AMD but still weird?
            return false;
        }

        // Unreachable
    }

    /*
        Detection 3: Garbage MSR Write
        Report method: Write to MSR outside bitmap range (0x2000-0xBFFFFFFF).
        Real hardware generates #GP, naive VMMs may swallow the write.
    */
    inline bool detection_3(void) {
        constexpr uint32_t GARBAGE_MSR = 0xDEAD;
        bool got_exception = false;

        __try {
            __writemsr(GARBAGE_MSR, 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            got_exception = true;
        }

        if (!got_exception)
            return true;

        got_exception = false;
        __try {
            __readmsr(GARBAGE_MSR);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            got_exception = true;
        }

        return !got_exception;
    }

    /*
        Detection 4: XSETBV #GP injection
        Report method: Clear XCR0 bit 0 which must always be set.
        Real hardware injects #GP(0). Naive VMMs blindly execute _xsetbv in host and bugcheck.
        If no exception -> VMM swallowed the illegal write.
    */
    inline bool detection_4(void) {
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
            return true;
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

        if (!got_gp)
            return true;

        __try {
            _xsetbv(0, xcr0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        return false;
    }

    /*
        Detection 5: Synthetic MSR probe
        Report method: Read from MSR 0x40000000 (HV synthetic range).
        Real hardware #GPs. Commercial HVs (Hyper-V, VMware) respond with data.
        If we already know MS Hyper-V root is present we skip this â€” it will respond.
    */
    inline bool detection_5(void) {
        int regs[4] = {};
        __cpuid(regs, 1);
        if ((regs[2] & (1 << 31)) != 0)
            return false;

        bool got_exception = false;
        __try {
            __readmsr(0x40000000);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            got_exception = true;
        }

        return !got_exception;
    }

    /*
        Detection 6: CPUID leaf comparison
        Report method: Compare reserved leaf 0x40000000 against an invalid leaf.
        On bare metal both return identical data (highest standard leaf fallback).
        A VMM intercepts 0x40000000 to report its identity.
    */
    inline bool detection_6(void) {
        int regs[4] = {};
        __cpuid(regs, 1);
        if ((regs[2] & (1 << 31)) != 0)
            return false;

        int invalid_leaf[4] = {};
        int reserved_leaf[4] = {};

        __cpuid(invalid_leaf, 0x13371337);
        __cpuid(reserved_leaf, 0x40000000);

        if (invalid_leaf[0] != reserved_leaf[0] ||
            invalid_leaf[1] != reserved_leaf[1] ||
            invalid_leaf[2] != reserved_leaf[2] ||
            invalid_leaf[3] != reserved_leaf[3])
            return true;

        int max_basic[4] = {};
        __cpuid(max_basic, 0);
        int highest_basic[4] = {};
        __cpuid(highest_basic, max_basic[0]);

        if (highest_basic[0] != reserved_leaf[0] ||
            highest_basic[1] != reserved_leaf[1] ||
            highest_basic[2] != reserved_leaf[2] ||
            highest_basic[3] != reserved_leaf[3])
            return true;

        return false;
    }

    /*
        Detection 7: RDTSC/CPUID/RDTSC timing
        Report method: Standard timing attack. CPUID causes VM-exit adding overhead.
        Multiple rounds, median comparison against bare-metal baseline (~200-400 cycles).
    */
    inline bool detection_7(void) {
        constexpr int ROUNDS = 64;
        constexpr uint32_t BARE_METAL_THRESHOLD = 1500;
        uint32_t samples[ROUNDS] = {};

        _disable();

        for (int i = 0; i < ROUNDS; ++i) {
            int dummy[4] = {};
            uint64_t t0 = __rdtsc();
            __cpuid(dummy, 0);
            uint64_t t1 = __rdtsc();
            uint64_t delta = t1 - t0;
            samples[i] = (delta > 0xFFFFFFFFULL) ? 0xFFFFFFFFu : (uint32_t)delta;
        }

        _enable();

        for (int i = 0; i < ROUNDS - 1; ++i) {
            for (int j = i + 1; j < ROUNDS; ++j) {
                if (samples[j] < samples[i]) {
                    uint32_t tmp = samples[i];
                    samples[i] = samples[j];
                    samples[j] = tmp;
                }
            }
        }

        uint32_t median = samples[ROUNDS / 2];
        return median > BARE_METAL_THRESHOLD;
    }

    /*
        Detection 8: IET Divergence via APERF
        Report method: Compare APERF delta of CPUID (exiting inst) vs a non-exiting inst.
        On bare metal the non-exiting candidate takes longer. Under VMM, CPUID takes much
        longer because it causes a VM-exit. If CPUID APERF > candidate APERF -> VMM present.
    */
    inline bool detection_8(void) {
        ia32_perf_capabilities_register perf_cap;
        __try {
            perf_cap.flags = __readmsr(IA32_PERF_CAPABILITIES);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        constexpr int ITERATIONS = 32;
        uint64_t cpuid_deltas[ITERATIONS] = {};
        uint64_t div_deltas[ITERATIONS] = {};

        _disable();

        for (int i = 0; i < ITERATIONS; ++i) {
            uint64_t aperf_start = 0, aperf_end = 0;
            int dummy[4] = {};

            __try { aperf_start = __readmsr(0xE8); }
            __except (EXCEPTION_EXECUTE_HANDLER) { _enable(); return false; }

            __cpuid(dummy, 0);

            __try { aperf_end = __readmsr(0xE8); }
            __except (EXCEPTION_EXECUTE_HANDLER) { _enable(); return false; }

            cpuid_deltas[i] = aperf_end - aperf_start;
        }

        for (int i = 0; i < ITERATIONS; ++i) {
            uint64_t aperf_start = 0, aperf_end = 0;

            __try { aperf_start = __readmsr(0xE8); }
            __except (EXCEPTION_EXECUTE_HANDLER) { _enable(); return false; }

            volatile uint64_t dividend = 0xDEADBEEFCAFEBABEULL;
            volatile uint64_t divisor = 7;
            for (int k = 0; k < 50; ++k)
                dividend = dividend / divisor + k;

            __try { aperf_end = __readmsr(0xE8); }
            __except (EXCEPTION_EXECUTE_HANDLER) { _enable(); return false; }

            div_deltas[i] = aperf_end - aperf_start;
        }

        _enable();

        for (int i = 0; i < ITERATIONS - 1; ++i) {
            for (int j = i + 1; j < ITERATIONS; ++j) {
                if (cpuid_deltas[j] < cpuid_deltas[i]) {
                    uint64_t t = cpuid_deltas[i];
                    cpuid_deltas[i] = cpuid_deltas[j];
                    cpuid_deltas[j] = t;
                }
                if (div_deltas[j] < div_deltas[i]) {
                    uint64_t t = div_deltas[i];
                    div_deltas[i] = div_deltas[j];
                    div_deltas[j] = t;
                }
            }
        }

        uint64_t cpuid_median = cpuid_deltas[ITERATIONS / 2];
        uint64_t div_median = div_deltas[ITERATIONS / 2];

        if (cpuid_median > div_median * 3)
            return true;

        return false;
    }

    /*
        Detection 9: INVD cache side-channel
        Report method: Push value to stack (cached), set to 0 in WB memory,
        INVD flushes caches without writeback. On real hardware the original
        push survives (in system memory). Under a VMM that emulates INVD as
        WBINVD (or NOP), the zero overwrites.
    */
    inline bool detection_9(void) {
        bool detected = false;

        _disable();

        __try {
            __declspec(align(64)) volatile uint8_t canary_buf[64];
            for (int i = 0; i < 64; ++i) canary_buf[i] = 0xAA;

            __wbinvd();

            for (int i = 0; i < 64; ++i) canary_buf[i] = 0x00;

            __wbinvd();

            uint8_t check = 0;
            for (int i = 0; i < 64; ++i) check |= canary_buf[i];

            if (check == 0)
                detected = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            detected = false;
        }

        _enable();
        return detected;
    }

    /*
        Detection 10: CR4.VMXE & VMX availability check
        Report method: Some VMMs mask CR4.VMXE=0 in read shadow but still allow
        VMX instructions. On real hardware with VMXE=0, VMREAD causes #UD.
        If VMXE reads as 0 but VMREAD doesn't #UD -> VMM detected.
    */
    inline bool detection_10(void) {
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

    /*
        Detection 11: LBR stack consistency across VM-exit
        Report method: Save LBR TOS, force VM-exit via CPUID, check LBR TOS again.
        If TOS changed -> VMM doesn't save/restore LBR state properly.
    */
    inline bool detection_11(void) {
        ia32_perf_capabilities_register cap;
        __try { cap.flags = __readmsr(IA32_PERF_CAPABILITIES); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

        if (cap.lbr_format == LBR_PERF_UNSSUPORTED)
            return false;

        ia32_debugctl_register old_ctl{};
        __try { old_ctl.flags = __readmsr(IA32_DEBUGCTL); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

        ia32_debugctl_register ctl{};
        ctl.flags = old_ctl.flags;
        ctl.lbr = 1;

        __try { __writemsr(IA32_DEBUGCTL, ctl.flags); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return true; }

        uint64_t tos_pre = 0;
        __try { tos_pre = __readmsr(IA32_LASTBRANCH_TOS); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            __try { __writemsr(IA32_DEBUGCTL, old_ctl.flags); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            return true;
        }

        int dummy[4] = {};
        __cpuid(dummy, 0);
        __cpuid(dummy, 0);
        __cpuid(dummy, 0);

        uint64_t tos_post = 0;
        __try { tos_post = __readmsr(IA32_LASTBRANCH_TOS); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            __try { __writemsr(IA32_DEBUGCTL, old_ctl.flags); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            return true;
        }

        __try { __writemsr(IA32_DEBUGCTL, old_ctl.flags); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        return (tos_pre != tos_post);
    }

    static bool is_microsoft_hyperv_root_local() {
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

    inline void execute_ve_detections(void) {
        if (is_microsoft_hyperv_root_local())
            return;

        safety_net_t storage;
        if (!safety_net::start_safety_net(storage))
            return;

        image_base = safety_net::g_image_base;
        image_size = safety_net::g_image_size;

        const int num_detections = 11;
        bool detection_results[num_detections];
        bool (*detections[])(void) = {
            detection_1,   // #VE trigger
            detection_2,   // LBR stack after #VE
            detection_3,   // Garbage MSR write
            detection_4,   // XSETBV #GP injection
            detection_5,   // Synthetic MSR probe
            detection_6,   // CPUID leaf comparison
            detection_7,   // RDTSC/CPUID/RDTSC timing
            detection_8,   // IET divergence (APERF)
            detection_9,   // INVD cache side-channel
            detection_10,  // CR4.VMXE + VMX check
            detection_11,  // LBR TOS consistency
        };

        const char* detection_names[] = {
            "VE trigger",
            "LBR stack after VE",
            "Garbage MSR write",
            "XSETBV GP injection",
            "Synthetic MSR probe",
            "CPUID leaf comparison",
            "RDTSC/CPUID timing",
            "IET divergence (APERF)",
            "INVD cache side-channel",
            "CR4.VMXE + VMX check",
            "LBR TOS consistency",
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
            log_error_indent(2, "%d / %d detections failed â€” hypervisor likely present", failed, num_detections);
        }
    }
};
