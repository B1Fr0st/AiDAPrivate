#pragma once
#include "includes.h"
#include "func_defs.h"
#include "physmem_decl.h"

namespace idt {
    inline char allocated_memory_page[0x1000];
    inline segment_descriptor_register_32 comp_idt;
    inline segment_descriptor_register_64 actual_idt;


    namespace storing {
        inline bool detection_1(void) {
            bool hypervisor_detected = false;


            segment_descriptor_register_64 idtr;
            __try {
                __lock_sidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != invalid_opcode)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        inline bool detection_2(void) {
            bool hypervisor_detected = false;


            __try {

                __sidt((void*)0xdead);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != page_fault)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        inline bool detection_3(void) {

            volatile segment_descriptor_register_64* idtr_in_tlb = (volatile segment_descriptor_register_64*)allocated_memory_page;


            for (uint32_t i = 0; i < sizeof(segment_descriptor_register_64); i++) {
                volatile uint8_t dummy = *(uint8_t*)((uint64_t)allocated_memory_page + i);
                UNREFERENCED_PARAMETER(dummy);
            }

            uint64_t stored_flags;
            if (!physmem::paging_manipulation::win_destroy_memory_page_mapping(allocated_memory_page, stored_flags)) {
                return false;
            }

            if (physmem::paging_manipulation::is_memory_page_mapped(allocated_memory_page)) {
                return false;
            }


            bool hypervisor_detected = false;
            __try {
                __sidt((void*)idtr_in_tlb);
            }

            __except (EXCEPTION_EXECUTE_HANDLER) {
                hypervisor_detected = true;
            }

            physmem::paging_manipulation::win_restore_memory_page_mapping(allocated_memory_page, stored_flags);

            return hypervisor_detected;
        }

        inline bool detection_4(void) {
            uint64_t lowest_tsc = MAXULONG64;
            segment_descriptor_register_64 idtr;

            for (int i = 0; i < 10; i++) {

                _mm_lfence();
                uint64_t start = __rdtsc();
                _mm_lfence();

                __sidt(&idtr);

                _mm_lfence();
                uint64_t end = __rdtsc();
                _mm_lfence();

                uint64_t delta = (end - start);
                if (delta < lowest_tsc)
                    lowest_tsc = delta;


                if (delta & (1ull << 63)) {
                    return true;
                }
            }

            return lowest_tsc > MAX_ACCEPTABLE_TSC;
        }

        inline bool detection_5(void) {
            static uint8_t compatibility_shellcode[] = {
                0xB8, 0x00, 0x00, 0x00, 0x00,
                0x0F, 0x01, 0x08,
                0xC3
            };

            *(uint32_t*)(compatibility_shellcode + 1) = safety_net::execution_mode::get_compatibility_data_page_address();

            void* data_page = safety_net::execution_mode::get_compatibility_data_page();
            memset(data_page, 0, 0x1000);

            bool result = false;
            __try {
                result = safety_net::execution_mode::execute_32_bit_shellcode(compatibility_shellcode, sizeof(compatibility_shellcode));
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                result = true;
            }

            if (!result)
                return true;

            segment_descriptor_register_64 curr_idt;
            __sidt(&curr_idt);

            comp_idt = *(segment_descriptor_register_32*)data_page;
            actual_idt = curr_idt;


            if (memcmp((void*)&curr_idt, data_page, sizeof(segment_descriptor_register_64)) == 0) {
                return true;
            }

            return false;
        }

        inline bool detection_6(void) {
            bool hypervisor_detected = false;


            __try {

                __gp_fault_sidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != general_protection)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        inline bool detection_7(void) {
            bool hypervisor_detected = false;


            __try {

                __ss_fault_sidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != stack_segment_fault)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        inline bool detection_8(void) {
            cr4 curr_cr4;
            cr4 new_cr4;

            curr_cr4.flags = __readcr4();
            new_cr4.flags = curr_cr4.flags;

            new_cr4.usermode_instruction_prevention = 0;
            new_cr4.smap_enable = 0;
            new_cr4.smep_enable = 0;
            __writecr4(new_cr4.flags);

            rflags curr_flags;
            rflags new_flags;
            curr_flags.flags = __readeflags();
            new_flags.flags = curr_flags.flags;

            new_flags.alignment_check_flag = 0;
            __writeeflags(new_flags.flags);

            if (!safety_net::cpl::switch_to_cpl_3()) {
                __writecr4(curr_cr4.flags);
                __writeeflags(curr_flags.flags);
                return false;
            }

            bool hypervisor_detected = false;
            segment_descriptor_register_64 idtr;

            __try {

                __sidt(&idtr);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                hypervisor_detected = true;
            }

            if (!safety_net::cpl::switch_to_cpl_0()) {
                __writecr4(curr_cr4.flags);
                __writeeflags(curr_flags.flags);
                return false;
            }

            __writecr4(curr_cr4.flags);
            __writeeflags(curr_flags.flags);

            return hypervisor_detected;
        }

        inline bool detection_9(void) {
            cr4 curr_cr4;
            cr4 new_cr4;

            curr_cr4.flags = __readcr4();
            new_cr4.flags = curr_cr4.flags;

            new_cr4.usermode_instruction_prevention = 1;
            new_cr4.smap_enable = 0;
            new_cr4.smep_enable = 0;
            __writecr4(new_cr4.flags);

            rflags curr_flags;
            rflags new_flags;
            curr_flags.flags = __readeflags();
            new_flags.flags = curr_flags.flags;

            new_flags.alignment_check_flag = 0;
            __writeeflags(new_flags.flags);

            if (!safety_net::cpl::switch_to_cpl_3()) {
                __writecr4(curr_cr4.flags);
                __writeeflags(curr_flags.flags);
                return false;
            }

            bool hypervisor_detected = false;
            segment_descriptor_register_64 idtr;

            __try {

                __sidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                idt_regs_ecode_t* record = safety_net::idt::get_core_last_interrupt_record();
                if (record->exception_vector != general_protection || record->error_code != 0)
                    hypervisor_detected = true;
            }

            if (!safety_net::cpl::switch_to_cpl_0()) {
                __writecr4(curr_cr4.flags);
                __writeeflags(curr_flags.flags);
                return false;
            }

            __writecr4(curr_cr4.flags);
            __writeeflags(curr_flags.flags);

            return hypervisor_detected;
        }

        inline void execute_detections(void) {
            safety_net_t storage;
            if (!safety_net::start_safety_net(storage))
                return;

            const int num_detections = 9;
            bool detection_results[num_detections];
            bool (*detections[])(void) = { detection_1, detection_2, detection_3, detection_4, detection_5, detection_6, detection_7, detection_8, detection_9 };

            for (int i = 0; i < num_detections; ++i) {
                detection_results[i] = detections[i]();
            }

            safety_net::stop_safety_net(storage);

            for (int i = 0; i < num_detections; ++i) {
                if (detection_results[i]) {
                    log_error_indent(2, "Failed detection %d", i + 1);
                }
                else {
                    log_success_indent(2, "Passed detection %d", i + 1);
                }
            }
        }
    };


    namespace loading {

        inline bool detection_1(void) {
            bool hypervisor_detected = false;


            segment_descriptor_register_64 idtr;
            __sidt(&idtr);

            __try {
                __lock_lidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != invalid_opcode)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        inline bool detection_2(void) {
            bool hypervisor_detected = false;


            __try {

                __lidt((void*)0xdead);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != page_fault)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        inline bool detection_3(void) {
            memset(allocated_memory_page, 0, 0x1000);

            segment_descriptor_register_64 idtr;
            __sidt(&idtr);


            memcpy(allocated_memory_page, &idtr, sizeof(idtr));

            uint64_t stored_flags;
            if (!physmem::paging_manipulation::win_destroy_memory_page_mapping(allocated_memory_page, stored_flags))
                return false;

            if (physmem::paging_manipulation::is_memory_page_mapped(allocated_memory_page))
                return false;


            bool hypervisor_detected = false;
            __try {
                __lidt(allocated_memory_page);
            }

            __except (EXCEPTION_EXECUTE_HANDLER) {
                hypervisor_detected = true;
            }

            physmem::paging_manipulation::win_restore_memory_page_mapping(allocated_memory_page, stored_flags);
            return hypervisor_detected;
        }

        inline bool detection_4(void) {
            uint64_t lowest_tsc = MAXULONG64;
            segment_descriptor_register_64 idtr;


            __sidt(&idtr);

            for (int i = 0; i < 10; i++) {

                _mm_lfence();
                uint64_t start = __rdtsc();
                _mm_lfence();

                __lidt(&idtr);

                _mm_lfence();
                uint64_t end = __rdtsc();
                _mm_lfence();

                uint64_t delta = (end - start);
                if (delta < lowest_tsc)
                    lowest_tsc = delta;

                if (delta & (1ull << 63)) {
                    return true;
                }
            }

            return lowest_tsc > MAX_ACCEPTABLE_TSC;
        }

        inline bool detection_5(void) {
            bool hypervisor_detected = false;


            __try {
                __gp_fault_lidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != general_protection)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        inline bool detection_6(void) {
            bool hypervisor_detected = false;


            __try {
                __ss_fault_lidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != stack_segment_fault)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        inline bool detection_7(void) {
            segment_descriptor_register_64 idtr;
            __sidt(&idtr);

            cr4 curr_cr4;
            cr4 new_cr4;

            curr_cr4.flags = __readcr4();
            new_cr4.flags = curr_cr4.flags;

            new_cr4.usermode_instruction_prevention = 0;
            new_cr4.smap_enable = 0;
            new_cr4.smep_enable = 0;
            __writecr4(new_cr4.flags);

            if (!safety_net::cpl::switch_to_cpl_3()) {
                __writecr4(curr_cr4.flags);
                return false;
            }

            bool hypervisor_detected = false;
            __try {

                __lidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                idt_regs_ecode_t* record = safety_net::idt::get_core_last_interrupt_record();
                if (record->exception_vector != general_protection || record->error_code != 0)
                    hypervisor_detected = true;
            }

            if (!safety_net::cpl::switch_to_cpl_0()) {
                __writecr4(curr_cr4.flags);
                return false;
            }

            __writecr4(curr_cr4.flags);
            return hypervisor_detected;
        }

        inline void execute_detections(void) {
            safety_net_t storage;
            if (!safety_net::start_safety_net(storage))
                return;

            const int num_detections = 7;
            bool detection_results[num_detections];
            bool (*detections[])(void) = { detection_1, detection_2, detection_3, detection_4, detection_5, detection_6, detection_7 };

            for (int i = 0; i < num_detections; ++i) {
                detection_results[i] = detections[i]();
            }

            safety_net::stop_safety_net(storage);

            for (int i = 0; i < num_detections; ++i) {
                if (detection_results[i]) {
                    log_error_indent(2, "Failed detection %d", i + 1);
                }
                else {
                    log_success_indent(2, "Passed detection %d", i + 1);
                }
            }
        }
    };

    inline void execute_idt_detections(void) {
        memset(allocated_memory_page, 0, 0x1000);

        log_new_line();
        log_info_indent(1, "SIDT");
        storing::execute_detections();
        log_new_line();

        log_info_indent(1, "LIDT");
        loading::execute_detections();
        log_new_line();
    }
};
