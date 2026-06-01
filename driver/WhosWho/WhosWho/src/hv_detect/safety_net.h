#pragma once
#include "includes.h"
#include "func_defs.h"
#include "hv_structs.h"
#include "physmem_decl.h"

#include <ntimage.h>

namespace safety_net {
	inline bool inited = false;

	namespace gdt {

		constexpr segment_selector zero_descriptor_selector = {0, 0, 0};

		constexpr segment_selector constructed_cpl0_cs = { 0, 0, 1 };
		constexpr segment_selector constructed_cpl0_ss = { 0, 0, 2 };

		constexpr segment_selector constructed_cpl3_ss = { 3, 0, 3 };
		constexpr segment_selector constructed_cpl3_cs = { 3, 0, 4 };

		constexpr segment_selector constructed_tr = { 0, 0, 5 };

		constexpr segment_selector compatibility_constructed_cpl0_cs = { 0, 0, 7 };
		constexpr segment_selector compatibility_constructed_cpl0_ss = { 0, 0, 8 };

		constexpr segment_selector constructed_ds_es_fs_gs = { 0, 0, 9 };

		constexpr uint16_t constructed_gdt_size = 10;


		inline bool gdt_inited = false;

		inline void* interrupt_stack = 0;
		inline task_state_segment_64* my_tss = 0;
		inline segment_descriptor_32* my_gdt = 0;
		inline segment_descriptor_register_64 my_gdtr = { 0 };


		inline segment_descriptor_register_64 get_constructed_gdtr(void) {
			return my_gdtr;
		}

		inline void log_segment_descriptor_64(segment_descriptor_64* descriptor, const char* segment_name) {

			uint64_t base_address = ((uint64_t)descriptor->base_address_upper << 32) |
				(descriptor->base_address_high << 24) |
				(descriptor->base_address_middle << 16) |
				descriptor->base_address_low;


			uint32_t segment_limit = (descriptor->segment_limit_high << 16) |
				descriptor->segment_limit_low;


			if (descriptor->granularity) {
				segment_limit = (segment_limit << 12) | 0xFFF;
			}


			log_info("Segment Descriptor (%s):", segment_name);
			log_info("  Base Address: 0x%016llX", base_address);
			log_info("  Segment Limit: 0x%X", segment_limit);
			log_info("  Type: 0x%X", descriptor->type);
			log_info("  Descriptor Type (S flag): 0x%X", descriptor->descriptor_type);
			log_info("  DPL (Descriptor Privilege Level): 0x%X", descriptor->descriptor_privilege_level);
			log_info("  Present (P flag): 0x%X", descriptor->present);
			log_info("  Granularity (G flag): 0x%X", descriptor->granularity);
			log_info("  Default/Big (D flag): 0x%X", descriptor->default_big);
			log_info("  Long Mode (L flag): 0x%X", descriptor->long_mode);
			log_info("  System: 0x%X", descriptor->system);
			log_info("  System: 0x%X", descriptor->descriptor_type == 0 ? 1 : 0);
		}

		inline void log_segment_descriptor_32(segment_descriptor_32* descriptor, const char* segment_name) {

			uint32_t base_address = (descriptor->base_address_high << 24) |
				(descriptor->base_address_middle << 16) |
				descriptor->base_address_low;


			uint32_t segment_limit = (descriptor->segment_limit_high << 16) |
				descriptor->segment_limit_low;


			if (descriptor->granularity) {
				segment_limit = (segment_limit << 12) | 0xFFF;
			}

			log_info("Segment Descriptor (%s):", segment_name);
			log_info("  Base Address: 0x%08X", base_address);
			log_info("  Segment Limit: 0x%X", segment_limit);
			log_info("  Type: 0x%X", descriptor->type);
			log_info("  Descriptor Type (S flag): 0x%X", descriptor->descriptor_type);
			log_info("  DPL (Descriptor Privilege Level): 0x%X", descriptor->descriptor_privilege_level);
			log_info("  Present (P flag): 0x%X", descriptor->present);
			log_info("  Granularity (G flag): 0x%X", descriptor->granularity);
			log_info("  Default/Big (D/B flag): 0x%X", descriptor->default_big);
			log_info("  Long Mode (L flag): 0x%X", descriptor->long_mode);
			log_info("  System: 0x%X\n", descriptor->system);
		}

		inline void log_segment_selector(segment_selector* selector, const char* selector_name) {

			uint16_t rpl = selector->request_privilege_level;
			uint16_t table = selector->table;
			uint16_t index = selector->index;


			const char* table_name = (table == 0) ? "GDT" : "LDT";


			log_info("[%s] Segment Selector Details:", selector_name);
			log_info("  Request Privilege Level (RPL): %u", rpl);
			log_info("  Table Indicator (TI): %s (%u)", table_name, table);
			log_info("  Index: %u", index);
			log_info("  Raw Flags: 0x%04X", selector->flags);
		}

		inline void log_constructed_gdt_descriptors(void) {

			segment_descriptor_register_64 win_gdtr;
			_sgdt(&win_gdtr);


			segment_descriptor_32* win_gdt = (segment_descriptor_32*)win_gdtr.base_address;


			segment_selector cs, ds, ss, es, fs, gs, tr;


			cs = __read_cs();
			ds = __read_ds();
			ss = __read_ss();
			es = __read_es();
			fs = __read_fs();
			gs = __read_gs();
			tr = __read_tr();


			log_info("CS: 0x%04x", *(uint16_t*)&cs);
			log_segment_descriptor_32(&win_gdt[cs.index], "CS");

			log_info("DS: 0x%04x", *(uint16_t*)&ds);
			log_segment_descriptor_32(&win_gdt[ds.index], "DS");

			log_info("SS: 0x%04x", *(uint16_t*)&ss);
			log_segment_descriptor_32(&win_gdt[ss.index], "SS");

			log_info("ES: 0x%04x", *(uint16_t*)&es);
			log_segment_descriptor_32(&win_gdt[es.index], "ES");

			log_info("FS: 0x%04x", *(uint16_t*)&fs);
			log_segment_descriptor_32(&win_gdt[fs.index], "FS");

			log_info("GS: 0x%04x", *(uint16_t*)&gs);
			log_segment_descriptor_32(&win_gdt[gs.index], "GS");

			log_info("TR: 0x%04x", *(uint16_t*)&tr);
			log_segment_descriptor_64((segment_descriptor_64*)(&win_gdt[tr.index]), "TSS");
		}


		inline bool init_gdt(void) {
			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;

			my_gdt = (segment_descriptor_32*)MmAllocateContiguousMemory(max(sizeof(segment_descriptor_32) * constructed_gdt_size, 0x1000), max_addr);
			if (!my_gdt)
				return false;
			memset(my_gdt, 0, max(sizeof(segment_descriptor_32) * constructed_gdt_size, 0x1000));

			my_tss = (task_state_segment_64*)MmAllocateContiguousMemory(0x1000, max_addr);
			if (!my_tss)
				return false;
			memset(my_tss, 0, 0x1000);

			interrupt_stack = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
			if (!interrupt_stack)
				return false;
			memset(interrupt_stack, 0, KERNEL_STACK_SIZE);

			my_tss->ist1 = (uint64_t)interrupt_stack + KERNEL_STACK_SIZE;
			my_tss->ist2 = (uint64_t)interrupt_stack + KERNEL_STACK_SIZE;
			my_tss->ist3 = (uint64_t)interrupt_stack + KERNEL_STACK_SIZE;
			my_tss->ist4 = (uint64_t)interrupt_stack + KERNEL_STACK_SIZE;
			my_tss->ist5 = (uint64_t)interrupt_stack + KERNEL_STACK_SIZE;
			my_tss->ist6 = (uint64_t)interrupt_stack + KERNEL_STACK_SIZE;
			my_tss->ist7 = (uint64_t)interrupt_stack + KERNEL_STACK_SIZE;

			uint64_t tss_base = reinterpret_cast<uint64_t>(my_tss);


			segment_descriptor_32* zero_descriptor = &my_gdt[zero_descriptor_selector.index];
			memset(zero_descriptor, 0, sizeof(segment_descriptor_32));


			segment_descriptor_32* cpl_0_cs_descriptor = &my_gdt[constructed_cpl0_cs.index];
			memset(cpl_0_cs_descriptor, 0, sizeof(segment_descriptor_32));
			cpl_0_cs_descriptor->present = 1;
			cpl_0_cs_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
			cpl_0_cs_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			cpl_0_cs_descriptor->descriptor_privilege_level = 0;
			cpl_0_cs_descriptor->long_mode = 1;


			segment_descriptor_32* cpl_0_ss_descriptor = &my_gdt[constructed_cpl0_ss.index];
			memset(cpl_0_ss_descriptor, 0, sizeof(segment_descriptor_32));
			cpl_0_ss_descriptor->present = 1;
			cpl_0_ss_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
			cpl_0_ss_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			cpl_0_ss_descriptor->descriptor_privilege_level = 0;
			cpl_0_ss_descriptor->default_big = 1;


			segment_descriptor_32* cpl_3_cs_descriptor = &my_gdt[constructed_cpl3_cs.index];
			memset(cpl_3_cs_descriptor, 0, sizeof(segment_descriptor_32));
			cpl_3_cs_descriptor->present = 1;
			cpl_3_cs_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
			cpl_3_cs_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			cpl_3_cs_descriptor->descriptor_privilege_level = 3;
			cpl_3_cs_descriptor->long_mode = 1;


			segment_descriptor_32* cpl_3_ss_descriptor = &my_gdt[constructed_cpl3_ss.index];
			memset(cpl_3_ss_descriptor, 0, sizeof(segment_descriptor_32));
			cpl_3_ss_descriptor->present = 1;
			cpl_3_ss_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
			cpl_3_ss_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			cpl_3_ss_descriptor->descriptor_privilege_level = 3;
			cpl_3_ss_descriptor->granularity = 1;
			cpl_3_ss_descriptor->default_big = 1;
			cpl_3_ss_descriptor->segment_limit_low = 0xFFFF;
			cpl_3_ss_descriptor->segment_limit_high = 0xF;


			segment_descriptor_32* comp_cpl_0_cs_descriptor = &my_gdt[compatibility_constructed_cpl0_cs.index];
			memset(comp_cpl_0_cs_descriptor, 0, sizeof(segment_descriptor_32));
			comp_cpl_0_cs_descriptor->present = 1;
			comp_cpl_0_cs_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
			comp_cpl_0_cs_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			comp_cpl_0_cs_descriptor->descriptor_privilege_level = 0;
			comp_cpl_0_cs_descriptor->default_big = 1;
			comp_cpl_0_cs_descriptor->granularity = 1;
			comp_cpl_0_cs_descriptor->segment_limit_low = 0xFFFF;
			comp_cpl_0_cs_descriptor->segment_limit_high = 0xF;
			comp_cpl_0_cs_descriptor->long_mode = 0;


			segment_descriptor_32* comp_cpl_0_ss_descriptor = &my_gdt[compatibility_constructed_cpl0_ss.index];
			memset(comp_cpl_0_ss_descriptor, 0, sizeof(segment_descriptor_32));
			comp_cpl_0_ss_descriptor->present = 1;
			comp_cpl_0_ss_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
			comp_cpl_0_ss_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			comp_cpl_0_ss_descriptor->descriptor_privilege_level = 0;
			comp_cpl_0_ss_descriptor->default_big = 1;
			comp_cpl_0_ss_descriptor->granularity = 1;
			comp_cpl_0_ss_descriptor->segment_limit_low = 0xFFFF;
			comp_cpl_0_ss_descriptor->segment_limit_high = 0xF;


			segment_descriptor_64* tss_descriptor = reinterpret_cast<segment_descriptor_64*>(&my_gdt[constructed_tr.index]);
			memset(tss_descriptor, 0, sizeof(segment_descriptor_64));

			tss_descriptor->present = 1;
			tss_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY;
			tss_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_SYSTEM;
			tss_descriptor->descriptor_privilege_level = 0;
			tss_descriptor->segment_limit_low = sizeof(task_state_segment_64) - 1;
			tss_descriptor->base_address_low = (tss_base >> 00) & 0xFFFF;
			tss_descriptor->base_address_middle = (tss_base >> 16) & 0xFF;
			tss_descriptor->base_address_high = (tss_base >> 24) & 0xFF;
			tss_descriptor->base_address_upper = (tss_base >> 32) & 0xFFFFFFFF;


			segment_descriptor_32* ds_es_fs_gs_descriptor = &my_gdt[constructed_ds_es_fs_gs.index];
			memset(ds_es_fs_gs_descriptor, 0, sizeof(segment_descriptor_32));
			ds_es_fs_gs_descriptor->present = 1;
			ds_es_fs_gs_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
			ds_es_fs_gs_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			ds_es_fs_gs_descriptor->descriptor_privilege_level = 0;
			ds_es_fs_gs_descriptor->default_big = 1;

			my_gdtr.base_address = (uint64_t)my_gdt;
			my_gdtr.limit = (constructed_gdt_size * sizeof(segment_descriptor_32));

			gdt_inited = true;

			return true;
		}
	};

	namespace idt {
		inline bool idt_inited = false;
		inline segment_descriptor_interrupt_gate_64* my_idt = 0;
		inline segment_descriptor_register_64 my_idtr = { 0 };

		inline uint64_t total_interrupts = 0;
		inline idt_regs_ecode_t* context_storage = 0;

		inline bool should_disable_lbr = false;
		inline volatile LONG64 last_exception_vector = -1;
		inline volatile LONG64 last_exception_error_code = 0;
		inline volatile LONG64 last_exception_rip = 0;
		inline volatile LONG64 last_exception_rsp = 0;
		inline volatile LONG probe_recovery_count = 0;
		inline volatile LONG unresolved_exception_count = 0;
		constexpr ULONG max_seh_runtime_functions = 0x20000;
		constexpr ULONG max_seh_stack_qwords = 512;

		inline bool is_canonical_address(uint64_t value) {
			uint64_t upper = value >> 48;
			return upper == 0 || upper == 0xFFFF;
		}

		inline bool safe_read_u64(uint64_t address, uint64_t* value) {
			if (!value || !address || !is_canonical_address(address))
				return false;

			__try {
				*value = *reinterpret_cast<uint64_t*>(address);
				return true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				*value = 0;
				return false;
			}
		}

		inline void publish_exception_snapshot(idt_regs_ecode_t* record) {
			if (!record)
				return;

			_InterlockedExchange64(&last_exception_vector, static_cast<LONG64>(record->exception_vector));
			_InterlockedExchange64(&last_exception_error_code, static_cast<LONG64>(record->error_code));
			_InterlockedExchange64(&last_exception_rip, static_cast<LONG64>(record->rip));
			_InterlockedExchange64(&last_exception_rsp, static_cast<LONG64>(record->rsp));
		}

		inline void get_last_exception_snapshot(uint64_t* vector, uint64_t* error_code, uint64_t* rip, uint64_t* rsp) {
			if (vector)
				*vector = static_cast<uint64_t>(_InterlockedCompareExchange64(&last_exception_vector, 0, 0));
			if (error_code)
				*error_code = static_cast<uint64_t>(_InterlockedCompareExchange64(&last_exception_error_code, 0, 0));
			if (rip)
				*rip = static_cast<uint64_t>(_InterlockedCompareExchange64(&last_exception_rip, 0, 0));
			if (rsp)
				*rsp = static_cast<uint64_t>(_InterlockedCompareExchange64(&last_exception_rsp, 0, 0));
		}

		inline LONG consume_probe_recovery_count(void) {
			return _InterlockedExchange(&probe_recovery_count, 0);
		}

		inline LONG consume_unresolved_exception_count(void) {
			return _InterlockedExchange(&unresolved_exception_count, 0);
		}

		inline bool is_rip_in_probe_helper(uint64_t rip, void (*proc)(void), uint64_t span) {
			uint64_t start = reinterpret_cast<uint64_t>(proc);
			return rip >= start && rip < start + span;
		}

		inline bool is_rip_in_probe_helper(uint64_t rip, void (*proc)(void*), uint64_t span) {
			uint64_t start = reinterpret_cast<uint64_t>(proc);
			return rip >= start && rip < start + span;
		}

		inline bool is_known_probe_helper_rip(uint64_t rip) {
			return is_rip_in_probe_helper(rip, __lock_sidt, 32) ||
				   is_rip_in_probe_helper(rip, __ss_fault_sidt, 32) ||
				   is_rip_in_probe_helper(rip, __gp_fault_sidt, 32) ||
				   is_rip_in_probe_helper(rip, __lock_lidt, 32) ||
				   is_rip_in_probe_helper(rip, __ss_fault_lidt, 32) ||
				   is_rip_in_probe_helper(rip, __gp_fault_lidt, 32) ||
				   is_rip_in_probe_helper(rip, __cause_ve, 16);
		}

		inline void mark_unresolved_exception(idt_regs_ecode_t* record, const char* reason) {
			publish_exception_snapshot(record);
			_InterlockedIncrement(&unresolved_exception_count);
			HVD_LOG("safety_exception_unresolved reason=%s vector=0x%llx error=0x%llx rip=0x%llx rsp=0x%llx cpu=%lu irql=%lu",
				reason ? reason : "unknown",
				record ? record->exception_vector : 0,
				record ? record->error_code : 0,
				record ? record->rip : 0,
				record ? record->rsp : 0,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
		}

		inline bool recover_known_probe_helper_fault(idt_regs_ecode_t* record, const char* reason) {
			if (!record || !is_known_probe_helper_rip(record->rip))
				return false;
			if (!record->rsp || !is_canonical_address(record->rsp))
				return false;

			uint64_t return_address = 0;
			if (!safe_read_u64(record->rsp, &return_address))
				return false;
			if (return_address < g_image_base || return_address >= g_image_base + g_image_size)
				return false;

			_InterlockedIncrement(&probe_recovery_count);
			HVD_LOG("safety_exception_probe_recovered reason=%s vector=0x%llx error=0x%llx rip=0x%llx return=0x%llx rsp=0x%llx cpu=%lu irql=%lu",
				reason ? reason : "unknown",
				record->exception_vector,
				record->error_code,
				record->rip,
				return_address,
				record->rsp,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());

			record->rip = return_address;
			record->rsp += sizeof(uint64_t);
			publish_exception_snapshot(record);
			return true;
		}


		inline segment_descriptor_interrupt_gate_64 create_interrupt_gate(void* assembly_handler) {
			segment_descriptor_interrupt_gate_64 gate = { 0 };

			gate.interrupt_stack_table = 4;
			gate.segment_selector = gdt::constructed_cpl0_cs.flags;
			gate.must_be_zero_0 = 0;
			gate.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
			gate.must_be_zero_1 = 0;
			gate.descriptor_privilege_level = 3;
			gate.present = 1;
			gate.reserved = 0;

			uint64_t offset = (uint64_t)assembly_handler;
			gate.offset_low = (offset >> 0) & 0xFFFF;
			gate.offset_middle = (offset >> 16) & 0xFFFF;
			gate.offset_high = (offset >> 32) & 0xFFFFFFFF;

			return gate;
		}

		inline segment_descriptor_register_64 get_constructed_idtr(void) {
			return my_idtr;
		}

		inline void increase_interrupt_counter(void) {
			total_interrupts++;
		}

		inline uint64_t get_interrupt_count(void) {
			return total_interrupts;
		}

		inline idt_regs_ecode_t* get_interrupt_record(uint32_t interrupt_idx) {
			if (!idt_inited || interrupt_idx >= MAX_RECORDABLE_INTERRUPTS)
				return 0;

			return &context_storage[interrupt_idx];
		}

		inline void reset_interrupt_count(void) {
			total_interrupts = 0;
		}

		inline idt_regs_ecode_t* get_core_last_interrupt_record(void) {
			if (!idt_inited || total_interrupts >= MAX_RECORDABLE_INTERRUPTS || !total_interrupts)
				return 0;

			idt_regs_ecode_t* record = &context_storage[total_interrupts - 1];


			reset_interrupt_count();

			return record;
		}

		inline void safe_interrupt_record(idt_regs_ecode_t* record) {
			publish_exception_snapshot(record);

			if (!idt_inited || total_interrupts >= MAX_RECORDABLE_INTERRUPTS)
				return;

			memcpy(&context_storage[total_interrupts], record, sizeof(idt_regs_ecode_t));
		}

		inline void set_should_disable_lbr_in_handler(bool val) {
			should_disable_lbr = val;
		}

		inline void log_all_interrupts() {
			uint64_t interrupt_count = get_interrupt_count();
			if (interrupt_count == 0) {
				log_info("No interrupts have occurred.");
				return;
			}

			log_info("Interrupt count: %p", interrupt_count);

			for (uint32_t i = 0; i < interrupt_count; ++i) {
				idt_regs_ecode_t* record = get_interrupt_record(i);
				if (!record) {
					log_error("Interrupt #%d has no valid record.", i);
					continue;
				}

				log_new_line();

				log_info("Interrupt #%d:", i);
				log_info_indent(1, "RAX: 0x%llx", record->rax);
				log_info_indent(1, "RBX: 0x%llx", record->rbx);
				log_info_indent(1, "RCX: 0x%llx", record->rcx);
				log_info_indent(1, "RDX: 0x%llx", record->rdx);
				log_info_indent(1, "RSI: 0x%llx", record->rsi);
				log_info_indent(1, "RDI: 0x%llx", record->rdi);
				log_info_indent(1, "RBP: 0x%llx", record->rbp);
				log_info_indent(1, "R8:  0x%llx", record->r8);
				log_info_indent(1, "R9:  0x%llx", record->r9);
				log_info_indent(1, "R10: 0x%llx", record->r10);
				log_info_indent(1, "R11: 0x%llx", record->r11);
				log_info_indent(1, "R12: 0x%llx", record->r12);
				log_info_indent(1, "R13: 0x%llx", record->r13);
				log_info_indent(1, "R14: 0x%llx", record->r14);
				log_info_indent(1, "R15: 0x%llx", record->r15);
				log_info_indent(1, "RIP: 0x%llx", record->rip);
				log_info_indent(1, "CS:  0x%llx", record->cs_selector);
				log_info_indent(1, "RFLAGS: 0x%llx", record->rflags.flags);
				log_info_indent(1, "RSP: 0x%llx", record->rsp);
				log_info_indent(1, "SS:  0x%llx", record->ss_selector);
				log_info_indent(1, "Exception Vector: 0x%llx", record->exception_vector);
				log_info_indent(1, "Error Code: 0x%llx", record->error_code);
			}
		}


		extern "C" __declspec(noinline) void exception_handler(idt_regs_ecode_t* record)
#ifdef SAFETY_NET_IMPLEMENT
		{
			if (should_disable_lbr) {
				__writemsr(IA32_DEBUGCTL, 0);
			}


			safe_interrupt_record(record);
			increase_interrupt_counter();


			if (execution_mode::handle_mode_switch(record))
				return;


			if (record->exception_vector == stack_segment_fault) {
				record->rsp = record->rax;
			}


			if (record->exception_vector == nmi)
				return;

			if (!g_image_base || !g_image_size || !is_canonical_address(g_image_base)) {
				if (recover_known_probe_helper_fault(record, "image_context_unavailable"))
					return;
				mark_unresolved_exception(record, "image_context_unavailable");
				return;
			}

			IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)g_image_base;
			IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(g_image_base + dos_header->e_lfanew);
			IMAGE_DATA_DIRECTORY* exception = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
			RUNTIME_FUNCTION* rt_functions = (RUNTIME_FUNCTION*)(g_image_base + exception->VirtualAddress);
			ULONG runtime_function_count = exception->Size / sizeof(RUNTIME_FUNCTION);
			if (runtime_function_count > max_seh_runtime_functions)
				runtime_function_count = max_seh_runtime_functions;

			uint64_t rip_rva = record->rip - g_image_base;


			for (ULONG idx = 0; idx < runtime_function_count; ++idx) {
				RUNTIME_FUNCTION* function = &rt_functions[idx];
				if (!(rip_rva >= function->BeginAddress && rip_rva < function->EndAddress))
					continue;

				UNWIND_INFO* unwind_info = (UNWIND_INFO*)(g_image_base + function->UnwindData);
				if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
					continue;

				SCOPE_TABLE* scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));
				for (uint32_t entry = 0; entry < scope_table->Count; ++entry) {
					SCOPE_RECORD* scope_record = &scope_table->ScopeRecords[entry];
					if (rip_rva >= scope_record->BeginAddress && rip_rva < scope_record->EndAddress) {

						record->rip = g_image_base + scope_record->JumpTarget;

						return;
					}
				}
			}


			uint64_t* stack_ptr = (uint64_t*)record->rsp;
			for (ULONG stack_idx = 0; stack_ptr && stack_idx < max_seh_stack_qwords; ++stack_idx) {
				uint64_t stack_slot = reinterpret_cast<uint64_t>(stack_ptr + stack_idx);
				if (!is_canonical_address(stack_slot)) {
					if (recover_known_probe_helper_fault(record, "seh_stack_noncanonical"))
						return;
					mark_unresolved_exception(record, "seh_stack_noncanonical");
					return;
				}

				uint64_t potential_caller_rip = 0;
				if (!safe_read_u64(stack_slot, &potential_caller_rip)) {
					if (recover_known_probe_helper_fault(record, "seh_stack_read_failed"))
						return;
					mark_unresolved_exception(record, "seh_stack_read_failed");
					return;
				}
				if (potential_caller_rip < g_image_base || potential_caller_rip >= g_image_base + g_image_size)
					continue;

				uint64_t potential_caller_rva = potential_caller_rip - g_image_base;


				for (ULONG idx = 0; idx < runtime_function_count; ++idx) {
					RUNTIME_FUNCTION* function = &rt_functions[idx];
					if (!(potential_caller_rva >= function->BeginAddress && potential_caller_rva < function->EndAddress))
						continue;

					UNWIND_INFO* unwind_info = (UNWIND_INFO*)(g_image_base + function->UnwindData);
					if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
						continue;

					SCOPE_TABLE* scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));
					for (uint32_t entry = 0; entry < scope_table->Count; ++entry) {
						SCOPE_RECORD* scope_record = &scope_table->ScopeRecords[entry];
						if (potential_caller_rva >= scope_record->BeginAddress && potential_caller_rva < scope_record->EndAddress) {

							record->rip = g_image_base + scope_record->JumpTarget;
							record->rsp = (uint64_t)(stack_ptr + stack_idx + 1);

							return;
						}
					}
				}
			}

			if (recover_known_probe_helper_fault(record, "seh_stack_scan_exhausted"))
				return;

			mark_unresolved_exception(record, "seh_stack_scan_exhausted");
		}
#else
		;
#endif


		inline void create_idt(segment_descriptor_interrupt_gate_64* idt) {

			idt[divide_error] = idt::create_interrupt_gate(asm_de_handler);
			idt[debug] = idt::create_interrupt_gate(asm_db_handler);
			idt[nmi] = idt::create_interrupt_gate(asm_nmi_handler);
			idt[breakpoint] = idt::create_interrupt_gate(asm_bp_handler);
			idt[overflow] = idt::create_interrupt_gate(asm_of_handler);
			idt[bound_range_exceeded] = idt::create_interrupt_gate(asm_br_handler);
			idt[invalid_opcode] = idt::create_interrupt_gate(asm_ud_handler);
			idt[device_not_available] = idt::create_interrupt_gate(asm_nm_handler);
			idt[double_fault] = idt::create_interrupt_gate(asm_df_handler);
			idt[invalid_tss] = idt::create_interrupt_gate(asm_ts_handler);
			idt[segment_not_present] = idt::create_interrupt_gate(asm_np_handler);
			idt[stack_segment_fault] = idt::create_interrupt_gate(asm_ss_handler);
			idt[general_protection] = idt::create_interrupt_gate(asm_gp_handler);
			idt[page_fault] = idt::create_interrupt_gate(asm_pf_handler);
			idt[x87_floating_point_error] = idt::create_interrupt_gate(asm_mf_handler);
			idt[alignment_check] = idt::create_interrupt_gate(asm_ac_handler);
			idt[machine_check] = idt::create_interrupt_gate(asm_mc_handler);
			idt[simd_floating_point_error] = idt::create_interrupt_gate(asm_xm_handler);
			idt[virtualization_exception] = idt::create_interrupt_gate(asm_ve_handler);
			idt[control_protection] = idt::create_interrupt_gate(asm_cp_handler);

			my_idtr.base_address = (uint64_t)idt;
			my_idtr.limit = MAXUINT16;
		}

		inline bool init_idt(void) {
			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;
			my_idt = (segment_descriptor_interrupt_gate_64*)MmAllocateContiguousMemory(MAXUINT16, max_addr);
			if (!my_idt)
				return false;
			memset(my_idt, 0, MAXUINT16);

			create_idt(my_idt);

			context_storage = (idt_regs_ecode_t*)MmAllocateContiguousMemory(MAX_RECORDABLE_INTERRUPTS * sizeof(idt_regs_ecode_t), max_addr);
			if (!context_storage)
				return false;
			memset(context_storage, 0, MAX_RECORDABLE_INTERRUPTS * sizeof(idt_regs_ecode_t));

			idt_inited = true;

			return true;
		}
	};

	namespace cpl {
		inline bool cpl_switching_inited = false;
		inline bool currently_in_cpl_3 = false;


		inline uint64_t original_star = 0;
		inline uint64_t original_lstar = 0;
		inline uint64_t original_fmask = 0;

		inline uint64_t constructed_star = 0;
		inline uint64_t constructed_lstar = 0;
		inline uint64_t constructed_fmask = 0;


		inline bool switch_to_cpl_3(void) {
			if (!is_safety_net_active())
				return false;

			cr4 curr_cr4;
			curr_cr4.flags = __readcr4();
			if (curr_cr4.smap_enable || curr_cr4.smep_enable)
				return false;

			__writemsr(IA32_STAR, constructed_star);
			__writemsr(IA32_LSTAR, constructed_lstar);
			__writemsr(IA32_FMASK, constructed_fmask);

			__try {
				asm_switch_segments(gdt::constructed_cpl3_cs.flags, gdt::constructed_cpl3_ss.flags);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {

				__writemsr(IA32_STAR, original_star);
				__writemsr(IA32_LSTAR, original_lstar);
				__writemsr(IA32_FMASK, original_fmask);
				return false;
			}

			currently_in_cpl_3 = true;

			return true;
		}


		inline bool switch_to_cpl_0(void) {


			if (!currently_in_cpl_3) {
				__writemsr(IA32_STAR, constructed_star);
				__writemsr(IA32_LSTAR, constructed_lstar);
				__writemsr(IA32_FMASK, constructed_fmask);
			}

			__try {
				asm_switch_to_cpl_0();
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {

				currently_in_cpl_3 = false;
				__writemsr(IA32_STAR, original_star);
				__writemsr(IA32_LSTAR, original_lstar);
				__writemsr(IA32_FMASK, original_fmask);
				return false;
			}

			__writemsr(IA32_STAR, original_star);
			__writemsr(IA32_LSTAR, original_lstar);
			__writemsr(IA32_FMASK, original_fmask);

			currently_in_cpl_3 = false;

			return true;
		}

		inline bool init_cpl_switcher(void) {

			ia32_efer_register efer;
			efer.flags = __readmsr(IA32_EFER);
			if (!efer.syscall_enable || !efer.ia32e_mode_enable)
				return false;


			original_star = __readmsr(IA32_STAR);
			original_lstar = __readmsr(IA32_LSTAR);
			original_fmask = __readmsr(IA32_FMASK);


			ia32_star_register star;
			star.flags = 0;
			star.kernel_cs_selector = gdt::constructed_cpl0_cs.flags;
			star.user_cs_selector = gdt::constructed_cpl3_cs.flags - 16;
			constructed_star = star.flags;

			constructed_lstar = (uint64_t)asm_syscall_handler;

			constructed_fmask = 0;

			cpl_switching_inited = true;

			return true;
		}
	};

	namespace execution_mode {
		inline bool execution_mode_changing_allocated = false;
		inline bool execution_mode_changing_remapped = false;

		inline void* compatibility_stack = 0;
		inline void* compatibility_data_page = 0;
		inline void* compatibility_execution_page = 0;

		inline uint64_t backed_rsp;
		inline uint64_t backed_rip;

#define EXECUTION_PAGE_32_BIT_ADDRESS 0x0001000
#define EXECUTION_PAGE_32_BIT_USER_SHELLCODE_START EXECUTION_PAGE_32_BIT_ADDRESS + 0x100
#define DATA_PAGE_32_BIT_ADDRESS 0x00002000
#define COMPATIBILITY_STACK_32_BIT_ADDRESS 0x00003000


		inline bool execute_32_bit_shellcode(void* shellcode, uint64_t shellcode_size) {
			if (execution_mode_changing_allocated && !execution_mode_changing_remapped) {
				if (!physmem::remapping::overwrite_virtual_address_mapping((void*)EXECUTION_PAGE_32_BIT_ADDRESS, compatibility_execution_page, physmem::util::get_constructed_cr3().flags, physmem::util::get_system_cr3().flags))
					return false;

				if (!physmem::paging_manipulation::win_set_memory_range_supervisor((void*)EXECUTION_PAGE_32_BIT_ADDRESS, 0x1000, physmem::util::get_constructed_cr3().flags, 1))
					return false;

				if (!physmem::remapping::overwrite_virtual_address_mapping((void*)DATA_PAGE_32_BIT_ADDRESS, compatibility_data_page, physmem::util::get_constructed_cr3().flags, physmem::util::get_system_cr3().flags))
					return false;

				if (!physmem::paging_manipulation::win_set_memory_range_supervisor((void*)DATA_PAGE_32_BIT_ADDRESS, 0x1000, physmem::util::get_constructed_cr3().flags, 1))
					return false;

				for (uint64_t i = 0; i <= KERNEL_STACK_SIZE; i += PAGE_SIZE) {
					if (!physmem::remapping::overwrite_virtual_address_mapping((void*)(COMPATIBILITY_STACK_32_BIT_ADDRESS + i), (void*)((uint64_t)compatibility_stack + i), physmem::util::get_constructed_cr3().flags, physmem::util::get_system_cr3().flags))
						return false;
				}

				if (!physmem::paging_manipulation::win_set_memory_range_supervisor((void*)COMPATIBILITY_STACK_32_BIT_ADDRESS, KERNEL_STACK_SIZE, physmem::util::get_constructed_cr3().flags, 1))
					return false;

				execution_mode_changing_remapped = true;
			}


			memset(compatibility_stack, 0, KERNEL_STACK_SIZE);
			memset(compatibility_execution_page, 0, 0x1000);


			static uint8_t compatibility_prologue[] = {
				0x8C, 0xD0,
				0x8E, 0xD8,
				0x8E, 0xC0,
				0x8E, 0xE0,
				0x8E, 0xE8,

				0xB8, 0x00, 0x00, 0x00, 0x00,
				0xFF, 0xD0,
			};
			*(uint32_t*)(compatibility_prologue + 11) = (uint32_t)EXECUTION_PAGE_32_BIT_USER_SHELLCODE_START;


			static uint8_t compatibility_epilogue[] = {
				0xB8, 0x31, 0x73, 0x00, 0x00,
				0xCC
			};

			memcpy((void*)(EXECUTION_PAGE_32_BIT_USER_SHELLCODE_START), shellcode, shellcode_size);
			memcpy((void*)compatibility_execution_page, compatibility_prologue, sizeof(compatibility_prologue));
			memcpy((void*)((uint64_t)compatibility_execution_page + sizeof(compatibility_prologue)), compatibility_epilogue, sizeof(compatibility_epilogue));


			asm_execute_compatibility_mode_code();

			return true;
		}

		inline void* allocate_32bit_accessible_page(uint64_t size) {
			PHYSICAL_ADDRESS max_addr;

			max_addr.QuadPart = 0xFFFFFFFF;
			void* mem = MmAllocateContiguousMemory(size, max_addr);
			if (!mem)
				return 0;


			memset(mem, 0, size);
			return mem;
		}


		inline bool handle_mode_switch(idt_regs_ecode_t* record) {
			if (!record)
				return false;

			uint64_t eax = record->rax & 0xFFFFFFFF;
			if (eax == 0x1337 && record->exception_vector == breakpoint) {

				backed_rsp = record->rsp;
				backed_rip = record->rip;

				record->rsp = (uint64_t)COMPATIBILITY_STACK_32_BIT_ADDRESS + KERNEL_STACK_SIZE;
				record->rip = (uint64_t)EXECUTION_PAGE_32_BIT_ADDRESS;

				record->cs_selector = gdt::compatibility_constructed_cpl0_cs.flags;
				record->ss_selector = gdt::compatibility_constructed_cpl0_ss.flags;

				return true;
			}
			else if (eax == 0x7331 && record->exception_vector == breakpoint) {
				record->rsp = backed_rsp;
				record->rip = backed_rip;

				record->cs_selector = gdt::constructed_cpl0_cs.flags;
				record->ss_selector = gdt::constructed_cpl0_ss.flags;

				return true;
			}


			if (record->cs_selector == gdt::compatibility_constructed_cpl0_cs.flags &&
				record->ss_selector == gdt::compatibility_constructed_cpl0_ss.flags) {
				record->rsp = backed_rsp;
				record->rip = backed_rip;

				record->cs_selector = gdt::constructed_cpl0_cs.flags;
				record->ss_selector = gdt::constructed_cpl0_ss.flags;

				return true;
			}

			return false;
		}

		inline uint32_t get_compatibility_data_page_address(void) {
			return (uint32_t)DATA_PAGE_32_BIT_ADDRESS;
		}

		inline void* get_compatibility_data_page(void) {
			return compatibility_data_page;
		}

		inline bool init_execution_mode_changer(void) {

			compatibility_stack = allocate_32bit_accessible_page(KERNEL_STACK_SIZE);
			if (!compatibility_stack)
				return false;

			compatibility_execution_page = allocate_32bit_accessible_page(0x1000);
			if (!compatibility_execution_page)
				return false;

			compatibility_data_page = allocate_32bit_accessible_page(0x1000);
			if (!compatibility_data_page)
				return false;

			execution_mode_changing_allocated = true;
			return true;
		}
	};


	inline KPCR* safety_net_kpcr = 0;
	inline volatile LONG safety_net_active = 0;
	inline volatile LONG64 safety_net_start_sequence = 0;

	inline bool interrupts_enabled(void) {
		return (__readeflags() & 0x200ULL) != 0;
	}

	inline bool is_safety_net_active(void) {
		if (!inited)
			return false;


		segment_descriptor_register_64 current_gdtr;
		_sgdt(&current_gdtr);
		if (current_gdtr.base_address != gdt::my_gdtr.base_address ||
			current_gdtr.limit != gdt::my_gdtr.limit) {
			return false;
		}


		segment_descriptor_register_64 current_idtr;
		__sidt(&current_idtr);
		if (current_idtr.base_address != idt::my_idtr.base_address ||
			current_idtr.limit != idt::my_idtr.limit) {
			return false;
		}


		uint16_t current_ss = __read_ss().flags;
		uint16_t current_cs = __read_cs().flags;
		uint16_t current_tr = __read_tr().flags;

		if (current_ss != gdt::constructed_cpl0_ss.flags ||
			current_cs != gdt::constructed_cpl0_cs.flags ||
			current_tr != gdt::constructed_tr.flags) {
			return false;
		}


		rflags flags;
		flags.flags = __readeflags();
		if (flags.interrupt_enable_flag)
			return false;

		return true;
	}

	inline void set_safety_net_kpcr(KPCR* kpcr) {
		safety_net_kpcr = kpcr;
	}

	inline bool init_safety_net(uint64_t image_base, uint64_t image_size) {
		HVD_LOG_IMMEDIATE("safety_init_enter image_present=%u image_size=0x%llx inited=%u active=%ld cpu=%lu irql=%lu if=%u",
			image_base != 0 ? 1u : 0u,
			image_size,
			inited ? 1u : 0u,
			_InterlockedCompareExchange(&safety_net_active, 0, 0),
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
		if (!image_base || !image_size) {
			HVD_LOG_IMMEDIATE("safety_init_reject reason=missing_image cpu=%lu irql=%lu if=%u",
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			return false;
		}

		g_image_base = image_base;
		g_image_size = image_size;

		HVD_LOG_IMMEDIATE("safety_init_step_pre step=gdt cpu=%lu irql=%lu if=%u",
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
		if (!gdt::init_gdt()) {
			HVD_LOG_IMMEDIATE("safety_init_step_post step=gdt ok=0 cpu=%lu irql=%lu if=%u",
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			return false;
		}
		HVD_LOG_IMMEDIATE("safety_init_step_post step=gdt ok=1 cpu=%lu irql=%lu if=%u",
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);

		HVD_LOG_IMMEDIATE("safety_init_step_pre step=idt cpu=%lu irql=%lu if=%u",
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
		if (!idt::init_idt()) {
			HVD_LOG_IMMEDIATE("safety_init_step_post step=idt ok=0 cpu=%lu irql=%lu if=%u",
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			return false;
		}
		HVD_LOG_IMMEDIATE("safety_init_step_post step=idt ok=1 cpu=%lu irql=%lu if=%u",
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);

		HVD_LOG_IMMEDIATE("safety_init_step_pre step=cpl_switch cpu=%lu irql=%lu if=%u",
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
		if (!cpl::init_cpl_switcher()) {
			HVD_LOG_IMMEDIATE("safety_init_step_post step=cpl_switch ok=0 cpu=%lu irql=%lu if=%u",
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			return false;
		}
		HVD_LOG_IMMEDIATE("safety_init_step_post step=cpl_switch ok=1 cpu=%lu irql=%lu if=%u",
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);

		HVD_LOG_IMMEDIATE("safety_init_step_pre step=execution_mode cpu=%lu irql=%lu if=%u",
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
		if (!execution_mode::init_execution_mode_changer()) {
			HVD_LOG_IMMEDIATE("safety_init_step_post step=execution_mode ok=0 cpu=%lu irql=%lu if=%u",
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			return false;
		}
		HVD_LOG_IMMEDIATE("safety_init_step_post step=execution_mode ok=1 cpu=%lu irql=%lu if=%u",
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);

		inited = true;

		HVD_LOG_IMMEDIATE("safety_init_exit ok=1 image_size=0x%llx cpu=%lu irql=%lu if=%u",
			image_size,
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
		return true;
	}

	inline void free_safety_net(void) {
		HVD_LOG_IMMEDIATE("safety_free_enter inited=%u active=%ld gdt=%u tss=%u stack=%u idt=%u ctx=%u compat_stack=%u compat_exec=%u compat_data=%u cpu=%lu irql=%lu if=%u",
			inited ? 1u : 0u,
			_InterlockedCompareExchange(&safety_net_active, 0, 0),
			gdt::my_gdt ? 1u : 0u,
			gdt::my_tss ? 1u : 0u,
			gdt::interrupt_stack ? 1u : 0u,
			idt::my_idt ? 1u : 0u,
			idt::context_storage ? 1u : 0u,
			execution_mode::compatibility_stack ? 1u : 0u,
			execution_mode::compatibility_execution_page ? 1u : 0u,
			execution_mode::compatibility_data_page ? 1u : 0u,
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);

		if (gdt::my_gdt) {
			MmFreeContiguousMemory(gdt::my_gdt);
			gdt::my_gdt = 0;
		}
		if (gdt::my_tss) {
			MmFreeContiguousMemory(gdt::my_tss);
			gdt::my_tss = 0;
		}
		if (gdt::interrupt_stack) {
			MmFreeContiguousMemory(gdt::interrupt_stack);
			gdt::interrupt_stack = 0;
		}


		if (idt::my_idt) {
			MmFreeContiguousMemory(idt::my_idt);
			idt::my_idt = 0;
		}
		if (idt::context_storage) {
			MmFreeContiguousMemory(idt::context_storage);
			idt::context_storage = 0;
		}


		if (execution_mode::compatibility_stack) {
			MmFreeContiguousMemory(execution_mode::compatibility_stack);
			execution_mode::compatibility_stack = 0;
		}
		if (execution_mode::compatibility_execution_page) {
			MmFreeContiguousMemory(execution_mode::compatibility_execution_page);
			execution_mode::compatibility_execution_page = 0;
		}
		if (execution_mode::compatibility_data_page) {
			MmFreeContiguousMemory(execution_mode::compatibility_data_page);
			execution_mode::compatibility_data_page = 0;
		}
		_InterlockedExchange(&safety_net_active, 0);
		gdt::gdt_inited = false;
		gdt::my_gdtr = { 0 };
		idt::idt_inited = false;
		idt::my_idtr = { 0 };
		cpl::cpl_switching_inited = false;
		execution_mode::execution_mode_changing_allocated = false;
		execution_mode::execution_mode_changing_remapped = false;
		inited = false;
		HVD_LOG_IMMEDIATE("safety_free_exit cpu=%lu irql=%lu if=%u",
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
	}


	inline bool start_safety_net(safety_net_t& info_storage) {
		const LONG64 seq = _InterlockedIncrement64(&safety_net_start_sequence);
		RtlZeroMemory(&info_storage, sizeof(info_storage));
		HVD_LOG_IMMEDIATE("safety_start_enter seq=%lld inited=%u active=%ld physmem=%u cpu=%lu irql=%lu if=%u",
			seq,
			inited ? 1u : 0u,
			_InterlockedCompareExchange(&safety_net_active, 0, 0),
			physmem::is_initialized() ? 1u : 0u,
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
		if (!inited || !physmem::is_initialized()) {
			HVD_LOG_IMMEDIATE("safety_start_reject seq=%lld reason=not_initialized inited=%u physmem=%u cpu=%lu irql=%lu if=%u",
				seq,
				inited ? 1u : 0u,
				physmem::is_initialized() ? 1u : 0u,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			return false;
		}
		if (KeGetCurrentIrql() != PASSIVE_LEVEL || !interrupts_enabled()) {
			HVD_LOG_IMMEDIATE("safety_start_reject seq=%lld reason=unsafe_precondition cpu=%lu irql=%lu if=%u",
				seq,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			return false;
		}
		if (_InterlockedCompareExchange(&safety_net_active, 1, 0) != 0) {
			HVD_LOG_IMMEDIATE("safety_start_reject seq=%lld reason=already_active cpu=%lu irql=%lu if=%u",
				seq,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			return false;
		}

		bool ok = false;
		bool loaded_gdt = false;
		bool wrote_segments = false;
		bool wrote_tr = false;
		bool loaded_idt = false;
		bool loaded_cr3 = false;
		bool loaded_cr4 = false;
		bool wrote_gs = false;
		ULONG failed_step = 0;
		ULONG seh_code = 0;

		__try {
			failed_step = 1;
			HVD_LOG_IMMEDIATE("safety_start_step_pre seq=%lld step=%lu name=cli cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
			_cli();
			HVD_LOG_FAST("safety_start_step_post seq=%lld step=%lu name=cli ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);

			failed_step = 2;
			HVD_LOG_FAST("safety_start_step_pre seq=%lld step=%lu name=gs_base cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		info_storage.safed_kpcr = (KPCR*)__readmsr(IA32_GS_BASE);
		if (safety_net_kpcr) {
			__writemsr(IA32_GS_BASE, (uint64_t)safety_net_kpcr);
				wrote_gs = true;
			}
			HVD_LOG_FAST("safety_start_step_post seq=%lld step=%lu name=gs_base ok=1 kpcr_override=%u cpu=%lu irql=%lu if=%u",
				seq, failed_step, wrote_gs ? 1u : 0u, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);


			failed_step = 3;
			HVD_LOG_FAST("safety_start_step_pre seq=%lld step=%lu name=sgdt_lgdt cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		_sgdt(&info_storage.safed_gdtr);


		_lgdt(&gdt::my_gdtr);
			loaded_gdt = true;
			HVD_LOG_FAST("safety_start_step_post seq=%lld step=%lu name=sgdt_lgdt ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);


			failed_step = 4;
			HVD_LOG_FAST("safety_start_step_pre seq=%lld step=%lu name=segments cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		info_storage.safed_ss = __read_ss().flags;
		info_storage.safed_cs = __read_cs().flags;
		info_storage.safed_tr = __read_tr().flags;


		__write_ss(gdt::constructed_cpl0_ss.flags);
		__write_cs(gdt::constructed_cpl0_cs.flags);
			wrote_segments = true;
			HVD_LOG_FAST("safety_start_step_post seq=%lld step=%lu name=segments ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);


			failed_step = 5;
			HVD_LOG_FAST("safety_start_step_pre seq=%lld step=%lu name=tr cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		gdt::my_gdt[gdt::constructed_tr.index].type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
		__write_tr(gdt::constructed_tr.flags);
			wrote_tr = true;
			HVD_LOG_FAST("safety_start_step_post seq=%lld step=%lu name=tr ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);


			failed_step = 6;
			HVD_LOG_FAST("safety_start_step_pre seq=%lld step=%lu name=sidt_lidt cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		__sidt(&info_storage.safed_idtr);


		__lidt(&idt::my_idtr);
			loaded_idt = true;
			HVD_LOG_FAST("safety_start_step_post seq=%lld step=%lu name=sidt_lidt ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);


			failed_step = 7;
			HVD_LOG_FAST("safety_start_step_pre seq=%lld step=%lu name=cr3 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		info_storage.safed_cr3 = __readcr3();


		__writecr3(physmem::util::get_constructed_cr3().flags);
			loaded_cr3 = true;
			HVD_LOG_FAST("safety_start_step_post seq=%lld step=%lu name=cr3 ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);

			failed_step = 8;
			HVD_LOG_FAST("safety_start_step_pre seq=%lld step=%lu name=cr4 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		cr4 curr_cr4;
		curr_cr4.flags = __readcr4();
		info_storage.safed_cr4 = curr_cr4.flags;

		curr_cr4.smap_enable = 0;
		curr_cr4.smep_enable = 0;
		__writecr4(curr_cr4.flags);
			loaded_cr4 = true;
			HVD_LOG_FAST("safety_start_step_post seq=%lld step=%lu name=cr4 ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);

			ok = true;
		}
		__except ((seh_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
			HVD_LOG_FAST("safety_start_exception seq=%lld step=%lu code=0x%08lx loaded_gdt=%u segments=%u tr=%u idt=%u cr3=%u cr4=%u gs=%u cpu=%lu irql=%lu if=%u",
				seq,
				failed_step,
				seh_code,
				loaded_gdt ? 1u : 0u,
				wrote_segments ? 1u : 0u,
				wrote_tr ? 1u : 0u,
				loaded_idt ? 1u : 0u,
				loaded_cr3 ? 1u : 0u,
				loaded_cr4 ? 1u : 0u,
				wrote_gs ? 1u : 0u,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
		}

		if (!ok) {
			__try {
				if (loaded_cr4)
					__writecr4(info_storage.safed_cr4);
				if (loaded_cr3)
					__writecr3(info_storage.safed_cr3);
				if (loaded_idt)
					__lidt(&info_storage.safed_idtr);
				if (loaded_gdt)
					_lgdt(&info_storage.safed_gdtr);
				if (wrote_segments) {
					__write_ss(info_storage.safed_ss);
					__write_cs(info_storage.safed_cs);
				}
				if (wrote_tr) {
					segment_descriptor_32* saved_gdt = (segment_descriptor_32*)info_storage.safed_gdtr.base_address;
					segment_selector tr_selec;
					tr_selec.flags = info_storage.safed_tr;
					if (saved_gdt)
						saved_gdt[tr_selec.index].type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
					__write_tr(info_storage.safed_tr);
				}
				if (wrote_gs)
					__writemsr(IA32_GS_BASE, (uint64_t)info_storage.safed_kpcr);
				if (!interrupts_enabled())
					_sti();
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				if (!interrupts_enabled())
					_sti();
			}
			_InterlockedExchange(&safety_net_active, 0);
			HVD_LOG_IMMEDIATE("safety_start_exit seq=%lld ok=0 failed_step=%lu exception=0x%08lx cpu=%lu irql=%lu if=%u",
				seq,
				failed_step,
				seh_code,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			return false;
		}

		HVD_LOG_FAST("safety_start_exit seq=%lld ok=1 cpu=%lu irql=%lu if=%u",
			seq,
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
		return true;
	}

	inline void stop_safety_net(safety_net_t& info_storage) {
		const LONG64 seq = _InterlockedCompareExchange64(&safety_net_start_sequence, 0, 0);
		ULONG failed_step = 0;
		ULONG seh_code = 0;
		bool ok = false;
		HVD_LOG_FAST("safety_stop_enter seq=%lld active=%ld cpu=%lu irql=%lu if=%u",
			seq,
			_InterlockedCompareExchange(&safety_net_active, 0, 0),
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
		__try {
			failed_step = 1;
			HVD_LOG_FAST("safety_stop_step_pre seq=%lld step=%lu name=lgdt cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		_lgdt(&info_storage.safed_gdtr);
			HVD_LOG_FAST("safety_stop_step_post seq=%lld step=%lu name=lgdt ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);

			failed_step = 2;
			HVD_LOG_FAST("safety_stop_step_pre seq=%lld step=%lu name=segments cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		__write_ss(info_storage.safed_ss);
		__write_cs(info_storage.safed_cs);
			HVD_LOG_FAST("safety_stop_step_post seq=%lld step=%lu name=segments ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);


			failed_step = 3;
			HVD_LOG_FAST("safety_stop_step_pre seq=%lld step=%lu name=tr cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		segment_descriptor_32* gdt = (segment_descriptor_32*)info_storage.safed_gdtr.base_address;
		segment_selector tr_selec;
		tr_selec.flags = info_storage.safed_tr;
		if (gdt)
			gdt[tr_selec.index].type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
		__write_tr(info_storage.safed_tr);
			HVD_LOG_FAST("safety_stop_step_post seq=%lld step=%lu name=tr ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);

			failed_step = 4;
			HVD_LOG_FAST("safety_stop_step_pre seq=%lld step=%lu name=lidt cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		__lidt(&info_storage.safed_idtr);
			HVD_LOG_FAST("safety_stop_step_post seq=%lld step=%lu name=lidt ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);

			failed_step = 5;
			HVD_LOG_FAST("safety_stop_step_pre seq=%lld step=%lu name=cr3 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		__writecr3(info_storage.safed_cr3);
			HVD_LOG_FAST("safety_stop_step_post seq=%lld step=%lu name=cr3 ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);

			failed_step = 6;
			HVD_LOG_FAST("safety_stop_step_pre seq=%lld step=%lu name=cr4 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		__writecr4(info_storage.safed_cr4);
			HVD_LOG_FAST("safety_stop_step_post seq=%lld step=%lu name=cr4 ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);

			failed_step = 7;
			HVD_LOG_FAST("safety_stop_step_pre seq=%lld step=%lu name=gs_base cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		__writemsr(IA32_GS_BASE, (uint64_t)info_storage.safed_kpcr);
			HVD_LOG_FAST("safety_stop_step_post seq=%lld step=%lu name=gs_base ok=1 cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);

			failed_step = 8;
			HVD_LOG_FAST("safety_stop_step_pre seq=%lld step=%lu name=sti cpu=%lu irql=%lu if=%u",
				seq, failed_step, KeGetCurrentProcessorNumber(), (ULONG)KeGetCurrentIrql(), interrupts_enabled() ? 1u : 0u);
		_sti();
			ok = true;
		}
		__except ((seh_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
			HVD_LOG_FAST("safety_stop_exception seq=%lld step=%lu code=0x%08lx cpu=%lu irql=%lu if=%u",
				seq,
				failed_step,
				seh_code,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				interrupts_enabled() ? 1u : 0u);
			if (!interrupts_enabled())
				_sti();
		}
		_InterlockedExchange(&safety_net_active, 0);
		HVD_LOG_IMMEDIATE("safety_stop_exit seq=%lld ok=%u failed_step=%lu exception=0x%08lx cpu=%lu irql=%lu if=%u",
			seq,
			ok ? 1u : 0u,
			failed_step,
			seh_code,
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			interrupts_enabled() ? 1u : 0u);
	}
};
