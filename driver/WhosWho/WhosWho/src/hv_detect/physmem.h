#pragma once
#include "physmem_decl.h"
#include "page_table_helpers.h"
#include "win_helpers.h"
#include "../function/KernelLayout.h"

namespace physmem {


	inline physmem_t physmem;

	inline uint64_t trace_elapsed_us(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
		LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
		if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart)
			return 0;
		return static_cast<uint64_t>(((now.QuadPart - start.QuadPart) * 1000000ULL) / static_cast<uint64_t>(freq.QuadPart));
	}

	inline uint64_t ptr_u64(const void* value) {
		return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(value));
	}

	inline uint64_t phys_u64(void* value) {
		if (!value)
			return 0;
		return static_cast<uint64_t>(MmGetPhysicalAddress(value).QuadPart);
	}

	namespace support {
		inline bool is_physmem_supported(void) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_support_enter cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());


			char vendor[13] = { 0 };
			cpuidsplit_t vendor_cpuid_data;
			__cpuid((int*)&vendor_cpuid_data, 0);
			((int*)vendor)[0] = vendor_cpuid_data.ebx;
			((int*)vendor)[1] = vendor_cpuid_data.edx;
			((int*)vendor)[2] = vendor_cpuid_data.ecx;
			if ((strncmp(vendor, "GenuineIntel", 12) != 0) &&
				(strncmp(vendor, "AuthenticAMD", 12) != 0)) {
				HVD_LOG_IMMEDIATE("physmem_support_exit ok=0 reason=vendor vendor=%.12s elapsed_us=%llu cpu=%lu irql=%lu",
					vendor,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}


			cr4 curr_cr4;
			curr_cr4.flags = __readcr4();
			if (curr_cr4.linear_addresses_57_bit) {
				HVD_LOG_IMMEDIATE("physmem_support_exit ok=0 reason=la57 vendor=%.12s cr4=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					vendor,
					curr_cr4.flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}


			cpuid_eax_01 cpuid_1;
			__cpuid((int*)(&cpuid_1), 1);
			if (!cpuid_1.cpuid_feature_information_edx.physical_address_extension) {
				HVD_LOG_IMMEDIATE("physmem_support_exit ok=0 reason=no_pae vendor=%.12s cpuid_edx=0x%08x elapsed_us=%llu cpu=%lu irql=%lu",
					vendor,
					cpuid_1.cpuid_feature_information_edx.flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}


			if (!cpuid_1.cpuid_feature_information_edx.sse2_support) {
				HVD_LOG_IMMEDIATE("physmem_support_exit ok=0 reason=no_sse2 vendor=%.12s cpuid_edx=0x%08x elapsed_us=%llu cpu=%lu irql=%lu",
					vendor,
					cpuid_1.cpuid_feature_information_edx.flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}


			if(!cpuid_1.cpuid_feature_information_edx.apic_on_chip) {
				HVD_LOG_IMMEDIATE("physmem_support_exit ok=0 reason=no_apic vendor=%.12s cpuid_edx=0x%08x elapsed_us=%llu cpu=%lu irql=%lu",
					vendor,
					cpuid_1.cpuid_feature_information_edx.flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			HVD_LOG_IMMEDIATE("physmem_support_exit ok=1 vendor=%.12s cr4=0x%llx cpuid_edx=0x%08x elapsed_us=%llu cpu=%lu irql=%lu",
				vendor,
				curr_cr4.flags,
				cpuid_1.cpuid_feature_information_edx.flags,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return true;
		}
	};

	namespace page_table_initialization {
		inline void* allocate_zero_table(PHYSICAL_ADDRESS max_addr) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_alloc_zero_table_pre size=0x%llx max_addr=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				static_cast<uint64_t>(PAGE_SIZE),
				static_cast<uint64_t>(max_addr.QuadPart),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			void* table = (void*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

			if (table)
				memset(table, 0, PAGE_SIZE);

			HVD_LOG_IMMEDIATE("physmem_alloc_zero_table_post ok=%u va=0x%llx pa=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				table ? 1u : 0u,
				ptr_u64(table),
				phys_u64(table),
				static_cast<uint64_t>(PAGE_SIZE),
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return table;
		}

		inline bool allocate_page_tables(void) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_allocate_page_tables_enter page_tables_size=0x%llx remap_count=%llu cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				static_cast<uint64_t>(sizeof(page_tables_t)),
				static_cast<uint64_t>(REMAPPING_TABLE_COUNT),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;

			physmem.page_tables = (page_tables_t*)MmAllocateContiguousMemory(sizeof(page_tables_t), max_addr);
			if(!physmem.page_tables) {
				HVD_LOG_IMMEDIATE("physmem_allocate_page_tables_exit ok=0 reason=page_tables_alloc_failed elapsed_us=%llu cpu=%lu irql=%lu",
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}
			HVD_LOG_IMMEDIATE("physmem_allocate_page_tables_alloc ok=1 va=0x%llx pa=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(physmem.page_tables),
				phys_u64(physmem.page_tables),
				static_cast<uint64_t>(sizeof(page_tables_t)),
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());


			memset(physmem.page_tables, 0, sizeof(page_tables_t));

			for (uint64_t i = 0; i < REMAPPING_TABLE_COUNT; i++) {
				physmem.remapping_tables.pdpt_table[i] = (pdpte_64*)allocate_zero_table(max_addr);
				physmem.remapping_tables.pd_table[i] = (pde_64*)allocate_zero_table(max_addr);
				physmem.remapping_tables.pt_table[i] = (pte_64*)allocate_zero_table(max_addr);

				if (!physmem.remapping_tables.pdpt_table[i] || !physmem.remapping_tables.pd_table[i] || !physmem.remapping_tables.pt_table[i]) {
					HVD_LOG_IMMEDIATE("physmem_allocate_page_tables_exit ok=0 reason=remap_table_alloc_failed index=%llu pdpt=0x%llx pd=0x%llx pt=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
						i,
						ptr_u64(physmem.remapping_tables.pdpt_table[i]),
						ptr_u64(physmem.remapping_tables.pd_table[i]),
						ptr_u64(physmem.remapping_tables.pt_table[i]),
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					return false;
				}
				HVD_LOG_IMMEDIATE("physmem_allocate_page_tables_remap index=%llu pdpt_va=0x%llx pdpt_pa=0x%llx pd_va=0x%llx pd_pa=0x%llx pt_va=0x%llx pt_pa=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					i,
					ptr_u64(physmem.remapping_tables.pdpt_table[i]),
					phys_u64(physmem.remapping_tables.pdpt_table[i]),
					ptr_u64(physmem.remapping_tables.pd_table[i]),
					phys_u64(physmem.remapping_tables.pd_table[i]),
					ptr_u64(physmem.remapping_tables.pt_table[i]),
					phys_u64(physmem.remapping_tables.pt_table[i]),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());

			}

			HVD_LOG_IMMEDIATE("physmem_allocate_page_tables_exit ok=1 elapsed_us=%llu cpu=%lu irql=%lu",
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return true;
		}

		inline uint64_t get_cr3(uint64_t target_pid) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_get_cr3_enter target_pid=%llu cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				target_pid,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			PEPROCESS sys_process = PsInitialSystemProcess;
			PEPROCESS curr_entry = sys_process;
			SIZE_T unique_pid_offset = whoswho_kernel_layout::eprocess_unique_process_id_offset();
			SIZE_T active_links_offset = whoswho_kernel_layout::eprocess_active_process_links_offset();
			SIZE_T active_threads_offset = whoswho_kernel_layout::eprocess_active_threads_offset();
			if (unique_pid_offset == 0 || active_links_offset == 0 || active_threads_offset == 0) {
				HVD_LOG_IMMEDIATE("physmem_get_cr3_exit ok=0 target_pid=%llu reason=unsupported_eprocess_layout build=%lu unique=0x%llx active=0x%llx threads=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					target_pid,
					whoswho_kernel_layout::build_number(),
					static_cast<unsigned long long>(unique_pid_offset),
					static_cast<unsigned long long>(active_links_offset),
					static_cast<unsigned long long>(active_threads_offset),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return 0;
			}

			do {
				uint64_t curr_pid;

				memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + unique_pid_offset), sizeof(curr_pid));


				if (target_pid == curr_pid) {

					uint32_t active_threads;

					memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + active_threads_offset), sizeof(active_threads));

					if (active_threads || target_pid == 4) {
						uint64_t cr3;

						memcpy(&cr3, (void*)((uintptr_t)curr_entry + 0x28), sizeof(cr3));

						HVD_LOG_IMMEDIATE("physmem_get_cr3_exit ok=1 target_pid=%llu cr3=0x%llx active_threads=%u eprocess=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
							target_pid,
							cr3,
							active_threads,
							ptr_u64(curr_entry),
							trace_elapsed_us(start, freq),
							KeGetCurrentProcessorNumber(),
							(ULONG)KeGetCurrentIrql());
						return cr3;
					}
				}

				PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+active_links_offset);
				curr_entry = (PEPROCESS)((uintptr_t)list->Flink - active_links_offset);
			} while (curr_entry != sys_process);

			HVD_LOG_IMMEDIATE("physmem_get_cr3_exit ok=0 target_pid=%llu elapsed_us=%llu cpu=%lu irql=%lu",
				target_pid,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return 0;
		}

		inline bool copy_kernel_page_tables(void) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_copy_kernel_pt_enter page_tables=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(physmem.page_tables),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			pml4e_64* kernel_pml4_page_table = 0;

			physmem.kernel_cr3.flags = get_cr3(4);
			if (!physmem.kernel_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_copy_kernel_pt_exit ok=0 reason=no_kernel_cr3 elapsed_us=%llu cpu=%lu irql=%lu",
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			kernel_pml4_page_table = (pml4e_64*)win::win_get_virtual_address(physmem.kernel_cr3.address_of_page_directory << 12);
			HVD_LOG_IMMEDIATE("physmem_copy_kernel_pt_lookup kernel_cr3=0x%llx pml4_pa=0x%llx pml4_va=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				physmem.kernel_cr3.flags,
				physmem.kernel_cr3.address_of_page_directory << 12,
				ptr_u64(kernel_pml4_page_table),
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			if (!kernel_pml4_page_table) {
				HVD_LOG_IMMEDIATE("physmem_copy_kernel_pt_exit ok=0 reason=no_kernel_pml4 elapsed_us=%llu cpu=%lu irql=%lu",
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			memcpy(physmem.page_tables->pml4_table, kernel_pml4_page_table, sizeof(pml4e_64) * 512);

			physmem.constructed_cr3.flags = physmem.kernel_cr3.flags;
			physmem.constructed_cr3.address_of_page_directory = win::win_get_physical_address(physmem.page_tables->pml4_table) >> 12;
			if (!physmem.constructed_cr3.address_of_page_directory) {
				HVD_LOG_IMMEDIATE("physmem_copy_kernel_pt_exit ok=0 reason=no_constructed_pml4_phys constructed_cr3=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					physmem.constructed_cr3.flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			HVD_LOG_IMMEDIATE("physmem_copy_kernel_pt_exit ok=1 kernel_cr3=0x%llx constructed_cr3=0x%llx constructed_pml4_pa=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				physmem.kernel_cr3.flags,
				physmem.constructed_cr3.flags,
				physmem.constructed_cr3.address_of_page_directory << 12,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return true;
		}

		inline uint64_t calculate_physical_memory_base(uint64_t pml4e_idx) {

			return (pml4e_idx << (9 + 9 + 9 + 12));
		}

		inline bool map_full_system_physical_memory(uint32_t free_pml4_idx) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_map_full_enter free_pml4_idx=%u page_tables=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				free_pml4_idx,
				ptr_u64(physmem.page_tables),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			page_tables_t* page_tables = physmem.page_tables;


			page_tables->pml4_table[free_pml4_idx].present = 1;
			page_tables->pml4_table[free_pml4_idx].write = 1;
			page_tables->pml4_table[free_pml4_idx].page_frame_number = win::win_get_physical_address(&page_tables->pdpt_table) >> 12;
			if (!page_tables->pml4_table[free_pml4_idx].page_frame_number) {
				HVD_LOG_IMMEDIATE("physmem_map_full_exit ok=0 reason=no_pdpt_phys free_pml4_idx=%u elapsed_us=%llu cpu=%lu irql=%lu",
					free_pml4_idx,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			for (uint64_t i = 0; i < PAGE_TABLE_ENTRY_COUNT; i++) {
				page_tables->pdpt_table[i].present = 1;
				page_tables->pdpt_table[i].write = 1;
				page_tables->pdpt_table[i].page_frame_number = win::win_get_physical_address(&page_tables->pd_2mb_table[i]) >> 12;
				if (!page_tables->pdpt_table[i].page_frame_number) {
					HVD_LOG_IMMEDIATE("physmem_map_full_exit ok=0 reason=no_pd_phys pdpt_index=%llu elapsed_us=%llu cpu=%lu irql=%lu",
						i,
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					return false;
				}

				for (uint64_t j = 0; j < PAGE_TABLE_ENTRY_COUNT; j++) {
					page_tables->pd_2mb_table[i][j].present = 1;
					page_tables->pd_2mb_table[i][j].write = 1;
					page_tables->pd_2mb_table[i][j].large_page = 1;
					page_tables->pd_2mb_table[i][j].page_frame_number = (i << 9) + j;
				}
			}

			HVD_LOG_IMMEDIATE("physmem_map_full_exit ok=1 free_pml4_idx=%u pml4e_flags=0x%llx pdpt_pa=0x%llx mapped_range_start=0x0 mapped_range_size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				free_pml4_idx,
				page_tables->pml4_table[free_pml4_idx].flags,
				page_tables->pml4_table[free_pml4_idx].page_frame_number << 12,
				static_cast<uint64_t>(PAGE_TABLE_ENTRY_COUNT) * static_cast<uint64_t>(PAGE_TABLE_ENTRY_COUNT) * 0x200000ULL,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return true;
		}

		inline bool construct_my_page_tables(void) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_construct_pt_enter page_tables=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(physmem.page_tables),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			page_tables_t* page_tables = physmem.page_tables;

			uint32_t free_pml4_idx = pt_helpers::find_free_pml4e_index(page_tables->pml4_table);
			if (!pt_helpers::is_index_valid(free_pml4_idx)) {
				HVD_LOG_IMMEDIATE("physmem_construct_pt_exit ok=0 reason=no_free_pml4 index=%u elapsed_us=%llu cpu=%lu irql=%lu",
					free_pml4_idx,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			bool status = map_full_system_physical_memory(free_pml4_idx);
			if (status != true) {
				HVD_LOG_IMMEDIATE("physmem_construct_pt_exit ok=0 reason=map_full_failed index=%u elapsed_us=%llu cpu=%lu irql=%lu",
					free_pml4_idx,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}

			physmem.mapped_physical_mem_base = calculate_physical_memory_base(free_pml4_idx);
			if (!physmem.mapped_physical_mem_base) {
				HVD_LOG_IMMEDIATE("physmem_construct_pt_exit ok=0 reason=no_mapped_base index=%u elapsed_us=%llu cpu=%lu irql=%lu",
					free_pml4_idx,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			HVD_LOG_IMMEDIATE("physmem_construct_pt_exit ok=1 free_pml4_idx=%u mapped_base=0x%llx constructed_cr3=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				free_pml4_idx,
				physmem.mapped_physical_mem_base,
				physmem.constructed_cr3.flags,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return true;
		}

		inline bool initialize_page_tables(void) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_initialize_pt_enter cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			bool status = page_table_initialization::allocate_page_tables();
			if (status != true) {
				HVD_LOG_IMMEDIATE("physmem_initialize_pt_exit ok=0 step=allocate elapsed_us=%llu cpu=%lu irql=%lu",
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}

			status = page_table_initialization::copy_kernel_page_tables();
			if (status != true) {
				HVD_LOG_IMMEDIATE("physmem_initialize_pt_exit ok=0 step=copy_kernel elapsed_us=%llu cpu=%lu irql=%lu",
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}

			status = page_table_initialization::construct_my_page_tables();
			if (status != true) {
				HVD_LOG_IMMEDIATE("physmem_initialize_pt_exit ok=0 step=construct elapsed_us=%llu cpu=%lu irql=%lu",
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}

			HVD_LOG_IMMEDIATE("physmem_initialize_pt_exit ok=1 elapsed_us=%llu cpu=%lu irql=%lu",
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return status;
		}
	}

	namespace util {
		inline cr3 get_constructed_cr3(void) {
			return physmem.constructed_cr3;
		}

		inline cr3 get_system_cr3(void) {
			return physmem.kernel_cr3;
		}
	};


	namespace runtime {
		inline bool translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address, uint64_t* remaining_bytes) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_translate_enter target_cr3=0x%llx va=0x%llx constructed_cr3=0x%llx mapped_base=0x%llx remaining_out=%u cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				outside_target_cr3,
				ptr_u64(virtual_address),
				physmem.constructed_cr3.flags,
				physmem.mapped_physical_mem_base,
				remaining_bytes ? 1u : 0u,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_translate_exit ok=0 reason=precondition target_cr3=0x%llx va=0x%llx current_cr3=0x%llx constructed_cr3=0x%llx if=%u elapsed_us=%llu cpu=%lu irql=%lu",
					outside_target_cr3,
					ptr_u64(virtual_address),
					__readcr3(),
					physmem.constructed_cr3.flags,
					flags.interrupt_enable_flag ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			cr3 target_cr3 = { 0 };
			va_64_t va = { 0 };

			target_cr3.flags = outside_target_cr3;
			va.flags = (uint64_t)virtual_address;

			bool status = true;
			pml4e_64* mapped_pml4_table = 0;
			pml4e_64* mapped_pml4_entry = 0;

			pdpte_64* mapped_pdpt_table = 0;
			pdpte_64* mapped_pdpt_entry = 0;

			pde_64* mapped_pde_table = 0;
			pde_64* mapped_pde_entry = 0;

			pte_64* mapped_pte_table = 0;
			pte_64* mapped_pte_entry = 0;

			mapped_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (target_cr3.address_of_page_directory << 12));
			mapped_pml4_entry = &mapped_pml4_table[va.pml4e_idx];
			if (!mapped_pml4_entry->present) {
				status = false;
				HVD_LOG_IMMEDIATE("physmem_translate_exit ok=0 reason=pml4_not_present va=0x%llx pml4_idx=%llu pml4_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(virtual_address),
					static_cast<uint64_t>(va.pml4e_idx),
					mapped_pml4_entry->flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}

			mapped_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (mapped_pml4_entry->page_frame_number << 12));
			mapped_pdpt_entry = &mapped_pdpt_table[va.pdpte_idx];
			if (!mapped_pdpt_entry->present) {
				status = false;
				HVD_LOG_IMMEDIATE("physmem_translate_exit ok=0 reason=pdpt_not_present va=0x%llx pdpt_idx=%llu pdpt_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(virtual_address),
					static_cast<uint64_t>(va.pdpte_idx),
					mapped_pdpt_entry->flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}

			if (mapped_pdpt_entry->large_page) {
				pdpte_1gb_64 mapped_pdpte_1gb_entry;
				mapped_pdpte_1gb_entry.flags = mapped_pdpt_entry->flags;

				physical_address = (mapped_pdpte_1gb_entry.page_frame_number << 30) + va.offset_1gb;
				if(remaining_bytes)
					*remaining_bytes = 0x40000000 - va.offset_1gb;

				HVD_LOG_IMMEDIATE("physmem_translate_exit ok=1 level=1gb va=0x%llx pa=0x%llx remaining=0x%llx entry_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(virtual_address),
					physical_address,
					remaining_bytes ? *remaining_bytes : 0,
					mapped_pdpt_entry->flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}


			mapped_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (mapped_pdpt_entry->page_frame_number << 12));
			mapped_pde_entry = &mapped_pde_table[va.pde_idx];
			if (!mapped_pde_entry->present) {
				status = false;
				HVD_LOG_IMMEDIATE("physmem_translate_exit ok=0 reason=pde_not_present va=0x%llx pde_idx=%llu pde_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(virtual_address),
					static_cast<uint64_t>(va.pde_idx),
					mapped_pde_entry->flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}

			if (mapped_pde_entry->large_page) {
				pde_2mb_64 mapped_pde_2mb_entry;
				mapped_pde_2mb_entry.flags = mapped_pde_entry->flags;

				physical_address = (mapped_pde_2mb_entry.page_frame_number << 21) + va.offset_2mb;
				if (remaining_bytes)
					*remaining_bytes = 0x200000 - va.offset_2mb;

				HVD_LOG_IMMEDIATE("physmem_translate_exit ok=1 level=2mb va=0x%llx pa=0x%llx remaining=0x%llx entry_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(virtual_address),
					physical_address,
					remaining_bytes ? *remaining_bytes : 0,
					mapped_pde_entry->flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_entry->page_frame_number << 12));
			mapped_pte_entry = &mapped_pte_table[va.pte_idx];
			if (!mapped_pte_entry->present) {
				status = false;
				HVD_LOG_IMMEDIATE("physmem_translate_exit ok=0 reason=pte_not_present va=0x%llx pte_idx=%llu pte_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(virtual_address),
					static_cast<uint64_t>(va.pte_idx),
					mapped_pte_entry->flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return status;
			}

			physical_address = (mapped_pte_entry->page_frame_number << 12) + va.offset_4kb;
			if (remaining_bytes)
				*remaining_bytes = 0x1000 - va.offset_4kb;

			HVD_LOG_IMMEDIATE("physmem_translate_exit ok=1 level=4kb va=0x%llx pa=0x%llx remaining=0x%llx entry_flags=0x%llx present=%u write=%u supervisor=%u elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(virtual_address),
				physical_address,
				remaining_bytes ? *remaining_bytes : 0,
				mapped_pte_entry->flags,
				mapped_pte_entry->present ? 1u : 0u,
				mapped_pte_entry->write ? 1u : 0u,
				mapped_pte_entry->supervisor ? 1u : 0u,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return status;
		}

		inline void copy_physical_memory(uint64_t dst_physical, uint64_t src_physical, uint64_t size) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_copy_physical_enter dst_pa=0x%llx src_pa=0x%llx size=0x%llx mapped_base=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				dst_physical,
				src_physical,
				size,
				physmem.mapped_physical_mem_base,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_copy_physical_exit ok=0 reason=precondition current_cr3=0x%llx constructed_cr3=0x%llx if=%u elapsed_us=%llu cpu=%lu irql=%lu",
					__readcr3(),
					physmem.constructed_cr3.flags,
					flags.interrupt_enable_flag ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return;
			}

			void* virtual_src = 0;
			void* virtual_dst = 0;

			virtual_src = (void*)(src_physical + physmem.mapped_physical_mem_base);
			virtual_dst = (void*)(dst_physical + physmem.mapped_physical_mem_base);

			HVD_LOG_IMMEDIATE("physmem_copy_physical_memcpy_pre dst_va=0x%llx src_va=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(virtual_dst),
				ptr_u64(virtual_src),
				size,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			memcpy(virtual_dst, virtual_src, size);
			HVD_LOG_IMMEDIATE("physmem_copy_physical_exit ok=1 dst_va=0x%llx src_va=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(virtual_dst),
				ptr_u64(virtual_src),
				size,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
		}

		inline bool copy_virtual_memory(void* dst, void* src, uint64_t size, uint64_t dst_cr3, uint64_t src_cr3) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_copy_virtual_enter dst=0x%llx src=0x%llx size=0x%llx dst_cr3=0x%llx src_cr3=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(dst),
				ptr_u64(src),
				size,
				dst_cr3,
				src_cr3,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_copy_virtual_exit ok=0 reason=precondition current_cr3=0x%llx constructed_cr3=0x%llx if=%u elapsed_us=%llu cpu=%lu irql=%lu",
					__readcr3(),
					physmem.constructed_cr3.flags,
					flags.interrupt_enable_flag ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			bool status = true;

			void* current_virtual_src = 0;
			void* current_virtual_dst = 0;
			uint64_t current_physical_src = 0;
			uint64_t current_physical_dst = 0;
			uint64_t src_remaining = 0;
			uint64_t dst_remaining = 0;
			uint64_t copyable_size = 0;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {

				status = translate_to_physical_address(src_cr3, (void*)((uint64_t)src + copied_bytes), current_physical_src, &src_remaining);
				if (status != true) {
					HVD_LOG_IMMEDIATE("physmem_copy_virtual_exit ok=0 reason=src_translate copied=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
						copied_bytes,
						size,
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					break;
				}
				status = translate_to_physical_address(dst_cr3, (void*)((uint64_t)dst + copied_bytes), current_physical_dst, &dst_remaining);
				if (status != true) {
					HVD_LOG_IMMEDIATE("physmem_copy_virtual_exit ok=0 reason=dst_translate copied=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
						copied_bytes,
						size,
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					break;
				}

				current_virtual_src = (void*)(current_physical_src + physmem.mapped_physical_mem_base);
				current_virtual_dst = (void*)(current_physical_dst + physmem.mapped_physical_mem_base);

				copyable_size = min(PAGE_SIZE, size - copied_bytes);
				copyable_size = min(copyable_size, src_remaining);
				copyable_size = min(copyable_size, dst_remaining);


				memcpy(current_virtual_dst, current_virtual_src, copyable_size);

				copied_bytes += copyable_size;
				HVD_LOG_IMMEDIATE("physmem_copy_virtual_chunk copied=0x%llx chunk=0x%llx src_pa=0x%llx dst_pa=0x%llx src_va=0x%llx dst_va=0x%llx src_remaining=0x%llx dst_remaining=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					copied_bytes,
					copyable_size,
					current_physical_src,
					current_physical_dst,
					ptr_u64(current_virtual_src),
					ptr_u64(current_virtual_dst),
					src_remaining,
					dst_remaining,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
			}

			HVD_LOG_IMMEDIATE("physmem_copy_virtual_exit ok=%u copied=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				status ? 1u : 0u,
				copied_bytes,
				size,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return status;
		}

		inline bool copy_memory_to_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t src_cr3) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_copy_to_constructed_enter dst=0x%llx src=0x%llx size=0x%llx src_cr3=0x%llx constructed_cr3=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(dst),
				ptr_u64(src),
				size,
				src_cr3,
				physmem.constructed_cr3.flags,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_copy_to_constructed_exit ok=0 reason=precondition current_cr3=0x%llx constructed_cr3=0x%llx if=%u elapsed_us=%llu cpu=%lu irql=%lu",
					__readcr3(),
					physmem.constructed_cr3.flags,
					flags.interrupt_enable_flag ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			bool status = true;

			void* current_virtual_src = 0;
			void* current_virtual_dst = 0;
			uint64_t current_physical_src = 0;
			uint64_t src_remaining = 0;
			uint64_t copyable_size = 0;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {

				status = translate_to_physical_address(src_cr3, (void*)((uint64_t)src + copied_bytes), current_physical_src, &src_remaining);
				if (status != true) {
					HVD_LOG_IMMEDIATE("physmem_copy_to_constructed_exit ok=0 reason=src_translate copied=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
						copied_bytes,
						size,
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					break;
				}

				current_virtual_src = (void*)(current_physical_src + physmem.mapped_physical_mem_base);
				current_virtual_dst = (void*)((uint64_t)dst + copied_bytes);

				copyable_size = min(PAGE_SIZE, size - copied_bytes);
				copyable_size = min(copyable_size, src_remaining);


				memcpy(current_virtual_dst, current_virtual_src, copyable_size);

				copied_bytes += copyable_size;
				HVD_LOG_IMMEDIATE("physmem_copy_to_constructed_chunk copied=0x%llx chunk=0x%llx src_pa=0x%llx src_va=0x%llx dst_va=0x%llx src_remaining=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					copied_bytes,
					copyable_size,
					current_physical_src,
					ptr_u64(current_virtual_src),
					ptr_u64(current_virtual_dst),
					src_remaining,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
			}

			HVD_LOG_IMMEDIATE("physmem_copy_to_constructed_exit ok=%u copied=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				status ? 1u : 0u,
				copied_bytes,
				size,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return status;
		}

		inline bool copy_memory_from_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t dst_cr3) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_copy_from_constructed_enter dst=0x%llx src=0x%llx size=0x%llx dst_cr3=0x%llx constructed_cr3=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(dst),
				ptr_u64(src),
				size,
				dst_cr3,
				physmem.constructed_cr3.flags,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_copy_from_constructed_exit ok=0 reason=precondition current_cr3=0x%llx constructed_cr3=0x%llx if=%u elapsed_us=%llu cpu=%lu irql=%lu",
					__readcr3(),
					physmem.constructed_cr3.flags,
					flags.interrupt_enable_flag ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			bool status = true;

			void* current_virtual_src = 0;
			void* current_virtual_dst = 0;
			uint64_t current_physical_dst = 0;
			uint64_t dst_remaining = 0;
			uint64_t copyable_size = 0;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {

				status = translate_to_physical_address(dst_cr3, (void*)((uint64_t)dst + copied_bytes), current_physical_dst, &dst_remaining);
				if (status != true) {
					HVD_LOG_IMMEDIATE("physmem_copy_from_constructed_exit ok=0 reason=dst_translate copied=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
						copied_bytes,
						size,
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					break;
				}

				current_virtual_src = (void*)((uint64_t)src + copied_bytes);
				current_virtual_dst = (void*)(current_physical_dst + physmem.mapped_physical_mem_base);

				copyable_size = min(PAGE_SIZE, size - copied_bytes);
				copyable_size = min(copyable_size, dst_remaining);


				memcpy(current_virtual_dst, current_virtual_src, copyable_size);

				copied_bytes += copyable_size;
				HVD_LOG_IMMEDIATE("physmem_copy_from_constructed_chunk copied=0x%llx chunk=0x%llx dst_pa=0x%llx src_va=0x%llx dst_va=0x%llx dst_remaining=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					copied_bytes,
					copyable_size,
					current_physical_dst,
					ptr_u64(current_virtual_src),
					ptr_u64(current_virtual_dst),
					dst_remaining,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
			}

			HVD_LOG_IMMEDIATE("physmem_copy_from_constructed_exit ok=%u copied=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				status ? 1u : 0u,
				copied_bytes,
				size,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return status;
		}
	};


	namespace remapping {
		inline bool get_remapping_entry(void* mem, remapped_entry_t*& remapping_entry) {
			va_64_t target_va = { 0 };
			remapped_entry_t dummy = { 0 };
			remapped_entry_t* curr_closest_entry = &dummy;

			target_va.flags = (uint64_t)mem;

			for (uint32_t i = 0; i < MAX_REMAPPINGS; i++) {
				remapped_entry_t* curr_entry = &physmem.remapping_tables.remapping_list[i];


				if (!curr_entry->used)
					continue;


				if (curr_entry->remapped_va.pml4e_idx != target_va.pml4e_idx)
					continue;


				if (curr_entry->remapped_va.pdpte_idx != target_va.pdpte_idx) {


					if (curr_closest_entry->remapped_va.pml4e_idx == target_va.pml4e_idx)
						continue;


					curr_closest_entry = curr_entry;
					continue;
				}


				if (curr_entry->pdpt_table.large_page) {
					curr_closest_entry = curr_entry;
					goto cleanup;
				}


				if (curr_entry->remapped_va.pde_idx != target_va.pde_idx) {


					if (curr_closest_entry->remapped_va.pml4e_idx == target_va.pml4e_idx &&
						curr_closest_entry->remapped_va.pdpte_idx == target_va.pdpte_idx)
						continue;


					curr_closest_entry = curr_entry;
					continue;
				}

				if (curr_entry->pd_table.large_page) {
					curr_closest_entry = curr_entry;
					goto cleanup;
				}


				if (curr_entry->remapped_va.pte_idx != target_va.pte_idx) {


					if (curr_closest_entry->remapped_va.pml4e_idx == target_va.pml4e_idx &&
						curr_closest_entry->remapped_va.pdpte_idx == target_va.pdpte_idx &&
						curr_closest_entry->remapped_va.pde_idx == target_va.pde_idx)
						continue;


					curr_closest_entry = curr_entry;
					continue;
				}


				curr_closest_entry = curr_entry;
				goto cleanup;
			}

		cleanup:

			if (curr_closest_entry == &dummy) {
				return false;
			}
			else {
				remapping_entry = curr_closest_entry;
			}

			return true;
		}

		inline bool add_remapping_entry(remapped_entry_t new_entry) {

			for (uint32_t i = 0; i < MAX_REMAPPINGS; i++) {
				remapped_entry_t* curr_entry = &physmem.remapping_tables.remapping_list[i];


				if (curr_entry->used)
					continue;

				memcpy(curr_entry, &new_entry, sizeof(remapped_entry_t));
				curr_entry->used = true;

				return true;
			}

			return false;
		}

		inline bool get_max_remapping_level(remapped_entry_t* remapping_entry, uint64_t target_address, usable_until_t& usable_level) {
			va_64_t target_va;
			target_va.flags = target_address;

			if (!remapping_entry || !target_address) {
				usable_level = non_valid;
				return false;
			}


			if (remapping_entry->remapped_va.pml4e_idx != target_va.pml4e_idx) {
				usable_level = non_valid;
				return false;
			}


			if (remapping_entry->remapped_va.pdpte_idx != target_va.pdpte_idx) {
				usable_level = pdpt_table_valid;
				return true;
			}

			if (remapping_entry->pdpt_table.large_page) {
				usable_level = pdpt_table_valid;
				return true;
			}


			if (remapping_entry->remapped_va.pde_idx != target_va.pde_idx) {
				usable_level = pde_table_valid;
				return true;
			}

			if (remapping_entry->pd_table.large_page) {
				usable_level = pde_table_valid;
				return true;
			}

			usable_level = pte_table_valid;
			return true;
		}


		inline bool ensure_memory_mapping_without_previous_mapping(void* mem, uint64_t mem_cr3_u64, uint64_t* ensured_size) {
			if (!ensured_size || !mem || !mem_cr3_u64)
				return false;

			va_64_t mem_va = { 0 };
			cr3 mem_cr3 = { 0 };

			mem_va.flags = (uint64_t)mem;
			mem_cr3.flags = mem_cr3_u64;
			bool status = true;


			pml4e_64* mapped_pml4_table = 0;
			pdpte_64* mapped_pdpt_table = 0;
			pde_64* mapped_pde_table = 0;
			pte_64* mapped_pte_table = 0;


			pml4e_64* my_pml4_table = 0;
			pdpte_64* my_pdpt_table = 0;
			pde_64* my_pde_table = 0;
			pte_64* my_pte_table = 0;


			uint64_t pdpt_phys = 0;
			uint64_t pd_phys = 0;
			uint64_t pt_phys = 0;


			remapped_entry_t new_entry = { 0 };

			my_pml4_table = physmem.page_tables->pml4_table;

			mapped_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (mem_cr3.address_of_page_directory << 12));
			mapped_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12));

			if (mapped_pdpt_table[mem_va.pdpte_idx].large_page) {
				my_pdpt_table = pt_manager::get_free_pdpt_table(&physmem.remapping_tables);
				if (!my_pdpt_table) {
					status = false;
					goto cleanup;
				}

				pdpte_1gb_64* my_1gb_pdpt_table = (pdpte_1gb_64*)my_pdpt_table;

				if (runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_1gb_pdpt_table, pdpt_phys) != true)
					goto cleanup;

				memcpy(my_1gb_pdpt_table, mapped_pdpt_table, sizeof(pdpte_1gb_64) * 512);
				memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

				my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;


				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = true;
				new_entry.pdpt_table.table = my_pdpt_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x40000000 - mem_va.offset_1gb;

				goto cleanup;
			}

			mapped_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));

			if (mapped_pde_table[mem_va.pde_idx].large_page) {
				my_pdpt_table = pt_manager::get_free_pdpt_table(&physmem.remapping_tables);
				if (!my_pdpt_table) {
					status = false;
					goto cleanup;
				}

				my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
				if (!my_pde_table) {
					status = false;
					goto cleanup;
				}

				pde_2mb_64* my_2mb_pd_table = (pde_2mb_64*)my_pde_table;

				if (runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pdpt_table, pdpt_phys) != true)
					goto cleanup;

				if (runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys) != true)
					goto cleanup;


				memcpy(my_2mb_pd_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
				memcpy(my_pdpt_table, mapped_pdpt_table, sizeof(pdpte_64) * 512);
				memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

				my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;
				my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;


				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = my_pdpt_table;

				new_entry.pd_table.large_page = true;
				new_entry.pd_table.table = my_pde_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x200000 - mem_va.offset_2mb;

				goto cleanup;
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_table[mem_va.pde_idx].page_frame_number << 12));

			my_pdpt_table = pt_manager::get_free_pdpt_table(&physmem.remapping_tables);
			if (!my_pdpt_table) {
				status = false;
				goto cleanup;
			}

			my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
			if (!my_pde_table) {
				status = false;
				goto cleanup;
			}

			my_pte_table = pt_manager::get_free_pt_table(&physmem.remapping_tables);
			if (!my_pte_table) {
				status = false;
				goto cleanup;
			}

			status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pdpt_table, pdpt_phys);
			if (status != true)
				goto cleanup;

			status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys);
			if (status != true)
				goto cleanup;

			status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pte_table, pt_phys);
			if (status != true)
				goto cleanup;

			memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
			memcpy(my_pde_table, mapped_pde_table, sizeof(pde_64) * 512);
			memcpy(my_pdpt_table, mapped_pdpt_table, sizeof(pdpte_64) * 512);
			memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

			my_pde_table[mem_va.pde_idx].present = 1;
			my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;

			my_pdpt_table[mem_va.pdpte_idx].present = 1;
			my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;

			my_pml4_table[mem_va.pml4e_idx].present = 1;
			my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;


			new_entry.used = true;
			new_entry.remapped_va = mem_va;

			new_entry.pdpt_table.large_page = false;
			new_entry.pdpt_table.table = my_pdpt_table;

			new_entry.pd_table.large_page = false;
			new_entry.pd_table.table = my_pde_table;

			new_entry.pt_table = my_pte_table;

			status = add_remapping_entry(new_entry);

			*ensured_size = 0x1000 - mem_va.offset_4kb;

		cleanup:

			__invlpg(mem);

			return status;
		}

		inline bool ensure_memory_mapping_with_previous_mapping(void* mem, uint64_t mem_cr3_u64, remapped_entry_t* remapping_entry, uint64_t* ensured_size) {
			if (!ensured_size || !mem || !mem_cr3_u64 || !remapping_entry)
				return false;

			bool status = true;
			va_64_t mem_va = { 0 };
			cr3 mem_cr3 = { 0 };

			mem_va.flags = (uint64_t)mem;
			mem_cr3.flags = mem_cr3_u64;


			pml4e_64* mapped_pml4_table = 0;
			pdpte_64* mapped_pdpt_table = 0;
			pde_64* mapped_pde_table = 0;
			pte_64* mapped_pte_table = 0;


			pdpte_64* my_pdpt_table = 0;
			pde_64* my_pde_table = 0;
			pte_64* my_pte_table = 0;

			usable_until_t max_usable = non_valid;
			status = get_max_remapping_level(remapping_entry, (uint64_t)mem, max_usable);
			if (status != true)
				goto cleanup;

			mapped_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (mem_cr3.address_of_page_directory << 12));
			mapped_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12));

			if (mapped_pdpt_table[mem_va.pdpte_idx].large_page) {
				switch (max_usable) {
				case pdpt_table_valid:
				case pde_table_valid:
				case pte_table_valid: {
					my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
					if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
						status = false;
						goto cleanup;
					}


					memcpy(&my_pdpt_table[mem_va.pdpte_idx], &mapped_pdpt_table[mem_va.pdpte_idx], sizeof(pdpte_1gb_64));

					remapped_entry_t new_entry;
					new_entry.used = true;
					new_entry.remapped_va = mem_va;

					new_entry.pdpt_table.large_page = true;
					new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

					status = add_remapping_entry(new_entry);

					*ensured_size = 0x40000000 - mem_va.offset_1gb;

					goto cleanup;
				}
				}
			}

			mapped_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));

			if (mapped_pde_table[mem_va.pde_idx].large_page) {
				switch (max_usable) {
				case pdpt_table_valid: {
					my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
					if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
						status = false;
						goto cleanup;
					}

					my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
					if (!my_pde_table) {
						status = false;
						goto cleanup;
					}


					uint64_t pd_phys;
					status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys);
					if (status != true)
						goto cleanup;


					memcpy(my_pde_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
					my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;

					remapped_entry_t new_entry;
					new_entry.used = true;
					new_entry.remapped_va = mem_va;

					new_entry.pdpt_table.large_page = false;
					new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

					new_entry.pd_table.large_page = true;
					new_entry.pd_table.table = my_pde_table;

					status = add_remapping_entry(new_entry);

					*ensured_size = 0x200000 - mem_va.offset_2mb;

					goto cleanup;
				}
				case pde_table_valid:
				case pte_table_valid: {
					pde_2mb_64* my_2mb_pde_table = (pde_2mb_64*)remapping_entry->pd_table.table;
					if (mem_va.pde_idx == remapping_entry->remapped_va.pde_idx) {
						status = false;
						goto cleanup;
					}


					memcpy(&my_2mb_pde_table[mem_va.pde_idx], &mapped_pde_table[mem_va.pde_idx], sizeof(pde_2mb_64));

					remapped_entry_t new_entry;
					new_entry.used = true;
					new_entry.remapped_va = mem_va;

					new_entry.pdpt_table.large_page = false;
					new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

					new_entry.pd_table.large_page = true;
					new_entry.pd_table.table = remapping_entry->pd_table.table;

					status = add_remapping_entry(new_entry);

					*ensured_size = 0x200000 - mem_va.offset_2mb;

					goto cleanup;
				}
				}
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_table[mem_va.pde_idx].page_frame_number << 12));

			switch (max_usable) {
			case pdpt_table_valid: {
				my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
				if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
					status = false;
					goto cleanup;
				}
				my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
				if (!my_pde_table) {
					status = false;
					goto cleanup;
				}
				my_pte_table = pt_manager::get_free_pt_table(&physmem.remapping_tables);
				if (!my_pte_table) {
					status = false;
					goto cleanup;
				}

				uint64_t pd_phys = 0;
				status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys);
				if (status != true)
					goto cleanup;

				uint64_t pt_phys = 0;
				status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pte_table, pt_phys);
				if (status != true)
					goto cleanup;


				memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
				memcpy(my_pde_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
				my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;
				my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;


				remapped_entry_t new_entry;
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = false;
				new_entry.pd_table.table = my_pde_table;

				new_entry.pt_table = my_pte_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x1000 - mem_va.offset_4kb;

				goto cleanup;
			}
			case pde_table_valid: {
				my_pde_table = (pde_64*)remapping_entry->pd_table.table;
				if (mem_va.pde_idx == remapping_entry->remapped_va.pde_idx) {
					status = false;
					goto cleanup;
				}

				my_pte_table = pt_manager::get_free_pt_table(&physmem.remapping_tables);
				if (!my_pte_table) {
					status = false;
					goto cleanup;
				}

				uint64_t pt_phys = 0;
				status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pte_table, pt_phys);
				if (status != true)
					goto cleanup;


				memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
				my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;


				remapped_entry_t new_entry;
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = false;
				new_entry.pd_table.table = remapping_entry->pd_table.table;

				new_entry.pt_table = my_pte_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x1000 - mem_va.offset_4kb;

				goto cleanup;
			}
			case pte_table_valid: {
				my_pte_table = (pte_64*)remapping_entry->pt_table;
				if (mem_va.pte_idx == remapping_entry->remapped_va.pte_idx) {
					status = false;
					goto cleanup;
				}


				memcpy(&my_pte_table[mem_va.pte_idx], &mapped_pte_table[mem_va.pte_idx], sizeof(pte_64));

				remapped_entry_t new_entry;
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = false;
				new_entry.pd_table.table = remapping_entry->pd_table.table;

				new_entry.pt_table = remapping_entry->pt_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x1000 - mem_va.offset_4kb;

				goto cleanup;
			}
			}

		cleanup:

			__invlpg(mem);
			return status;
		}

		inline bool ensure_memory_mapping(void* mem, uint64_t mem_cr3_u64, uint64_t* ensured_size = 0) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_ensure_mapping_enter va=0x%llx cr3=0x%llx ensured_out=%u mapped_base=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(mem),
				mem_cr3_u64,
				ensured_size ? 1u : 0u,
				physmem.mapped_physical_mem_base,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			if (!mem || !mem_cr3_u64) {
				HVD_LOG_IMMEDIATE("physmem_ensure_mapping_exit ok=0 reason=invalid_args va=0x%llx cr3=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(mem),
					mem_cr3_u64,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			bool status = true;
			remapped_entry_t* remapping_entry = 0;
			uint64_t dummy_size = 0;

			status = get_remapping_entry(mem, remapping_entry);
			const bool had_previous = status == true;

			if (!ensured_size)
				ensured_size = &dummy_size;

			if (had_previous) {
				status = ensure_memory_mapping_with_previous_mapping(mem, mem_cr3_u64, remapping_entry, ensured_size);
			}
			else {
				status = ensure_memory_mapping_without_previous_mapping(mem, mem_cr3_u64, ensured_size);
			}

			HVD_LOG_IMMEDIATE("physmem_ensure_mapping_exit ok=%u previous=%u va=0x%llx cr3=0x%llx ensured_size=0x%llx remap=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				status ? 1u : 0u,
				had_previous ? 1u : 0u,
				ptr_u64(mem),
				mem_cr3_u64,
				ensured_size ? *ensured_size : 0,
				ptr_u64(remapping_entry),
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return status;
		}


		inline bool ensure_memory_mapping_for_range(void* target_address, uint64_t size, uint64_t mem_cr3_u64) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_ensure_range_enter base=0x%llx size=0x%llx cr3=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(target_address),
				size,
				mem_cr3_u64,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_ensure_range_exit ok=0 reason=precondition base=0x%llx size=0x%llx current_cr3=0x%llx constructed_cr3=0x%llx if=%u elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(target_address),
					size,
					__readcr3(),
					physmem.constructed_cr3.flags,
					flags.interrupt_enable_flag ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			bool status = true;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {
				void* current_target = (void*)((uint64_t)target_address + copied_bytes);
				uint64_t ensured_size = 0;

				status = ensure_memory_mapping(current_target, mem_cr3_u64, &ensured_size);
				if (status != true) {
					HVD_LOG_IMMEDIATE("physmem_ensure_range_exit ok=0 reason=ensure_failed base=0x%llx current=0x%llx copied=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
						ptr_u64(target_address),
						ptr_u64(current_target),
						copied_bytes,
						size,
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					return status;
				}

				copied_bytes += ensured_size;
				HVD_LOG_IMMEDIATE("physmem_ensure_range_chunk current=0x%llx ensured=0x%llx copied=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(current_target),
					ensured_size,
					copied_bytes,
					size,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
			}

			HVD_LOG_IMMEDIATE("physmem_ensure_range_exit ok=1 base=0x%llx size=0x%llx copied=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(target_address),
				size,
				copied_bytes,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return status;
		}

		inline bool overwrite_virtual_address_mapping(void* target_address, void* new_memory, uint64_t target_address_cr3_u64, uint64_t new_mem_cr3_u64) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_enter target=0x%llx new=0x%llx target_cr3=0x%llx new_cr3=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(target_address),
				ptr_u64(new_memory),
				target_address_cr3_u64,
				new_mem_cr3_u64,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_exit ok=0 reason=precondition target=0x%llx current_cr3=0x%llx constructed_cr3=0x%llx if=%u elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(target_address),
					__readcr3(),
					physmem.constructed_cr3.flags,
					flags.interrupt_enable_flag ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			if (PAGE_ALIGN(target_address) != target_address ||
				PAGE_ALIGN(new_memory) != new_memory) {
				HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_exit ok=0 reason=unaligned target=0x%llx new=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(target_address),
					ptr_u64(new_memory),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			bool status = true;

			cr3 new_mem_cr3 = { 0 };

			va_64_t target_va = { 0 };
			va_64_t new_mem_va = { 0 };

			target_va.flags = (uint64_t)target_address;
			new_mem_va.flags = (uint64_t)new_memory;

			new_mem_cr3.flags = (uint64_t)new_mem_cr3_u64;

			pml4e_64* my_pml4_table = 0;
			pdpte_64* my_pdpt_table = 0;
			pde_64* my_pde_table = 0;
			pte_64* my_pte_table = 0;

			pml4e_64* new_mem_pml4_table = 0;
			pdpte_64* new_mem_pdpt_table = 0;
			pde_64* new_mem_pde_table = 0;
			pte_64* new_mem_pte_table = 0;


			status = ensure_memory_mapping(target_address, target_address_cr3_u64);
			if (status != true) {
				HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_exit ok=0 reason=ensure_target_failed target=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(target_address),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				goto cleanup;
			}


			my_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (physmem.constructed_cr3.address_of_page_directory << 12));
			new_mem_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (new_mem_cr3.address_of_page_directory << 12));

			my_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (my_pml4_table[target_va.pml4e_idx].page_frame_number << 12));
			new_mem_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (new_mem_pml4_table[new_mem_va.pml4e_idx].page_frame_number << 12));

			if (my_pdpt_table[target_va.pdpte_idx].large_page || new_mem_pdpt_table[new_mem_va.pdpte_idx].large_page) {
				if (!my_pdpt_table[target_va.pdpte_idx].large_page || !new_mem_pdpt_table[new_mem_va.pdpte_idx].large_page) {
					status = false;
					HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_level level=1gb ok=0 target_flags=0x%llx new_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
						my_pdpt_table[target_va.pdpte_idx].flags,
						new_mem_pdpt_table[new_mem_va.pdpte_idx].flags,
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					goto cleanup;
				}

				memcpy(&my_pdpt_table[target_va.pdpte_idx], &new_mem_pdpt_table[new_mem_va.pdpte_idx], sizeof(pdpte_1gb_64));

				HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_level level=1gb ok=1 target_flags=0x%llx new_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					my_pdpt_table[target_va.pdpte_idx].flags,
					new_mem_pdpt_table[new_mem_va.pdpte_idx].flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				goto cleanup;
			}

			my_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (my_pdpt_table[target_va.pdpte_idx].page_frame_number << 12));
			new_mem_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (new_mem_pdpt_table[new_mem_va.pdpte_idx].page_frame_number << 12));

			if (my_pde_table[target_va.pde_idx].large_page || new_mem_pde_table[new_mem_va.pde_idx].large_page) {
				if (!my_pde_table[target_va.pde_idx].large_page || !new_mem_pde_table[new_mem_va.pde_idx].large_page) {
					status = false;
					HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_level level=2mb ok=0 target_flags=0x%llx new_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
						my_pde_table[target_va.pde_idx].flags,
						new_mem_pde_table[new_mem_va.pde_idx].flags,
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					goto cleanup;
				}

				memcpy(&my_pde_table[target_va.pde_idx], &new_mem_pde_table[new_mem_va.pde_idx], sizeof(pde_2mb_64));

				HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_level level=2mb ok=1 target_flags=0x%llx new_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					my_pde_table[target_va.pde_idx].flags,
					new_mem_pde_table[new_mem_va.pde_idx].flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				goto cleanup;
			}


			my_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (my_pde_table[target_va.pde_idx].page_frame_number << 12));
			new_mem_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (new_mem_pde_table[new_mem_va.pde_idx].page_frame_number << 12));

			memcpy(&my_pte_table[target_va.pte_idx], &new_mem_pte_table[new_mem_va.pte_idx], sizeof(pte_64));
			HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_level level=4kb ok=1 target_flags=0x%llx new_flags=0x%llx present=%u write=%u supervisor=%u elapsed_us=%llu cpu=%lu irql=%lu",
				my_pte_table[target_va.pte_idx].flags,
				new_mem_pte_table[new_mem_va.pte_idx].flags,
				my_pte_table[target_va.pte_idx].present ? 1u : 0u,
				my_pte_table[target_va.pte_idx].write ? 1u : 0u,
				my_pte_table[target_va.pte_idx].supervisor ? 1u : 0u,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());

		cleanup:
			__invlpg(target_address);

			HVD_LOG_IMMEDIATE("physmem_overwrite_mapping_exit ok=%u target=0x%llx new=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				status ? 1u : 0u,
				ptr_u64(target_address),
				ptr_u64(new_memory),
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return status;
		}
	};

	namespace paging_manipulation {
		inline bool win_destroy_memory_page_mapping(void* memory, uint64_t& stored_flags) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_destroy_mapping_enter memory=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(memory),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_destroy_mapping_exit ok=0 reason=precondition memory=0x%llx current_cr3=0x%llx constructed_cr3=0x%llx if=%u elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					__readcr3(),
					physmem.constructed_cr3.flags,
					flags.interrupt_enable_flag ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}


			va_64_t mem_va;
			mem_va.flags = (uint64_t)memory;

			pml4e_64* pml4_table = 0;
			pdpte_64* pdpt_table = 0;
			pde_64* pde_table = 0;
			pte_64* pte_table = 0;

			pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + __readcr3());
			if (!pml4_table) {
				HVD_LOG_IMMEDIATE("physmem_destroy_mapping_exit ok=0 reason=no_pml4 memory=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (pml4_table[mem_va.pml4e_idx].page_frame_number << 12));
			if (!pdpt_table) {
				HVD_LOG_IMMEDIATE("physmem_destroy_mapping_exit ok=0 reason=no_pdpt memory=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));
			if (!pde_table) {
				HVD_LOG_IMMEDIATE("physmem_destroy_mapping_exit ok=0 reason=no_pde memory=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (pde_table[mem_va.pde_idx].page_frame_number << 12));
			if (!pte_table) {
				HVD_LOG_IMMEDIATE("physmem_destroy_mapping_exit ok=0 reason=no_pte memory=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			stored_flags = pte_table[mem_va.pte_idx].flags;
			pte_table[mem_va.pte_idx].flags = 0;

			HVD_LOG_IMMEDIATE("physmem_destroy_mapping_exit ok=1 memory=0x%llx stored_flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(memory),
				stored_flags,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());

			return true;
		}

		inline bool win_restore_memory_page_mapping(void* memory, uint64_t stored_flags) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_restore_mapping_enter memory=0x%llx stored_flags=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(memory),
				stored_flags,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags) {
				HVD_LOG_IMMEDIATE("physmem_restore_mapping_exit ok=0 reason=precondition memory=0x%llx current_cr3=0x%llx constructed_cr3=0x%llx if=%u elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					__readcr3(),
					physmem.constructed_cr3.flags,
					flags.interrupt_enable_flag ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;

			va_64_t mem_va;
			mem_va.flags = (uint64_t)memory;

			pml4e_64* pml4_table = 0;
			pdpte_64* pdpt_table = 0;
			pde_64* pde_table = 0;
			pte_64* pte_table = 0;

			pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + __readcr3());
			if (!pml4_table) {
				HVD_LOG_IMMEDIATE("physmem_restore_mapping_exit ok=0 reason=no_pml4 memory=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (pml4_table[mem_va.pml4e_idx].page_frame_number << 12));
			if (!pdpt_table) {
				HVD_LOG_IMMEDIATE("physmem_restore_mapping_exit ok=0 reason=no_pdpt memory=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));
			if (!pde_table) {
				HVD_LOG_IMMEDIATE("physmem_restore_mapping_exit ok=0 reason=no_pde memory=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (pde_table[mem_va.pde_idx].page_frame_number << 12));
			if (!pte_table) {
				HVD_LOG_IMMEDIATE("physmem_restore_mapping_exit ok=0 reason=no_pte memory=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			pte_table[mem_va.pte_idx].flags = stored_flags;

			HVD_LOG_IMMEDIATE("physmem_restore_mapping_exit ok=1 memory=0x%llx restored_flags=0x%llx present=%u write=%u supervisor=%u elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(memory),
				pte_table[mem_va.pte_idx].flags,
				pte_table[mem_va.pte_idx].present ? 1u : 0u,
				pte_table[mem_va.pte_idx].write ? 1u : 0u,
				pte_table[mem_va.pte_idx].supervisor ? 1u : 0u,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return true;
		}

		inline bool set_single_page_supervisor(void* memory, cr3 mem_cr3, bool supervisor, uint64_t* set_size) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_set_supervisor_page_enter memory=0x%llx cr3=0x%llx supervisor=%u cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(memory),
				mem_cr3.flags,
				supervisor ? 1u : 0u,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());
			va_64_t mem_va;
			mem_va.flags = (uint64_t)memory;

			pml4e_64* pml4_table = 0;
			pdpte_64* pdpt_table = 0;
			pde_64* pde_table = 0;
			pte_64* pte_table = 0;

			pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (mem_cr3.address_of_page_directory << 12));
			if (!pml4_table[mem_va.pml4e_idx].present) {
				HVD_LOG_IMMEDIATE("physmem_set_supervisor_page_exit ok=0 reason=pml4_not_present memory=0x%llx flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					pml4_table[mem_va.pml4e_idx].flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return pml4_table[mem_va.pml4e_idx].flags;
			}

			pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (pml4_table[mem_va.pml4e_idx].page_frame_number << 12));
			if (!pdpt_table[mem_va.pdpte_idx].present) {
				HVD_LOG_IMMEDIATE("physmem_set_supervisor_page_exit ok=0 reason=pdpt_not_present memory=0x%llx flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					pdpt_table[mem_va.pdpte_idx].flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			if (pdpt_table[mem_va.pdpte_idx].large_page) {
				uint64_t old_flags = pdpt_table[mem_va.pdpte_idx].flags;
				pdpt_table[mem_va.pdpte_idx].supervisor = supervisor;
				pml4_table[mem_va.pml4e_idx].supervisor = supervisor;
				__invlpg(memory);
				if(set_size)
					*set_size = 0x40000000 - mem_va.offset_1gb;

				HVD_LOG_IMMEDIATE("physmem_set_supervisor_page_exit ok=1 level=1gb memory=0x%llx old_flags=0x%llx new_flags=0x%llx set_size=0x%llx supervisor=%u elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					old_flags,
					pdpt_table[mem_va.pdpte_idx].flags,
					set_size ? *set_size : 0,
					supervisor ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return true;
			}

			pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));
			if (!pde_table[mem_va.pde_idx].present) {
				HVD_LOG_IMMEDIATE("physmem_set_supervisor_page_exit ok=0 reason=pde_not_present memory=0x%llx flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					pde_table[mem_va.pde_idx].flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			if (pde_table[mem_va.pde_idx].large_page) {
				uint64_t old_flags = pde_table[mem_va.pde_idx].flags;
				pde_table[mem_va.pde_idx].supervisor = supervisor;
				pdpt_table[mem_va.pdpte_idx].supervisor = supervisor;
				pml4_table[mem_va.pml4e_idx].supervisor = supervisor;
				__invlpg(memory);
				if(set_size)
					*set_size = 0x200000 - mem_va.offset_2mb;

				HVD_LOG_IMMEDIATE("physmem_set_supervisor_page_exit ok=1 level=2mb memory=0x%llx old_flags=0x%llx new_flags=0x%llx set_size=0x%llx supervisor=%u elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					old_flags,
					pde_table[mem_va.pde_idx].flags,
					set_size ? *set_size : 0,
					supervisor ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return true;
			}

			pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (pde_table[mem_va.pde_idx].page_frame_number << 12));
			if (!pte_table[mem_va.pte_idx].present) {
				HVD_LOG_IMMEDIATE("physmem_set_supervisor_page_exit ok=0 reason=pte_not_present memory=0x%llx flags=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(memory),
					pte_table[mem_va.pte_idx].flags,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			uint64_t old_flags = pte_table[mem_va.pte_idx].flags;
			pte_table[mem_va.pte_idx].supervisor = supervisor;
			pde_table[mem_va.pde_idx].supervisor = supervisor;
			pdpt_table[mem_va.pdpte_idx].supervisor = supervisor;
			pml4_table[mem_va.pml4e_idx].supervisor = supervisor;

			if(set_size)
				*set_size = 0x1000 - mem_va.offset_4kb;

			__invlpg(memory);

			HVD_LOG_IMMEDIATE("physmem_set_supervisor_page_exit ok=1 level=4kb memory=0x%llx old_flags=0x%llx new_flags=0x%llx set_size=0x%llx present=%u write=%u supervisor=%u elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(memory),
				old_flags,
				pte_table[mem_va.pte_idx].flags,
				set_size ? *set_size : 0,
				pte_table[mem_va.pte_idx].present ? 1u : 0u,
				pte_table[mem_va.pte_idx].write ? 1u : 0u,
				pte_table[mem_va.pte_idx].supervisor ? 1u : 0u,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return true;
		}

		inline bool win_set_memory_range_supervisor(void* memory, uint64_t size, uint64_t mem_cr3, bool supervisor) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_set_supervisor_range_enter memory=0x%llx size=0x%llx cr3=0x%llx supervisor=%u cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(memory),
				size,
				mem_cr3,
				supervisor ? 1u : 0u,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());

			cr3 cr3_mem_cr3;
			cr3_mem_cr3.flags = mem_cr3;

			bool status = true;
			uint64_t set_bytes = 0;

			while (set_bytes < size) {
				void* current_target = (void*)((uint64_t)memory + set_bytes);
				uint64_t remaining_bytes = 0;

				status = set_single_page_supervisor(current_target, cr3_mem_cr3, supervisor, &remaining_bytes);
				if (status != true) {
					HVD_LOG_IMMEDIATE("physmem_set_supervisor_range_exit ok=0 memory=0x%llx current=0x%llx set_bytes=0x%llx size=0x%llx supervisor=%u elapsed_us=%llu cpu=%lu irql=%lu",
						ptr_u64(memory),
						ptr_u64(current_target),
						set_bytes,
						size,
						supervisor ? 1u : 0u,
						trace_elapsed_us(start, freq),
						KeGetCurrentProcessorNumber(),
						(ULONG)KeGetCurrentIrql());
					return status;
				}

				set_bytes += remaining_bytes;
				HVD_LOG_IMMEDIATE("physmem_set_supervisor_range_chunk current=0x%llx remaining=0x%llx set_bytes=0x%llx size=0x%llx supervisor=%u elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(current_target),
					remaining_bytes,
					set_bytes,
					size,
					supervisor ? 1u : 0u,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
			}

			HVD_LOG_IMMEDIATE("physmem_set_supervisor_range_exit ok=1 memory=0x%llx size=0x%llx set_bytes=0x%llx supervisor=%u elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(memory),
				size,
				set_bytes,
				supervisor ? 1u : 0u,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return status;
		}

		inline bool is_memory_page_mapped(void* memory) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;

			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;

			va_64_t mem_va;
			mem_va.flags = (uint64_t)memory;

			pml4e_64* pml4_table = 0;
			pdpte_64* pdpt_table = 0;
			pde_64* pde_table = 0;
			pte_64* pte_table = 0;

			pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + __readcr3());
			if (!pml4_table)
				return false;

			pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (pml4_table[mem_va.pml4e_idx].page_frame_number << 12));
			if (!pdpt_table) {
				return false;
			}

			pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));
			if (!pde_table) {
				return false;
			}

			pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (pde_table[mem_va.pde_idx].page_frame_number << 12));
			if (!pte_table)
				return false;

			return pte_table[mem_va.pte_idx].present;
		}

		inline bool prepare_driver_for_supervisor_access(void* driver_base, uint64_t driver_size, uint64_t mem_cr3) {
			LARGE_INTEGER freq{};
			LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
			HVD_LOG_IMMEDIATE("physmem_prepare_supervisor_enter driver_base=0x%llx driver_size=0x%llx cr3=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
				ptr_u64(driver_base),
				driver_size,
				mem_cr3,
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql(),
				start.QuadPart,
				__rdtsc());


			if (!physmem::remapping::ensure_memory_mapping_for_range((void*)driver_base, driver_size, mem_cr3)) {
				HVD_LOG_IMMEDIATE("physmem_prepare_supervisor_exit ok=0 step=driver_mapping driver_base=0x%llx driver_size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(driver_base),
					driver_size,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			if (!physmem::paging_manipulation::win_set_memory_range_supervisor((void*)driver_base, driver_size, mem_cr3, 1)) {
				HVD_LOG_IMMEDIATE("physmem_prepare_supervisor_exit ok=0 step=driver_supervisor driver_base=0x%llx driver_size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(driver_base),
					driver_size,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}


			KPCR* kpcr = (KPCR*)__readmsr(IA32_GS_BASE);
			void* curr_thread = *(void**)((uint64_t)kpcr->CurrentPrcb + 0x8);
			uint64_t stack_base = *(uint64_t*)((uint64_t)curr_thread + 0x38);
			uint64_t stack_limit = *(uint64_t*)((uint64_t)curr_thread + 0x30);
			uint64_t stack_size = stack_base - stack_limit;

			HVD_LOG_IMMEDIATE("physmem_prepare_supervisor_stack kpcr=0x%llx thread=0x%llx stack_base=0x%llx stack_limit=0x%llx stack_size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(kpcr),
				ptr_u64(curr_thread),
				stack_base,
				stack_limit,
				stack_size,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());

			if (!physmem::remapping::ensure_memory_mapping_for_range((void*)stack_limit, stack_size, mem_cr3)) {
				HVD_LOG_IMMEDIATE("physmem_prepare_supervisor_exit ok=0 step=stack_mapping stack_limit=0x%llx stack_size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					stack_limit,
					stack_size,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			if (!physmem::paging_manipulation::win_set_memory_range_supervisor((void*)stack_limit, stack_size, mem_cr3, 1)) {
				HVD_LOG_IMMEDIATE("physmem_prepare_supervisor_exit ok=0 step=stack_supervisor stack_limit=0x%llx stack_size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					stack_limit,
					stack_size,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}


			void* interrupt_records = (void*)safety_net::idt::get_interrupt_record(0);
			uint64_t interrupt_records_size = MAX_RECORDABLE_INTERRUPTS * sizeof(idt_regs_ecode_t);
			if (!physmem::remapping::ensure_memory_mapping_for_range(interrupt_records, interrupt_records_size, mem_cr3)) {
				HVD_LOG_IMMEDIATE("physmem_prepare_supervisor_exit ok=0 step=idt_records_mapping records=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(interrupt_records),
					interrupt_records_size,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			if (!physmem::paging_manipulation::win_set_memory_range_supervisor(interrupt_records, interrupt_records_size, mem_cr3, 1)) {
				HVD_LOG_IMMEDIATE("physmem_prepare_supervisor_exit ok=0 step=idt_records_supervisor records=0x%llx size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
					ptr_u64(interrupt_records),
					interrupt_records_size,
					trace_elapsed_us(start, freq),
					KeGetCurrentProcessorNumber(),
					(ULONG)KeGetCurrentIrql());
				return false;
			}

			safety_net::set_safety_net_kpcr(kpcr);

			HVD_LOG_IMMEDIATE("physmem_prepare_supervisor_exit ok=1 driver_base=0x%llx driver_size=0x%llx stack_limit=0x%llx stack_size=0x%llx records=0x%llx records_size=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
				ptr_u64(driver_base),
				driver_size,
				stack_limit,
				stack_size,
				ptr_u64(interrupt_records),
				interrupt_records_size,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return true;
		}
	};

	inline bool is_initialized(void) {
		return physmem.initialized;
	}

	inline bool init_physmem(void) {
		LARGE_INTEGER freq{};
		LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
		HVD_LOG_IMMEDIATE("physmem_init_enter initialized=%u page_tables=0x%llx constructed_cr3=0x%llx mapped_base=0x%llx cpu=%lu irql=%lu qpc=%lld tsc=%llu",
			physmem.initialized ? 1u : 0u,
			ptr_u64(physmem.page_tables),
			physmem.constructed_cr3.flags,
			physmem.mapped_physical_mem_base,
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql(),
			start.QuadPart,
			__rdtsc());
		if (!support::is_physmem_supported()) {
			HVD_LOG_IMMEDIATE("physmem_init_exit ok=0 step=support initialized=%u elapsed_us=%llu cpu=%lu irql=%lu",
				physmem.initialized ? 1u : 0u,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return false;
		}

		if (!page_table_initialization::initialize_page_tables()) {
			HVD_LOG_IMMEDIATE("physmem_init_exit ok=0 step=page_tables initialized=%u elapsed_us=%llu cpu=%lu irql=%lu",
				physmem.initialized ? 1u : 0u,
				trace_elapsed_us(start, freq),
				KeGetCurrentProcessorNumber(),
				(ULONG)KeGetCurrentIrql());
			return false;
		}

		physmem.initialized = true;

		HVD_LOG_IMMEDIATE("physmem_init_exit ok=1 initialized=%u page_tables=0x%llx constructed_cr3=0x%llx mapped_base=0x%llx elapsed_us=%llu cpu=%lu irql=%lu",
			physmem.initialized ? 1u : 0u,
			ptr_u64(physmem.page_tables),
			physmem.constructed_cr3.flags,
			physmem.mapped_physical_mem_base,
			trace_elapsed_us(start, freq),
			KeGetCurrentProcessorNumber(),
			(ULONG)KeGetCurrentIrql());
		return true;
	};
};
