#pragma once
#include "hv_structs.h"
#include "includes.h"
#include "func_defs.h"

typedef struct {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} cpuidsplit_t;

typedef struct {
    void* table;
    bool large_page;
} slot_t;

typedef struct {
    va_64_t remapped_va;
    slot_t pdpt_table;
    slot_t pd_table;
    void* pt_table;

    bool used;
} remapped_entry_t;

typedef enum {
    non_valid,
    pdpt_table_valid,
    pde_table_valid,
    pte_table_valid,
} usable_until_t;

#define REMAPPING_TABLE_COUNT 16
#define MAX_REMAPPINGS 64
#define PAGE_TABLE_ENTRY_COUNT 512

typedef struct {
    pdpte_64* pdpt_table[REMAPPING_TABLE_COUNT];
    pde_64*   pd_table[REMAPPING_TABLE_COUNT];
    pte_64*   pt_table[REMAPPING_TABLE_COUNT];

    bool is_pdpt_table_occupied[REMAPPING_TABLE_COUNT];
    bool is_pd_table_occupied[REMAPPING_TABLE_COUNT];
    bool is_pt_table_occupied[REMAPPING_TABLE_COUNT];

    remapped_entry_t remapping_list[MAX_REMAPPINGS];
} remapping_tables_t;

typedef struct {
    pml4e_64  pml4_table[PAGE_TABLE_ENTRY_COUNT];
    pdpte_64  pdpt_table[PAGE_TABLE_ENTRY_COUNT];
    pde_64    pd_2mb_table[PAGE_TABLE_ENTRY_COUNT][PAGE_TABLE_ENTRY_COUNT];
} page_tables_t;

typedef struct {
    page_tables_t*     page_tables;
    remapping_tables_t remapping_tables;
    cr3                kernel_cr3;
    cr3                constructed_cr3;
    uint64_t           mapped_physical_mem_base;
    bool               initialized;
} physmem_t;