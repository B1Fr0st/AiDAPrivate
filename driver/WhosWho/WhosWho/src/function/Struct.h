#pragma once
#include <ntifs.h>
#include <ntddmou.h>
#include <stddef.h>

typedef VOID
(*MouseClassServiceCallback)(
    PDEVICE_OBJECT DeviceObject,
    PMOUSE_INPUT_DATA InputDataStart,
    PMOUSE_INPUT_DATA InputDataEnd,
    PULONG InputDataConsumed
);

typedef struct _MOUSE_OBJECT
{
    PDEVICE_OBJECT mouse_device;
    MouseClassServiceCallback service_callback;
} MOUSE_OBJECT, * PMOUSE_OBJECT;

inline PDEVICE_OBJECT g_mouse_device = nullptr;
inline MouseClassServiceCallback g_mouse_callback = nullptr;
inline volatile LONG g_mouse_init_lock = 0;

extern "C" {
    extern POBJECT_TYPE* IoDriverObjectType;
}

#pragma pack(push, 8)

typedef struct _DB {
    UINT32 pid;
    UINT32 padding;
    UINT64 dtb;
} dtb_solve, * p_dtb_solve;
static_assert(sizeof(dtb_solve) == 16, "dtb_solve size must be 16 bytes");

typedef struct _PRW {
    UINT32 pid;
    UINT32 padding_1;
    UINT64 dtb;
    PVOID address;
    PVOID buffer;
    SIZE_T size;
    SIZE_T retSize;
    UINT8 shouldWrite;
    UINT8 padding_2[7];
} physical_rw, * p_physical_rw;
static_assert(sizeof(physical_rw) == 56, "physical_rw size must be 56 bytes");

typedef struct _BA {
    UINT32 pid;
    UINT32 padding;
    ULONGLONG* outAddress;
} base_address, * p_base_address;
static_assert(sizeof(base_address) == 16, "base_address size must be 16 bytes");

typedef struct _MM {
    INT32 inputX;
    INT32 inputY;
    UINT32 buttonFlags;
} mouse_move, * p_mouse_move;
static_assert(sizeof(mouse_move) == 12, "mouse_move size must be 12 bytes");

typedef struct _RC {
    UINT64 dtb;
    UINT64 target_function;
    UINT64 shellcode_address;
    UINT64 spoof_return;
    UINT64 arg1;
    UINT64 arg2;
    UINT64 arg3;
    UINT64 arg4;
    UINT64 result;
    UINT64 completed;
    UINT64 original_rip;
    UINT64 trampoline_addr;
} remote_call, * p_remote_call;
static_assert(sizeof(remote_call) == 96, "remote_call size must be 96 bytes");

typedef struct _CR {
    UINT64 dtb;
    UINT64 result_address;
    UINT64 result;
} call_result, * p_call_result;
static_assert(sizeof(call_result) == 24, "call_result size must be 24 bytes");

#pragma pack(push, 1)
typedef struct _SHELLCODE_CONTEXT {
    UINT64 target_function;
    UINT64 spoof_return;
    UINT64 arg1;
    UINT64 arg2;
    UINT64 arg3;
    UINT64 arg4;
    UINT64 result;
    UINT64 saved_rsp;
    UINT64 original_rip;
    UINT64 rbx_backup;
    volatile UINT64 completed;
    UINT64 trampoline_addr;
    UINT64 stack_backup[8];
    UINT64 xmm_backup[12];
    UINT64 reserved[8];
} SHELLCODE_CONTEXT, *PSHELLCODE_CONTEXT;
static_assert(sizeof(SHELLCODE_CONTEXT) == 320, "SHELLCODE_CONTEXT must be 320 bytes");
static_assert(offsetof(SHELLCODE_CONTEXT, result) == 0x30, "result must be at 0x30 in SHELLCODE_CONTEXT");
static_assert(offsetof(SHELLCODE_CONTEXT, original_rip) == 0x40, "original_rip must be at 0x40 in SHELLCODE_CONTEXT");
static_assert(offsetof(SHELLCODE_CONTEXT, completed) == 0x50, "completed must be at 0x50 in SHELLCODE_CONTEXT");
static_assert(offsetof(SHELLCODE_CONTEXT, trampoline_addr) == 0x58, "trampoline_addr must be at 0x58 in SHELLCODE_CONTEXT");
#pragma pack(pop)

#define SHELLCODE_MAGIC_COMPLETE 0xDEADC0DE12345678ULL

typedef struct _AM {
    UINT32 pid;
    UINT32 padding;
    UINT64 size;
    UINT64 allocated_address;
    UINT64 actual_size;
} alloc_mem, * p_alloc_mem;
static_assert(sizeof(alloc_mem) == 32, "alloc_mem size must be 32 bytes");

typedef struct _FM {
    UINT32 pid;
    UINT32 padding;
    UINT64 address;
} free_mem, * p_free_mem;
static_assert(sizeof(free_mem) == 16, "free_mem size must be 16 bytes");

typedef struct _HB {
    UINT32 magic;
    UINT32 session_key;
    UINT64 timestamp;
    UINT64 response;
} heartbeat, * p_heartbeat;
static_assert(sizeof(heartbeat) == 24, "heartbeat size must be 24 bytes");


typedef struct _TCTX {
    UINT32 pid;
    UINT32 tid;
    UINT32 should_set;
    UINT32 padding;
    UINT64 register_mask;

    UINT64 rax;
    UINT64 rbx;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 rbp;
    UINT64 rsp;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;
    UINT64 rip;
    UINT64 rflags;

    UINT64 cs;
    UINT64 ss;

    UINT64 dr0;
    UINT64 dr1;
    UINT64 dr2;
    UINT64 dr3;
    UINT64 dr6;
    UINT64 dr7;
} thread_ctx, * p_thread_ctx;
static_assert(sizeof(thread_ctx) == 232, "thread_ctx size must be 232 bytes");


#define MAX_ENUM_THREADS 256

typedef struct _THREAD_ENTRY {
    UINT32 tid;
    UINT32 state;
    UINT64 rip;
} THREAD_ENTRY;
static_assert(sizeof(THREAD_ENTRY) == 16, "THREAD_ENTRY size must be 16 bytes");

typedef struct _TENUM {
    UINT32 pid;
    UINT32 thread_count;
    THREAD_ENTRY entries[MAX_ENUM_THREADS];
} thread_enum, * p_thread_enum;
static_assert(sizeof(thread_enum) == 8 + sizeof(THREAD_ENTRY) * MAX_ENUM_THREADS, "thread_enum size check");


typedef struct _TSR {
    UINT32 tid;
    UINT32 should_resume;
    ULONG  previous_count;
    UINT32 padding;
} suspend_resume_thread, * p_suspend_resume_thread;
static_assert(sizeof(suspend_resume_thread) == 16, "suspend_resume_thread size must be 16 bytes");


typedef struct _QM {
    UINT32 pid;
    UINT32 padding;
    UINT64 address;

    UINT64 region_base;
    UINT64 region_size;
    UINT32 state;
    UINT32 protect;
    UINT32 type;
    UINT32 allocation_protect;
    UINT64 allocation_base;
} query_memory, * p_query_memory;
static_assert(sizeof(query_memory) == 56, "query_memory size must be 56 bytes");


typedef struct _PM {
    UINT32 pid;
    UINT32 new_protect;
    UINT64 address;
    UINT64 size;
    UINT32 old_protect;
    UINT32 padding;
} protect_memory, * p_protect_memory;
static_assert(sizeof(protect_memory) == 32, "protect_memory size must be 32 bytes");


#define MAX_ENUM_REGIONS 4096

typedef struct _REGION_ENTRY {
    UINT64 base;
    UINT64 size;
    UINT32 state;
    UINT32 protect;
    UINT32 type;
    UINT32 padding;
} REGION_ENTRY;
static_assert(sizeof(REGION_ENTRY) == 32, "REGION_ENTRY size must be 32 bytes");

typedef struct _EREGS {
    UINT32 pid;
    UINT32 include_all;
    UINT64 start_address;
    UINT64 max_address;
    UINT32 region_count;
    UINT32 padding;
    REGION_ENTRY entries[MAX_ENUM_REGIONS];
} enum_regions, * p_enum_regions;
static_assert(sizeof(enum_regions) == 32 + sizeof(REGION_ENTRY) * MAX_ENUM_REGIONS, "enum_regions size check");


typedef struct _RPEB {
    UINT32 pid;
    UINT32 padding;

    UINT64 peb_address;
    UINT64 image_base;
    UINT8  being_debugged;
    UINT8  pad1[3];
    UINT32 nt_global_flag;
    UINT64 ldr_address;
    UINT64 process_heap;
    UINT32 number_of_heaps;
    UINT32 max_heaps;
    UINT64 process_heaps;
} read_peb, * p_read_peb;
static_assert(sizeof(read_peb) == 64, "read_peb size must be 64 bytes");


typedef struct _SDF {
    UINT32 pid;
    UINT32 result_flags;
} spoof_debug, * p_spoof_debug;
static_assert(sizeof(spoof_debug) == 8, "spoof_debug size must be 8 bytes");


typedef struct _MEX {
    UINT64 dtb;
    UINT64 module_base;
    char   export_name[128];
    UINT64 resolved_address;
    UINT32 ordinal;
    UINT32 padding;
} module_export, * p_module_export;
static_assert(sizeof(module_export) == 160, "module_export size must be 160 bytes");


typedef struct _V2P {
    UINT64 dtb;
    UINT64 virtual_address;
    UINT64 physical_address;
} virt_to_phys, * p_virt_to_phys;
static_assert(sizeof(virt_to_phys) == 24, "virt_to_phys size must be 24 bytes");

#pragma pack(pop)

#define DTB_CACHE_SIZE 32

typedef struct _DTB_CACHE_ENTRY {
    UINT64 dtb;
    UINT64 last_access;
    UINT32 pid;
    UINT32 valid;
} DTB_CACHE_ENTRY, *PDTB_CACHE_ENTRY;
static_assert(sizeof(DTB_CACHE_ENTRY) == 24, "DTB_CACHE_ENTRY must be 24 bytes");

inline DTB_CACHE_ENTRY g_dtb_cache[DTB_CACHE_SIZE] = { 0 };
inline volatile LONG g_cache_lock = 0;

__forceinline void AcquireCacheLock() {
    while (_InterlockedCompareExchange(&g_cache_lock, 1, 0) != 0) {
        YieldProcessor();
    }
    KeMemoryBarrier();
}

__forceinline void ReleaseCacheLock() {
    KeMemoryBarrier();
    _InterlockedExchange(&g_cache_lock, 0);
}

__forceinline BOOLEAN LookupDTBCache(UINT32 pid, PUINT64 out_dtb) {
    if (!out_dtb || pid == 0) {
        return FALSE;
    }

    AcquireCacheLock();

    for (int i = 0; i < DTB_CACHE_SIZE; i++) {
        if (g_dtb_cache[i].valid && g_dtb_cache[i].pid == pid) {
            *out_dtb = g_dtb_cache[i].dtb;
            g_dtb_cache[i].last_access = __rdtsc();
            ReleaseCacheLock();
            return TRUE;
        }
    }

    ReleaseCacheLock();
    return FALSE;
}

__forceinline void InsertDTBCache(UINT32 pid, UINT64 dtb) {
    if (pid == 0 || dtb == 0) {
        return;
    }

    AcquireCacheLock();

    for (int i = 0; i < DTB_CACHE_SIZE; i++) {
        if (g_dtb_cache[i].valid && g_dtb_cache[i].pid == pid) {
            g_dtb_cache[i].dtb = dtb;
            g_dtb_cache[i].last_access = __rdtsc();
            ReleaseCacheLock();
            return;
        }
    }

    int target_idx = 0;
    UINT64 oldest_time = ~0ULL;

    for (int i = 0; i < DTB_CACHE_SIZE; i++) {
        if (!g_dtb_cache[i].valid) {
            target_idx = i;
            break;
        }
        if (g_dtb_cache[i].last_access < oldest_time) {
            oldest_time = g_dtb_cache[i].last_access;
            target_idx = i;
        }
    }

    g_dtb_cache[target_idx].pid = pid;
    g_dtb_cache[target_idx].dtb = dtb;
    g_dtb_cache[target_idx].last_access = __rdtsc();
    KeMemoryBarrier();
    g_dtb_cache[target_idx].valid = TRUE;

    ReleaseCacheLock();
}

__forceinline void InvalidateDTBCache(UINT32 pid) {
    AcquireCacheLock();

    for (int i = 0; i < DTB_CACHE_SIZE; i++) {
        if (g_dtb_cache[i].pid == pid) {
            g_dtb_cache[i].valid = FALSE;
            KeMemoryBarrier();
        }
    }

    ReleaseCacheLock();
}
