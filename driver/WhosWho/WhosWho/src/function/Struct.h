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
    UINT64 target_function;    // 0x00
    UINT64 spoof_return;       // 0x08
    UINT64 arg1;               // 0x10
    UINT64 arg2;               // 0x18
    UINT64 arg3;               // 0x20
    UINT64 arg4;               // 0x28
    UINT64 result;             // 0x30
    UINT64 saved_rsp;          // 0x38
    UINT64 original_rip;       // 0x40
    UINT64 rbx_backup;         // 0x48
    volatile UINT64 completed; // 0x50
    UINT64 trampoline_addr;    // 0x58
    UINT64 stack_backup[8];    // 0x60-0x9F
    UINT64 xmm_backup[12];     // 0xA0-0xFF - XMM0-XMM5 (16 bytes each)
    UINT64 reserved[8];        // 0x100-0x13F - extra space for alignment
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