#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include <Crypter.h>
#include <stddef.h>
#include <intrin.h>

#pragma intrinsic(_mm_mfence)

namespace call_guard {
    __forceinline BOOLEAN is_valid_user_range(UINT64 addr) {
        return (addr > 0x10000ULL && addr < 0x00007FFFFFFFFFFFULL);
    }
    
    __forceinline BOOLEAN is_valid_code_ptr(UINT64 addr) {
        if (!is_valid_user_range(addr)) return FALSE;
        return TRUE;
    }
    
    __forceinline BOOLEAN is_valid_dtb(UINT64 dtb) {
        if (dtb == 0) return FALSE;
        UINT64 clean_dtb = dtb & ~0xFFFULL;
        UINT64 pfn = (clean_dtb >> 12) & 0xFFFFFFFFFULL;
        return (pfn != 0);
    }
}

#pragma pack(push, 1)
typedef struct _CALL_CONTEXT {
    UINT64 target_func;      // 0x00
    UINT64 spoof_gadget;     // 0x08
    UINT64 param1;           // 0x10
    UINT64 param2;           // 0x18
    UINT64 param3;           // 0x20
    UINT64 param4;           // 0x28
    UINT64 ret_value;        // 0x30
    UINT64 saved_rsp;        // 0x38
    UINT64 original_rip;     // 0x40
    UINT64 rbx_backup;       // 0x48
    volatile UINT64 exec_done; // 0x50
    UINT64 trampoline_addr;  // 0x58
    UINT64 stack_backup[8];  // 0x60-0x9F
    UINT64 xmm_backup[12];   // 0xA0-0xFF
    UINT64 reserved[8];      // 0x100-0x13F
} CALL_CONTEXT, *PCALL_CONTEXT;
#pragma pack(pop)

static_assert(sizeof(CALL_CONTEXT) == 320, "CALL_CONTEXT must be 320 bytes");
static_assert(offsetof(CALL_CONTEXT, ret_value) == 0x30, "ret_value must be at offset 0x30");
static_assert(offsetof(CALL_CONTEXT, original_rip) == 0x40, "original_rip must be at offset 0x40");
static_assert(offsetof(CALL_CONTEXT, exec_done) == 0x50, "exec_done must be at offset 0x50");
static_assert(offsetof(CALL_CONTEXT, trampoline_addr) == 0x58, "trampoline_addr must be at offset 0x58");

namespace poly_engine {
    inline volatile ULONG g_poly_seed = 0xCAFEBABEu;
    
    __forceinline ULONG poly_rand() {
        ULONG x = g_poly_seed ^ (ULONG)(__rdtsc() & 0xFFFFFFFFu);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        g_poly_seed = x;
        return x;
    }
    
    __forceinline SIZE_T emit_junk(PUINT8 buf, SIZE_T max_junk) {
        SIZE_T count = (poly_rand() % (max_junk + 1));
        for (SIZE_T j = 0; j < count; j++) {
            ULONG r = poly_rand() % 8;
            switch (r) {
                case 0: buf[j] = 0x90; break;
                case 1: buf[j] = 0x66; if (j + 1 < count) buf[++j] = 0x90; break;
                case 2: buf[j] = 0x0F; if (j + 1 < count) { buf[++j] = 0x1F; if (j + 1 < count) buf[++j] = 0x00; } break;
                case 3: buf[j] = 0x87; buf[j] |= 0xC0; break;
                case 4: buf[j] = 0x48; if (j + 1 < count) buf[++j] = 0x87; if (j + 1 < count) buf[++j] = 0xC0; break;
                default: buf[j] = 0x90; break;
            }
        }
        return count;
    }
}

namespace shellcode_builder {
    
    __forceinline SIZE_T build_spoofed_call_v2(PUINT8 buf, UINT64 ctx_addr, UINT64 spoof_gadget, UINT64 epilogue_addr) {
        UNREFERENCED_PARAMETER(spoof_gadget);
        UNREFERENCED_PARAMETER(epilogue_addr);
        SIZE_T i = 0;
        
        i += poly_engine::emit_junk(&buf[i], 3);
        
        buf[i++] = 0x9C;
        
        ULONG push_order = poly_engine::poly_rand();
        if (push_order & 1) {
            buf[i++] = 0x50;
            buf[i++] = 0x51;
        } else {
            buf[i++] = 0x51;
            buf[i++] = 0x50;
            buf[i++] = 0x48; buf[i++] = 0x87; buf[i++] = 0xC1;
        }
        buf[i++] = 0x52;
        buf[i++] = 0x53;
        buf[i++] = 0x55;
        buf[i++] = 0x56;
        buf[i++] = 0x57;
        buf[i++] = 0x41; buf[i++] = 0x50;
        buf[i++] = 0x41; buf[i++] = 0x51;
        buf[i++] = 0x41; buf[i++] = 0x52;
        buf[i++] = 0x41; buf[i++] = 0x53;
        buf[i++] = 0x41; buf[i++] = 0x54;
        buf[i++] = 0x41; buf[i++] = 0x55;
        buf[i++] = 0x41; buf[i++] = 0x56;
        buf[i++] = 0x41; buf[i++] = 0x57;
        
        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC; buf[i++] = 0x80; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x04; buf[i++] = 0x24;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x4C; buf[i++] = 0x24; buf[i++] = 0x10;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x54; buf[i++] = 0x24; buf[i++] = 0x20;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x5C; buf[i++] = 0x24; buf[i++] = 0x30;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x64; buf[i++] = 0x24; buf[i++] = 0x40;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x6C; buf[i++] = 0x24; buf[i++] = 0x50;
        
        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x5E; buf[i++] = 0x48;
        
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x66; buf[i++] = 0x38;
        
        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0xE4; buf[i++] = 0xF0;
        
        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC;
        *(UINT32*)&buf[i] = 0x28;
        i += 4;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x10;
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x56; buf[i++] = 0x18;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x20;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x28;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x06;
        
        buf[i++] = 0xFF; buf[i++] = 0xD0;
        
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x46; buf[i++] = 0x30;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x5E; buf[i++] = 0x48;
        
        buf[i++] = 0x48; buf[i++] = 0xC7; buf[i++] = 0x46; buf[i++] = 0x50;
        buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
        
        buf[i++] = 0x0F; buf[i++] = 0xAE; buf[i++] = 0xF0;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x66; buf[i++] = 0x38;
        
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x6C; buf[i++] = 0x24; buf[i++] = 0x50;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x64; buf[i++] = 0x24; buf[i++] = 0x40;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x5C; buf[i++] = 0x24; buf[i++] = 0x30;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x54; buf[i++] = 0x24; buf[i++] = 0x20;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x4C; buf[i++] = 0x24; buf[i++] = 0x10;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x04; buf[i++] = 0x24;
        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xC4; buf[i++] = 0x80; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
        
        buf[i++] = 0x41; buf[i++] = 0x5F;
        buf[i++] = 0x41; buf[i++] = 0x5E;
        buf[i++] = 0x41; buf[i++] = 0x5D;
        buf[i++] = 0x41; buf[i++] = 0x5C;
        buf[i++] = 0x41; buf[i++] = 0x5B;
        buf[i++] = 0x41; buf[i++] = 0x5A;
        buf[i++] = 0x41; buf[i++] = 0x59;
        buf[i++] = 0x41; buf[i++] = 0x58;
        buf[i++] = 0x5F;
        buf[i++] = 0x5E;
        buf[i++] = 0x5D;
        buf[i++] = 0x5B;
        buf[i++] = 0x5A;
        buf[i++] = 0x59;
        buf[i++] = 0x58;
        
        buf[i++] = 0x9D;
        
        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x40;
        buf[i++] = 0xFF; buf[i++] = 0xE0;
        
        return i;
    }
    
    __forceinline SIZE_T build_jmp_rbx_spoofed(PUINT8 buf, UINT64 ctx_addr, UINT64 jmp_rbx_gadget, UINT64 epilogue_addr) {
        SIZE_T i = 0;
        
        buf[i++] = 0x9C;
        
        buf[i++] = 0x50;
        buf[i++] = 0x51;
        buf[i++] = 0x52;
        buf[i++] = 0x53;
        buf[i++] = 0x55;
        buf[i++] = 0x56;
        buf[i++] = 0x57;
        buf[i++] = 0x41; buf[i++] = 0x50;
        buf[i++] = 0x41; buf[i++] = 0x51;
        buf[i++] = 0x41; buf[i++] = 0x52;
        buf[i++] = 0x41; buf[i++] = 0x53;
        buf[i++] = 0x41; buf[i++] = 0x54;
        buf[i++] = 0x41; buf[i++] = 0x55;
        buf[i++] = 0x41; buf[i++] = 0x56;
        buf[i++] = 0x41; buf[i++] = 0x57;
        
        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC; buf[i++] = 0x80; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x04; buf[i++] = 0x24;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x4C; buf[i++] = 0x24; buf[i++] = 0x10;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x54; buf[i++] = 0x24; buf[i++] = 0x20;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x5C; buf[i++] = 0x24; buf[i++] = 0x30;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x64; buf[i++] = 0x24; buf[i++] = 0x40;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x6C; buf[i++] = 0x24; buf[i++] = 0x50;
        
        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x5E; buf[i++] = 0x48;
        
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x66; buf[i++] = 0x38;
        
        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0xE4; buf[i++] = 0xF0;
        
        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC;
        *(UINT32*)&buf[i] = 0x28;
        i += 4;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x10;
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x56; buf[i++] = 0x18;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x20;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x28;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x58;
        buf[i++] = 0x50;
        
        buf[i++] = 0x48; buf[i++] = 0xB8;
        *(UINT64*)&buf[i] = epilogue_addr;
        i += 8;
        buf[i++] = 0x50;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x1E;
        
        buf[i++] = 0x48; buf[i++] = 0xB8;
        *(UINT64*)&buf[i] = jmp_rbx_gadget;
        i += 8;
        
        buf[i++] = 0xFF; buf[i++] = 0xE0;
        
        return i;
    }
    
    __forceinline SIZE_T build_epilogue_v2(PUINT8 buf, UINT64 ctx_addr) {
        SIZE_T i = 0;
        
        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0xC4; buf[i++] = 0x10;
        
        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x46; buf[i++] = 0x30;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x5E; buf[i++] = 0x48;
        
        buf[i++] = 0x48; buf[i++] = 0xC7; buf[i++] = 0x46; buf[i++] = 0x50;
        buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
        
        buf[i++] = 0x0F; buf[i++] = 0xAE; buf[i++] = 0xF0;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x66; buf[i++] = 0x38;
        
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x6C; buf[i++] = 0x24; buf[i++] = 0x50;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x64; buf[i++] = 0x24; buf[i++] = 0x40;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x5C; buf[i++] = 0x24; buf[i++] = 0x30;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x54; buf[i++] = 0x24; buf[i++] = 0x20;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x4C; buf[i++] = 0x24; buf[i++] = 0x10;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x04; buf[i++] = 0x24;
        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xC4; buf[i++] = 0x80; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
        
        buf[i++] = 0x41; buf[i++] = 0x5F;
        buf[i++] = 0x41; buf[i++] = 0x5E;
        buf[i++] = 0x41; buf[i++] = 0x5D;
        buf[i++] = 0x41; buf[i++] = 0x5C;
        buf[i++] = 0x41; buf[i++] = 0x5B;
        buf[i++] = 0x41; buf[i++] = 0x5A;
        buf[i++] = 0x41; buf[i++] = 0x59;
        buf[i++] = 0x41; buf[i++] = 0x58;
        buf[i++] = 0x5F;
        buf[i++] = 0x5E;
        buf[i++] = 0x5D;
        buf[i++] = 0x5B;
        buf[i++] = 0x5A;
        buf[i++] = 0x59;
        buf[i++] = 0x58;
        
        buf[i++] = 0x9D;
        
        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x40;
        buf[i++] = 0xFF; buf[i++] = 0xE0;
        
        return i;
    }
    
    __forceinline SIZE_T build_direct_call(PUINT8 buf, UINT64 ctx_addr, UINT64 epilogue_addr) {
        UNREFERENCED_PARAMETER(epilogue_addr);
        SIZE_T i = 0;
        
        buf[i++] = 0x9C;
        
        buf[i++] = 0x50;
        buf[i++] = 0x51;
        buf[i++] = 0x52;
        buf[i++] = 0x53;
        buf[i++] = 0x55;
        buf[i++] = 0x56;
        buf[i++] = 0x57;
        buf[i++] = 0x41; buf[i++] = 0x50;
        buf[i++] = 0x41; buf[i++] = 0x51;
        buf[i++] = 0x41; buf[i++] = 0x52;
        buf[i++] = 0x41; buf[i++] = 0x53;
        buf[i++] = 0x41; buf[i++] = 0x54;
        buf[i++] = 0x41; buf[i++] = 0x55;
        buf[i++] = 0x41; buf[i++] = 0x56;
        buf[i++] = 0x41; buf[i++] = 0x57;
        
        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC; buf[i++] = 0x80; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x04; buf[i++] = 0x24;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x4C; buf[i++] = 0x24; buf[i++] = 0x10;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x54; buf[i++] = 0x24; buf[i++] = 0x20;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x5C; buf[i++] = 0x24; buf[i++] = 0x30;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x64; buf[i++] = 0x24; buf[i++] = 0x40;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x6C; buf[i++] = 0x24; buf[i++] = 0x50;
        
        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x5E; buf[i++] = 0x48;
        
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x66; buf[i++] = 0x38;
        
        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0xE4; buf[i++] = 0xF0;
        
        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC;
        *(UINT32*)&buf[i] = 0x28;
        i += 4;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x10;
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x56; buf[i++] = 0x18;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x20;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x28;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x06;
        
        buf[i++] = 0xFF; buf[i++] = 0xD0;
        
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x46; buf[i++] = 0x30;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x5E; buf[i++] = 0x48;
        
        buf[i++] = 0x48; buf[i++] = 0xC7; buf[i++] = 0x46; buf[i++] = 0x50;
        buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
        
        buf[i++] = 0x0F; buf[i++] = 0xAE; buf[i++] = 0xF0;
        
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x66; buf[i++] = 0x38;
        
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x6C; buf[i++] = 0x24; buf[i++] = 0x50;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x64; buf[i++] = 0x24; buf[i++] = 0x40;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x5C; buf[i++] = 0x24; buf[i++] = 0x30;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x54; buf[i++] = 0x24; buf[i++] = 0x20;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x4C; buf[i++] = 0x24; buf[i++] = 0x10;
        buf[i++] = 0x0F; buf[i++] = 0x28; buf[i++] = 0x04; buf[i++] = 0x24;
        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xC4; buf[i++] = 0x80; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;
        
        buf[i++] = 0x41; buf[i++] = 0x5F;
        buf[i++] = 0x41; buf[i++] = 0x5E;
        buf[i++] = 0x41; buf[i++] = 0x5D;
        buf[i++] = 0x41; buf[i++] = 0x5C;
        buf[i++] = 0x41; buf[i++] = 0x5B;
        buf[i++] = 0x41; buf[i++] = 0x5A;
        buf[i++] = 0x41; buf[i++] = 0x59;
        buf[i++] = 0x41; buf[i++] = 0x58;
        buf[i++] = 0x5F;
        buf[i++] = 0x5E;
        buf[i++] = 0x5D;
        buf[i++] = 0x5B;
        buf[i++] = 0x5A;
        buf[i++] = 0x59;
        buf[i++] = 0x58;
        
        buf[i++] = 0x9D;
        
        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x40;
        buf[i++] = 0xFF; buf[i++] = 0xE0;
        
        return i;
    }
}

NTSTATUS functions::handle7781(p_remote_call request) {
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!call_guard::is_valid_code_ptr(request->target_function)) {
        return STATUS_INVALID_ADDRESS;
    }
    
    if (!call_guard::is_valid_dtb(request->dtb)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (request->shellcode_address == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!call_guard::is_valid_user_range(request->shellcode_address)) {
        return STATUS_INVALID_ADDRESS;
    }

    UINT64 dtb_clean = request->dtb & ~0xFFFULL;
    UINT64 base_addr = request->shellcode_address;
    UINT64 context_addr = base_addr;
    UINT64 code_addr = base_addr + 0x200;
    UINT64 epilogue_addr = base_addr + 0x600;
    
    CALL_CONTEXT ctx = { 0 };
    ctx.target_func = request->target_function;
    ctx.spoof_gadget = request->spoof_return;
    ctx.param1 = request->arg1;
    ctx.param2 = request->arg2;
    ctx.param3 = request->arg3;
    ctx.param4 = request->arg4;
    ctx.ret_value = 0;
    ctx.saved_rsp = 0;
    ctx.original_rip = 0;
    ctx.rbx_backup = 0;
    ctx.exec_done = 0;
    ctx.trampoline_addr = epilogue_addr;
    for (int k = 0; k < 8; k++) ctx.stack_backup[k] = 0;
    for (int k = 0; k < 12; k++) ctx.xmm_backup[k] = 0;
    for (int k = 0; k < 8; k++) ctx.reserved[k] = 0;
    
    UINT8 shellcode[768];
    SIZE_T sc_size = 0;
    
    if (request->spoof_return != 0 && call_guard::is_valid_code_ptr(request->spoof_return)) {
        sc_size = shellcode_builder::build_jmp_rbx_spoofed(shellcode, context_addr, request->spoof_return, epilogue_addr);
    } else {
        sc_size = shellcode_builder::build_direct_call(shellcode, context_addr, epilogue_addr);
    }
    
    if (sc_size == 0 || sc_size > sizeof(shellcode)) {
        return STATUS_UNSUCCESSFUL;
    }
    
    UINT8 epilogue[256];
    SIZE_T ep_size = shellcode_builder::build_epilogue_v2(epilogue, context_addr);
    
    if (ep_size == 0 || ep_size > sizeof(epilogue)) {
        return STATUS_UNSUCCESSFUL;
    }

    SIZE_T bytes_written = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    
    UINT64 phys_ctx = strong::translate_virtual_address(dtb_clean, context_addr);
    if (!phys_ctx) {
        return STATUS_INVALID_ADDRESS;
    }
    
    status = strong::write_physical((PVOID)phys_ctx, &ctx, sizeof(ctx), &bytes_written);
    if (!NT_SUCCESS(status) || bytes_written != sizeof(ctx)) {
        return STATUS_UNSUCCESSFUL;
    }
    
    SIZE_T remaining = sc_size;
    SIZE_T offset = 0;
    
    while (remaining > 0) {
        UINT64 current_va = code_addr + offset;
        UINT64 physical_addr = strong::translate_virtual_address(dtb_clean, current_va);
        
        if (!physical_addr) {
            return STATUS_INVALID_ADDRESS;
        }
        
        SIZE_T page_offset = physical_addr & 0xFFF;
        SIZE_T bytes_in_page = 0x1000 - page_offset;
        SIZE_T write_size = (bytes_in_page < remaining) ? bytes_in_page : remaining;
        
        SIZE_T written = 0;
        status = strong::write_physical(
            (PVOID)physical_addr,
            &shellcode[offset],
            write_size,
            &written
        );
        
        if (!NT_SUCCESS(status)) {
            return status;
        }
        
        remaining -= written;
        offset += written;
    }
    
    remaining = ep_size;
    offset = 0;
    
    while (remaining > 0) {
        UINT64 current_va = epilogue_addr + offset;
        UINT64 physical_addr = strong::translate_virtual_address(dtb_clean, current_va);
        
        if (!physical_addr) {
            return STATUS_INVALID_ADDRESS;
        }
        
        SIZE_T page_offset = physical_addr & 0xFFF;
        SIZE_T bytes_in_page = 0x1000 - page_offset;
        SIZE_T write_size = (bytes_in_page < remaining) ? bytes_in_page : remaining;
        
        SIZE_T written = 0;
        status = strong::write_physical(
            (PVOID)physical_addr,
            &epilogue[offset],
            write_size,
            &written
        );
        
        if (!NT_SUCCESS(status)) {
            return status;
        }
        
        remaining -= written;
        offset += written;
    }

    KeMemoryBarrier();
    _mm_mfence();
    
    request->shellcode_address = code_addr;
    request->result = 0;
    request->completed = 0;

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle7782(p_call_result request) {
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!call_guard::is_valid_dtb(request->dtb)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (request->result_address == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!call_guard::is_valid_user_range(request->result_address)) {
        return STATUS_INVALID_ADDRESS;
    }

    UINT64 dtb_clean = request->dtb & ~0xFFFULL;
    UINT64 physical_addr = strong::translate_virtual_address(dtb_clean, request->result_address);
    
    if (!physical_addr) {
        return STATUS_INVALID_ADDRESS;
    }
    
    CALL_CONTEXT ctx = { 0 };
    SIZE_T bytes_read = 0;
    
    KeMemoryBarrier();
    
    NTSTATUS status = strong::read_physical(
        physical_addr,
        &ctx,
        sizeof(ctx),
        &bytes_read
    );
    
    if (!NT_SUCCESS(status) || bytes_read != sizeof(ctx)) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeMemoryBarrier();
    
    volatile UINT64 done_flag = ctx.exec_done;
    
    if (done_flag != 0) {
        request->result = ctx.ret_value;
        return STATUS_SUCCESS;
    }

    return STATUS_PENDING;
}

namespace alloc_internal {
    inline volatile UINT64 g_alloc_key = 0x5A5A5A5A5A5A5A5AULL;
    
    __forceinline void timing_noise() {
        volatile ULONG spin = (__rdtsc() & 0x7) + 1;
        while (spin--) {
            YieldProcessor();
        }
    }
}

NTSTATUS functions::handle7783(p_alloc_mem request) {
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (request->pid == 0 || request->pid <= 4) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (request->size == 0 || request->size > 0x1000000) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    
    if (!_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ZwAllocateVirtualMemory) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    alloc_internal::timing_noise();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process);
    
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }
    
    alloc_internal::timing_noise();
    
    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);
    
    PVOID base_addr = nullptr;
    SIZE_T region_size = (request->size + 0xFFF) & ~0xFFFULL;
    
    status = _ZwAllocateVirtualMemory(
        (HANDLE)-1,
        &base_addr,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);
    
    if (NT_SUCCESS(status) && base_addr) {
        request->allocated_address = (UINT64)base_addr;
        request->actual_size = region_size;
    } else {
        request->allocated_address = 0;
        request->actual_size = 0;
    }

    return status;
}

NTSTATUS functions::handle7784(p_free_mem request) {
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (request->pid == 0 || request->pid <= 4) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (request->address == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!call_guard::is_valid_user_range(request->address)) {
        return STATUS_INVALID_ADDRESS;
    }
    
    if (!_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ZwFreeVirtualMemory) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    alloc_internal::timing_noise();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process);
    
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }
    
    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);
    
    PVOID base_addr = (PVOID)request->address;
    SIZE_T region_size = 0;
    
    status = _ZwFreeVirtualMemory(
        (HANDLE)-1,
        &base_addr,
        &region_size,
        MEM_RELEASE
    );
    
    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return status;
}
