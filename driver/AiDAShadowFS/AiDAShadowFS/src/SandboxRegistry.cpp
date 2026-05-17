#include "SandboxRegistry.h"
#include "Logging.h"

namespace {
    SHADOW_SANDBOX_ENTRY g_entries[SHADOWFS_MAX_SANDBOX_PIDS];
    KSPIN_LOCK g_lock;
    volatile LONG g_lock_init = 0;
    volatile LONG g_any_active = 0;
    volatile LONG g_active_count = 0;
    volatile LONG64 g_stats_denials = 0;
    volatile LONG64 g_stats_redirects = 0;
    volatile LONG64 g_stats_copies = 0;
    volatile LONG64 g_stats_bytes_copied = 0;
    volatile LONG64 g_stats_fsctl_denials = 0;
    volatile LONG64 g_stats_ads_denials = 0;
    volatile LONG64 g_stats_mapping_denials = 0;
    volatile LONG64 g_stats_unc_denials = 0;
    volatile LONG64 g_stats_raw_device_denials = 0;
    volatile LONG64 g_stats_set_info_denials = 0;
    volatile LONG64 g_stats_dir_merge_emits = 0;

    __forceinline void ensure_lock() {
        if (InterlockedCompareExchange(&g_lock_init, 1, 0) == 0) {
            KeInitializeSpinLock(&g_lock);
        }
    }

    __forceinline void recompute_any_active_unsafe() {
        LONG count = 0;
        for (ULONG i = 0; i < SHADOWFS_MAX_SANDBOX_PIDS; ++i) {
            if (g_entries[i].active) {
                ++count;
            }
        }
        InterlockedExchange(&g_any_active, count > 0 ? 1 : 0);
        InterlockedExchange(&g_active_count, count);
    }
}

void shadow_registry_init() {
    ensure_lock();
    KIRQL irql;
    KeAcquireSpinLock(&g_lock, &irql);
    for (ULONG i = 0; i < SHADOWFS_MAX_SANDBOX_PIDS; ++i) {
        RtlZeroMemory(&g_entries[i], sizeof(SHADOW_SANDBOX_ENTRY));
    }
    InterlockedExchange(&g_any_active, 0);
    InterlockedExchange(&g_active_count, 0);
    InterlockedExchange64(&g_stats_denials, 0);
    InterlockedExchange64(&g_stats_redirects, 0);
    InterlockedExchange64(&g_stats_copies, 0);
    InterlockedExchange64(&g_stats_bytes_copied, 0);
    InterlockedExchange64(&g_stats_fsctl_denials, 0);
    InterlockedExchange64(&g_stats_ads_denials, 0);
    InterlockedExchange64(&g_stats_mapping_denials, 0);
    InterlockedExchange64(&g_stats_unc_denials, 0);
    InterlockedExchange64(&g_stats_raw_device_denials, 0);
    InterlockedExchange64(&g_stats_set_info_denials, 0);
    InterlockedExchange64(&g_stats_dir_merge_emits, 0);
    KeReleaseSpinLock(&g_lock, irql);
    SHADOW_LOG_INFO("registry_init complete max_pids=%lu", (unsigned long)SHADOWFS_MAX_SANDBOX_PIDS);
}

void shadow_registry_cleanup() {
    ensure_lock();
    KIRQL irql;
    KeAcquireSpinLock(&g_lock, &irql);
    for (ULONG i = 0; i < SHADOWFS_MAX_SANDBOX_PIDS; ++i) {
        RtlZeroMemory(&g_entries[i], sizeof(SHADOW_SANDBOX_ENTRY));
    }
    InterlockedExchange(&g_any_active, 0);
    InterlockedExchange(&g_active_count, 0);
    KeReleaseSpinLock(&g_lock, irql);
    SHADOW_LOG_INFO("registry_cleanup complete");
}

bool shadow_registry_add(HANDLE pid, ULONG flags, PCUNICODE_STRING sandbox_root) {
    if (pid == nullptr) return false;
    if (sandbox_root == nullptr || sandbox_root->Buffer == nullptr || sandbox_root->Length == 0) {
        SHADOW_LOG_WARN("registry_add REJECT empty_root pid=%lu", (unsigned long)(ULONG_PTR)pid);
        return false;
    }
    if (sandbox_root->Length > SHADOWFS_MAX_ROOT_BYTES) {
        SHADOW_LOG_WARN("registry_add REJECT root_too_long pid=%lu len=%u",
            (unsigned long)(ULONG_PTR)pid, sandbox_root->Length);
        return false;
    }

    ensure_lock();
    KIRQL irql;
    KeAcquireSpinLock(&g_lock, &irql);

    ULONG existing = SHADOWFS_MAX_SANDBOX_PIDS;
    for (ULONG i = 0; i < SHADOWFS_MAX_SANDBOX_PIDS; ++i) {
        if (g_entries[i].active && g_entries[i].pid == pid) {
            existing = i;
            break;
        }
    }
    if (existing < SHADOWFS_MAX_SANDBOX_PIDS) {
        g_entries[existing].flags = flags;
        g_entries[existing].root_length_bytes = sandbox_root->Length;
        RtlCopyMemory(g_entries[existing].root_buffer,
                      sandbox_root->Buffer,
                      sandbox_root->Length);
        if (sandbox_root->Length / sizeof(WCHAR) < SHADOWFS_MAX_ROOT_CHARS) {
            g_entries[existing].root_buffer[sandbox_root->Length / sizeof(WCHAR)] = L'\0';
        }
        KeReleaseSpinLock(&g_lock, irql);
        SHADOW_LOG_INFO("registry_add UPDATE pid=%lu flags=0x%08lX root='%wZ'",
            (unsigned long)(ULONG_PTR)pid, flags, sandbox_root);
        return true;
    }

    ULONG free_slot = SHADOWFS_MAX_SANDBOX_PIDS;
    for (ULONG i = 0; i < SHADOWFS_MAX_SANDBOX_PIDS; ++i) {
        if (!g_entries[i].active) {
            free_slot = i;
            break;
        }
    }
    if (free_slot >= SHADOWFS_MAX_SANDBOX_PIDS) {
        KeReleaseSpinLock(&g_lock, irql);
        SHADOW_LOG_ERROR("registry_add REJECT no_slot pid=%lu", (unsigned long)(ULONG_PTR)pid);
        return false;
    }

    g_entries[free_slot].pid = pid;
    g_entries[free_slot].flags = flags;
    g_entries[free_slot].root_length_bytes = sandbox_root->Length;
    g_entries[free_slot].active = 1;
    RtlCopyMemory(g_entries[free_slot].root_buffer,
                  sandbox_root->Buffer,
                  sandbox_root->Length);
    if (sandbox_root->Length / sizeof(WCHAR) < SHADOWFS_MAX_ROOT_CHARS) {
        g_entries[free_slot].root_buffer[sandbox_root->Length / sizeof(WCHAR)] = L'\0';
    }
    recompute_any_active_unsafe();
    LONG active_now = InterlockedCompareExchange(&g_active_count, 0, 0);
    KeReleaseSpinLock(&g_lock, irql);

    SHADOW_LOG_INFO("registry_add ADD pid=%lu flags=0x%08lX slot=%lu active_count=%ld root='%wZ'",
        (unsigned long)(ULONG_PTR)pid, flags, free_slot, active_now, sandbox_root);
    return true;
}

bool shadow_registry_remove(HANDLE pid) {
    if (pid == nullptr) return false;
    ensure_lock();
    KIRQL irql;
    KeAcquireSpinLock(&g_lock, &irql);
    bool removed = false;
    for (ULONG i = 0; i < SHADOWFS_MAX_SANDBOX_PIDS; ++i) {
        if (g_entries[i].active && g_entries[i].pid == pid) {
            RtlZeroMemory(&g_entries[i], sizeof(SHADOW_SANDBOX_ENTRY));
            removed = true;
            break;
        }
    }
    if (removed) {
        recompute_any_active_unsafe();
    }
    LONG active_now = InterlockedCompareExchange(&g_active_count, 0, 0);
    KeReleaseSpinLock(&g_lock, irql);
    if (removed) {
        SHADOW_LOG_INFO("registry_remove pid=%lu active_count=%ld",
            (unsigned long)(ULONG_PTR)pid, active_now);
    } else {
        SHADOW_LOG_WARN("registry_remove MISS pid=%lu (not tracked)", (unsigned long)(ULONG_PTR)pid);
    }
    return removed;
}

bool shadow_registry_any_active() {
    return InterlockedCompareExchange(&g_any_active, 0, 0) != 0;
}

ULONG shadow_registry_active_count() {
    return static_cast<ULONG>(InterlockedCompareExchange(&g_active_count, 0, 0));
}

bool shadow_registry_lookup(HANDLE pid, ULONG* out_flags, UNICODE_STRING* out_root) {
    if (pid == nullptr) return false;
    if (InterlockedCompareExchange(&g_any_active, 0, 0) == 0) return false;
    ensure_lock();
    KIRQL irql;
    KeAcquireSpinLock(&g_lock, &irql);
    bool hit = false;
    for (ULONG i = 0; i < SHADOWFS_MAX_SANDBOX_PIDS; ++i) {
        if (g_entries[i].active && g_entries[i].pid == pid) {
            if (out_flags) *out_flags = g_entries[i].flags;
            if (out_root) {
                if (out_root->Buffer != nullptr && out_root->MaximumLength >= g_entries[i].root_length_bytes) {
                    RtlCopyMemory(out_root->Buffer,
                                  g_entries[i].root_buffer,
                                  g_entries[i].root_length_bytes);
                    out_root->Length = g_entries[i].root_length_bytes;
                }
            }
            hit = true;
            break;
        }
    }
    KeReleaseSpinLock(&g_lock, irql);
    return hit;
}

void shadow_stats_inc_denials() {
    InterlockedIncrement64(&g_stats_denials);
}

void shadow_stats_inc_redirects() {
    InterlockedIncrement64(&g_stats_redirects);
}

void shadow_stats_inc_copies() {
    InterlockedIncrement64(&g_stats_copies);
}

void shadow_stats_add_bytes_copied(LONG64 amount) {
    if (amount <= 0) return;
    InterlockedAdd64(&g_stats_bytes_copied, amount);
}

void shadow_stats_inc_fsctl_denials() {
    InterlockedIncrement64(&g_stats_fsctl_denials);
    InterlockedIncrement64(&g_stats_denials);
}

void shadow_stats_inc_ads_denials() {
    InterlockedIncrement64(&g_stats_ads_denials);
    InterlockedIncrement64(&g_stats_denials);
}

void shadow_stats_inc_mapping_denials() {
    InterlockedIncrement64(&g_stats_mapping_denials);
    InterlockedIncrement64(&g_stats_denials);
}

void shadow_stats_inc_unc_denials() {
    InterlockedIncrement64(&g_stats_unc_denials);
    InterlockedIncrement64(&g_stats_denials);
}

void shadow_stats_inc_raw_device_denials() {
    InterlockedIncrement64(&g_stats_raw_device_denials);
    InterlockedIncrement64(&g_stats_denials);
}

void shadow_stats_inc_set_info_denials() {
    InterlockedIncrement64(&g_stats_set_info_denials);
    InterlockedIncrement64(&g_stats_denials);
}

void shadow_stats_inc_dir_merge_emits() {
    InterlockedIncrement64(&g_stats_dir_merge_emits);
}

LONG64 shadow_stats_denials() {
    return InterlockedCompareExchange64(&g_stats_denials, 0, 0);
}

LONG64 shadow_stats_redirects() {
    return InterlockedCompareExchange64(&g_stats_redirects, 0, 0);
}

LONG64 shadow_stats_copies() {
    return InterlockedCompareExchange64(&g_stats_copies, 0, 0);
}

LONG64 shadow_stats_bytes_copied() {
    return InterlockedCompareExchange64(&g_stats_bytes_copied, 0, 0);
}

LONG64 shadow_stats_fsctl_denials() {
    return InterlockedCompareExchange64(&g_stats_fsctl_denials, 0, 0);
}

LONG64 shadow_stats_ads_denials() {
    return InterlockedCompareExchange64(&g_stats_ads_denials, 0, 0);
}

LONG64 shadow_stats_mapping_denials() {
    return InterlockedCompareExchange64(&g_stats_mapping_denials, 0, 0);
}

LONG64 shadow_stats_unc_denials() {
    return InterlockedCompareExchange64(&g_stats_unc_denials, 0, 0);
}

LONG64 shadow_stats_raw_device_denials() {
    return InterlockedCompareExchange64(&g_stats_raw_device_denials, 0, 0);
}

LONG64 shadow_stats_set_info_denials() {
    return InterlockedCompareExchange64(&g_stats_set_info_denials, 0, 0);
}

LONG64 shadow_stats_dir_merge_emits() {
    return InterlockedCompareExchange64(&g_stats_dir_merge_emits, 0, 0);
}
