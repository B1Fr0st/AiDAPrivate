#pragma once

#include <ntifs.h>
#include <imports/Defs.h>
#include <core/KernelCrypto.h>

extern "C" PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);

namespace peer_attest {

    struct peb_image_view_t {
        UCHAR _reserved[0x10];
        PVOID image_base_address;
    };

    constexpr ULONG PEER_ATTEST_POOL_TAG = 'aPpS';
    constexpr ULONG MAX_PEER_SECTION_SIZE = 32u * 1024u * 1024u;
    constexpr ULONG MAX_PEER_SECTIONS     = 32u;

    constexpr UINT8 g_domain_separator[] = {
        'A','I','D','A','_','P','E','E','R','_','A','T','T','E','S','T','_','V','1', 0
    };
    constexpr ULONG g_domain_separator_len = sizeof(g_domain_separator);

    __forceinline bool is_volatile_section_name(const UCHAR name[8])
    {
        struct named_t { const char* s; ULONG len; };
        static const named_t volatile_names[] = {
            { ".epheme",  7 },
            { ".dthunk",  7 },
            { ".licbind", 8 },
            { ".feat",    5 },
            { ".gehi",    5 },
            { ".dseal",   6 },
        };

        for (ULONG i = 0; i < sizeof(volatile_names) / sizeof(volatile_names[0]); ++i) {
            const named_t& vn = volatile_names[i];
            if (vn.len > 8) continue;
            bool match = true;
            for (ULONG j = 0; j < vn.len; ++j) {
                if (name[j] != static_cast<UCHAR>(vn.s[j])) { match = false; break; }
            }
            if (match) {
                if (vn.len == 8) return true;
                if (name[vn.len] == 0) return true;
            }
        }
        return false;
    }

    __forceinline NTSTATUS attest_peer_process(
        IN PEPROCESS target,
        OUT UCHAR peer_hash[32])
    {
        if (peer_hash) {
            for (ULONG i = 0; i < 32; ++i) peer_hash[i] = 0;
        }
        if (!target || !peer_hash) {
            return STATUS_INVALID_PARAMETER;
        }
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        KAPC_STATE apc_state = {};
        BOOLEAN attached = FALSE;
        UINT8* section_digest_table = nullptr;
        ULONG section_count = 0;
        NTSTATUS status = STATUS_SUCCESS;

        KeStackAttachProcess(target, &apc_state);
        attached = TRUE;

        __try {
            auto peb = reinterpret_cast<peb_image_view_t*>(PsGetProcessPeb(target));
            if (!peb || !_MmIsAddressValid(peb)) {
                status = STATUS_NOT_FOUND;
                goto cleanup;
            }

            PVOID image_base = peb->image_base_address;
            if (!image_base || !_MmIsAddressValid(image_base)) {
                status = STATUS_NOT_FOUND;
                goto cleanup;
            }

            PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(image_base);
            if (!_MmIsAddressValid(dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto cleanup;
            }

            PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                static_cast<UCHAR*>(image_base) + dos->e_lfanew);
            if (!_MmIsAddressValid(nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto cleanup;
            }

            USHORT num_sections = nt->FileHeader.NumberOfSections;
            if (num_sections == 0 || num_sections > 96) {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto cleanup;
            }

            PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
            if (!_MmIsAddressValid(sections)) {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto cleanup;
            }

            section_digest_table = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_PEER_SECTIONS * 32, PEER_ATTEST_POOL_TAG));
            if (!section_digest_table) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto cleanup;
            }

            for (USHORT i = 0; i < num_sections; ++i) {
                if (section_count >= MAX_PEER_SECTIONS) break;

                const ULONG characteristics = sections[i].Characteristics;
                const ULONG required = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
                if ((characteristics & required) != required) continue;

                if (is_volatile_section_name(sections[i].Name)) continue;

                ULONG section_size = sections[i].Misc.VirtualSize;
                if (section_size == 0) continue;
                if (section_size > MAX_PEER_SECTION_SIZE) section_size = MAX_PEER_SECTION_SIZE;

                UCHAR* section_base = static_cast<UCHAR*>(image_base) + sections[i].VirtualAddress;
                if (!_MmIsAddressValid(section_base)) continue;
                if (!_MmIsAddressValid(section_base + section_size - 1)) continue;

                kernel_crypto::sha256_ctx_t ctx;
                kernel_crypto::sha256_init(&ctx);
                kernel_crypto::sha256_update(&ctx, g_domain_separator, g_domain_separator_len);
                kernel_crypto::sha256_update(&ctx, sections[i].Name, 8);

                UINT8 size_le[4];
                size_le[0] = static_cast<UINT8>(section_size & 0xFF);
                size_le[1] = static_cast<UINT8>((section_size >> 8) & 0xFF);
                size_le[2] = static_cast<UINT8>((section_size >> 16) & 0xFF);
                size_le[3] = static_cast<UINT8>((section_size >> 24) & 0xFF);
                kernel_crypto::sha256_update(&ctx, size_le, sizeof(size_le));

                const ULONG block = 4096;
                ULONG offset = 0;
                bool read_failed = false;
                while (offset < section_size) {
                    ULONG chunk = section_size - offset;
                    if (chunk > block) chunk = block;
                    if (!_MmIsAddressValid(section_base + offset)) { read_failed = true; break; }
                    if (!_MmIsAddressValid(section_base + offset + chunk - 1)) { read_failed = true; break; }
                    __try {
                        kernel_crypto::sha256_update(&ctx, section_base + offset, chunk);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        read_failed = true;
                    }
                    if (read_failed) break;
                    offset += chunk;
                }

                if (read_failed) {
                    RtlSecureZeroMemory(&ctx, sizeof(ctx));
                    continue;
                }

                UINT8 digest[32] = {};
                kernel_crypto::sha256_final(&ctx, digest);
                RtlCopyMemory(section_digest_table + (section_count * 32), digest, 32);
                ++section_count;
                RtlSecureZeroMemory(digest, sizeof(digest));
                RtlSecureZeroMemory(&ctx, sizeof(ctx));
            }

            if (section_count == 0) {
                status = STATUS_NOT_FOUND;
                goto cleanup;
            }

            {
                kernel_crypto::sha256_ctx_t agg_ctx;
                kernel_crypto::sha256_init(&agg_ctx);
                kernel_crypto::sha256_update(&agg_ctx, g_domain_separator, g_domain_separator_len);
                UINT8 count_le[4];
                count_le[0] = static_cast<UINT8>(section_count & 0xFF);
                count_le[1] = static_cast<UINT8>((section_count >> 8) & 0xFF);
                count_le[2] = static_cast<UINT8>((section_count >> 16) & 0xFF);
                count_le[3] = static_cast<UINT8>((section_count >> 24) & 0xFF);
                kernel_crypto::sha256_update(&agg_ctx, count_le, sizeof(count_le));
                kernel_crypto::sha256_update(&agg_ctx, section_digest_table, section_count * 32);
                kernel_crypto::sha256_final(&agg_ctx, peer_hash);
                RtlSecureZeroMemory(&agg_ctx, sizeof(agg_ctx));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_UNHANDLED_EXCEPTION;
        }

    cleanup:
        if (attached) {
            KeUnstackDetachProcess(&apc_state);
        }
        if (section_digest_table) {
            RtlSecureZeroMemory(section_digest_table, MAX_PEER_SECTIONS * 32);
            ExFreePoolWithTag(section_digest_table, PEER_ATTEST_POOL_TAG);
        }

        if (!NT_SUCCESS(status) && peer_hash) {
            for (ULONG i = 0; i < 32; ++i) peer_hash[i] = 0;
        }
        return status;
    }

    inline UCHAR           g_last_peer_hash[32] = {};
    inline volatile LONG64 g_last_peer_hash_tsc = 0;
    inline volatile LONG   g_last_peer_status   = 0;

    __forceinline NTSTATUS refresh_peer_hash(HANDLE peer_pid)
    {
        if (!peer_pid) {
            return STATUS_INVALID_PARAMETER;
        }

        PEPROCESS proc = nullptr;
        NTSTATUS lookup = PsLookupProcessByProcessId(peer_pid, &proc);
        if (!NT_SUCCESS(lookup) || !proc) {
            _InterlockedExchange(&g_last_peer_status, lookup);
            return lookup;
        }

        UCHAR hash[32] = {};
        NTSTATUS st = attest_peer_process(proc, hash);
        _InterlockedExchange(&g_last_peer_status, st);

        if (NT_SUCCESS(st)) {
            for (ULONG i = 0; i < 32; ++i) g_last_peer_hash[i] = hash[i];
            _InterlockedExchange64(&g_last_peer_hash_tsc, static_cast<LONG64>(__rdtsc()));
        }

        if (proc) {
            _ObfDereferenceObject(proc);
        }
        RtlSecureZeroMemory(hash, sizeof(hash));
        return st;
    }

    __forceinline void snapshot_last_hash(UCHAR out[32])
    {
        if (!out) return;
        for (ULONG i = 0; i < 32; ++i) out[i] = g_last_peer_hash[i];
    }

    __forceinline bool has_recent_hash()
    {
        return _InterlockedCompareExchange64(
            const_cast<volatile LONG64*>(&g_last_peer_hash_tsc), 0, 0) != 0;
    }

    __forceinline LONG last_status()
    {
        return _InterlockedCompareExchange(
            const_cast<volatile LONG*>(&g_last_peer_status), 0, 0);
    }
}
