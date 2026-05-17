#include "DirMerge.h"
#include "../Logging.h"

#include <ntstrsafe.h>

namespace {

const ULONG k_align_mask = sizeof(ULONGLONG) - 1;

__forceinline ULONG align_up_8(ULONG v) {
    return (v + k_align_mask) & ~k_align_mask;
}

__forceinline bool ascii_case_iequal(WCHAR a, WCHAR b) {
    if (a >= L'A' && a <= L'Z') a = static_cast<WCHAR>(a - L'A' + L'a');
    if (b >= L'A' && b <= L'Z') b = static_cast<WCHAR>(b - L'A' + L'a');
    return a == b;
}

bool name_equal_i(const WCHAR* a, ULONG a_bytes, const WCHAR* b, ULONG b_bytes) {
    if (a_bytes != b_bytes) return false;
    ULONG chars = a_bytes / sizeof(WCHAR);
    for (ULONG i = 0; i < chars; ++i) {
        if (!ascii_case_iequal(a[i], b[i])) return false;
    }
    return true;
}

struct class_descriptor_t {
    FILE_INFORMATION_CLASS fic;
    ULONG record_min_size;
    ULONG next_offset_offset;
    ULONG name_length_offset;
    ULONG name_buffer_offset;
};

const class_descriptor_t k_class_table[] = {
    {
        FileDirectoryInformation,
        static_cast<ULONG>(sizeof(FILE_DIRECTORY_INFORMATION)),
        FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, NextEntryOffset),
        FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileNameLength),
        FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName)
    },
    {
        FileFullDirectoryInformation,
        static_cast<ULONG>(sizeof(FILE_FULL_DIR_INFORMATION)),
        FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, NextEntryOffset),
        FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileNameLength),
        FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName)
    },
    {
        FileBothDirectoryInformation,
        static_cast<ULONG>(sizeof(FILE_BOTH_DIR_INFORMATION)),
        FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, NextEntryOffset),
        FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileNameLength),
        FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName)
    },
    {
        FileIdBothDirectoryInformation,
        static_cast<ULONG>(sizeof(FILE_ID_BOTH_DIR_INFORMATION)),
        FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, NextEntryOffset),
        FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileNameLength),
        FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName)
    },
    {
        FileIdFullDirectoryInformation,
        static_cast<ULONG>(sizeof(FILE_ID_FULL_DIR_INFORMATION)),
        FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, NextEntryOffset),
        FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileNameLength),
        FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName)
    },
    {
        FileNamesInformation,
        static_cast<ULONG>(sizeof(FILE_NAMES_INFORMATION)),
        FIELD_OFFSET(FILE_NAMES_INFORMATION, NextEntryOffset),
        FIELD_OFFSET(FILE_NAMES_INFORMATION, FileNameLength),
        FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName)
    },
    {
        FileIdGlobalTxDirectoryInformation,
        static_cast<ULONG>(sizeof(FILE_ID_GLOBAL_TX_DIR_INFORMATION)),
        FIELD_OFFSET(FILE_ID_GLOBAL_TX_DIR_INFORMATION, NextEntryOffset),
        FIELD_OFFSET(FILE_ID_GLOBAL_TX_DIR_INFORMATION, FileNameLength),
        FIELD_OFFSET(FILE_ID_GLOBAL_TX_DIR_INFORMATION, FileName)
    },
    {
        FileIdExtdDirectoryInformation,
        static_cast<ULONG>(sizeof(FILE_ID_EXTD_DIR_INFORMATION)),
        FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, NextEntryOffset),
        FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength),
        FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileName)
    },
    {
        FileIdExtdBothDirectoryInformation,
        static_cast<ULONG>(sizeof(FILE_ID_EXTD_BOTH_DIR_INFORMATION)),
        FIELD_OFFSET(FILE_ID_EXTD_BOTH_DIR_INFORMATION, NextEntryOffset),
        FIELD_OFFSET(FILE_ID_EXTD_BOTH_DIR_INFORMATION, FileNameLength),
        FIELD_OFFSET(FILE_ID_EXTD_BOTH_DIR_INFORMATION, FileName)
    }
};

const class_descriptor_t* find_class(FILE_INFORMATION_CLASS fic) {
    for (ULONG i = 0; i < ARRAYSIZE(k_class_table); ++i) {
        if (k_class_table[i].fic == fic) {
            return &k_class_table[i];
        }
    }
    return nullptr;
}

NTSTATUS open_shadow_directory(
    PFLT_FILTER filter,
    PFLT_INSTANCE instance,
    PCUNICODE_STRING shadow_dir_path,
    HANDLE* out_handle,
    PFILE_OBJECT* out_fo)
{
    *out_handle = nullptr;
    *out_fo = nullptr;

    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb = {};
    InitializeObjectAttributes(&oa,
        const_cast<PUNICODE_STRING>(shadow_dir_path),
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);

    NTSTATUS s = FltCreateFileEx(
        filter,
        instance,
        out_handle,
        out_fo,
        FILE_LIST_DIRECTORY | SYNCHRONIZE | FILE_TRAVERSE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    return s;
}

NTSTATUS collect_shadow_names(
    PFLT_FILTER filter,
    PFLT_INSTANCE instance,
    PCUNICODE_STRING shadow_dir_path,
    FILE_INFORMATION_CLASS fic,
    PCUNICODE_STRING file_pattern,
    UCHAR** out_buf,
    ULONG* out_total_bytes)
{
    *out_buf = nullptr;
    *out_total_bytes = 0;
    const class_descriptor_t* desc = find_class(fic);
    if (desc == nullptr) return STATUS_NOT_SUPPORTED;

    HANDLE sdir = nullptr;
    PFILE_OBJECT sfo = nullptr;
    NTSTATUS o = open_shadow_directory(filter, instance, shadow_dir_path, &sdir, &sfo);
    if (!NT_SUCCESS(o)) return o;

    const ULONG query_buf_size = 64 * 1024;
    UCHAR* query_buf = static_cast<UCHAR*>(
        ExAllocatePool2(POOL_FLAG_PAGED, query_buf_size, SHADOW_TAG_ENUM));
    if (query_buf == nullptr) {
        FltClose(sdir);
        ObDereferenceObject(sfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG names_capacity = 64 * 1024;
    UCHAR* names = static_cast<UCHAR*>(
        ExAllocatePool2(POOL_FLAG_PAGED, names_capacity, SHADOW_TAG_ENUM));
    if (names == nullptr) {
        ExFreePoolWithTag(query_buf, SHADOW_TAG_ENUM);
        FltClose(sdir);
        ObDereferenceObject(sfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ULONG names_used = 0;

    bool first = true;
    while (true) {
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS qs = ZwQueryDirectoryFile(
            sdir,
            nullptr, nullptr, nullptr,
            &iosb,
            query_buf,
            query_buf_size,
            fic,
            FALSE,
            const_cast<PUNICODE_STRING>(file_pattern),
            first ? TRUE : FALSE);
        first = false;
        if (qs == STATUS_NO_MORE_FILES || qs == STATUS_NO_SUCH_FILE) break;
        if (!NT_SUCCESS(qs)) break;
        if (iosb.Information == 0) break;
        ULONG bytes_avail = static_cast<ULONG>(iosb.Information);
        ULONG c = 0;
        while (c < bytes_avail) {
            if (bytes_avail - c < desc->record_min_size) break;
            ULONG nxt = *reinterpret_cast<const ULONG*>(query_buf + c + desc->next_offset_offset);
            ULONG nl = *reinterpret_cast<const ULONG*>(query_buf + c + desc->name_length_offset);
            if (c + desc->name_buffer_offset + nl > bytes_avail) break;
            if (nl > 0) {
                if (names_used + sizeof(ULONG) + nl > names_capacity) {
                    ULONG new_cap = names_capacity * 2;
                    while (new_cap < names_used + sizeof(ULONG) + nl) new_cap *= 2;
                    UCHAR* new_buf = static_cast<UCHAR*>(
                        ExAllocatePool2(POOL_FLAG_PAGED, new_cap, SHADOW_TAG_ENUM));
                    if (new_buf == nullptr) break;
                    RtlCopyMemory(new_buf, names, names_used);
                    ExFreePoolWithTag(names, SHADOW_TAG_ENUM);
                    names = new_buf;
                    names_capacity = new_cap;
                }
                *reinterpret_cast<ULONG*>(names + names_used) = nl;
                names_used += sizeof(ULONG);
                RtlCopyMemory(names + names_used, query_buf + c + desc->name_buffer_offset, nl);
                names_used += nl;
            }
            if (nxt == 0) break;
            c += nxt;
        }
    }

    ExFreePoolWithTag(query_buf, SHADOW_TAG_ENUM);
    FltClose(sdir);
    ObDereferenceObject(sfo);

    *out_buf = names;
    *out_total_bytes = names_used;
    return STATUS_SUCCESS;
}

bool name_in_shadow_set(const UCHAR* names, ULONG names_size, const WCHAR* name, ULONG name_bytes) {
    ULONG c = 0;
    while (c + sizeof(ULONG) <= names_size) {
        ULONG nl = *reinterpret_cast<const ULONG*>(names + c);
        c += sizeof(ULONG);
        if (c + nl > names_size) break;
        const WCHAR* nb = reinterpret_cast<const WCHAR*>(names + c);
        if (name_equal_i(name, name_bytes, nb, nl)) return true;
        c += nl;
    }
    return false;
}

NTSTATUS query_shadow_entries_packed(
    PFLT_FILTER filter,
    PFLT_INSTANCE instance,
    PCUNICODE_STRING shadow_dir_path,
    FILE_INFORMATION_CLASS fic,
    PCUNICODE_STRING file_pattern,
    bool restart,
    ULONG skip_count,
    ULONG single_max,
    UCHAR* dest,
    ULONG dest_capacity,
    ULONG* out_dest_used,
    ULONG* out_emitted_count)
{
    *out_dest_used = 0;
    *out_emitted_count = 0;
    const class_descriptor_t* desc = find_class(fic);
    if (desc == nullptr) return STATUS_NOT_SUPPORTED;

    HANDLE sdir = nullptr;
    PFILE_OBJECT sfo = nullptr;
    NTSTATUS o = open_shadow_directory(filter, instance, shadow_dir_path, &sdir, &sfo);
    if (!NT_SUCCESS(o)) return o;

    const ULONG query_buf_size = 64 * 1024;
    UCHAR* query_buf = static_cast<UCHAR*>(
        ExAllocatePool2(POOL_FLAG_PAGED, query_buf_size, SHADOW_TAG_ENUM));
    if (query_buf == nullptr) {
        FltClose(sdir);
        ObDereferenceObject(sfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG dest_used = 0;
    ULONG emitted = 0;
    ULONG skipped = 0;
    bool first_query = true;
    bool stop = false;
    UNREFERENCED_PARAMETER(restart);

    while (!stop) {
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS qs = ZwQueryDirectoryFile(
            sdir,
            nullptr, nullptr, nullptr,
            &iosb,
            query_buf,
            query_buf_size,
            fic,
            FALSE,
            const_cast<PUNICODE_STRING>(file_pattern),
            first_query ? TRUE : FALSE);
        first_query = false;
        if (qs == STATUS_NO_MORE_FILES || qs == STATUS_NO_SUCH_FILE) break;
        if (!NT_SUCCESS(qs)) break;
        if (iosb.Information == 0) break;
        ULONG bytes_avail = static_cast<ULONG>(iosb.Information);
        ULONG c = 0;
        while (c < bytes_avail) {
            if (bytes_avail - c < desc->record_min_size) break;
            ULONG nxt = *reinterpret_cast<const ULONG*>(query_buf + c + desc->next_offset_offset);
            ULONG nl = *reinterpret_cast<const ULONG*>(query_buf + c + desc->name_length_offset);
            if (c + desc->name_buffer_offset + nl > bytes_avail) break;

            if (skipped < skip_count) {
                ++skipped;
            } else {
                ULONG no_pad = desc->name_buffer_offset + nl;
                ULONG padded = align_up_8(no_pad);
                if (dest_used + padded > dest_capacity) {
                    stop = true;
                    break;
                }
                RtlCopyMemory(dest + dest_used, query_buf + c, no_pad);
                ULONG pad_bytes = padded - no_pad;
                if (pad_bytes > 0) {
                    RtlZeroMemory(dest + dest_used + no_pad, pad_bytes);
                }
                *reinterpret_cast<ULONG*>(dest + dest_used + desc->next_offset_offset) = padded;
                dest_used += padded;
                ++emitted;
                if (single_max != 0 && emitted >= single_max) {
                    stop = true;
                    break;
                }
            }

            if (nxt == 0) break;
            c += nxt;
        }
    }

    ExFreePoolWithTag(query_buf, SHADOW_TAG_ENUM);
    FltClose(sdir);
    ObDereferenceObject(sfo);

    if (dest_used > 0) {
        ULONG last_off = 0;
        ULONG c = 0;
        while (c < dest_used) {
            ULONG nxt = *reinterpret_cast<const ULONG*>(dest + c + desc->next_offset_offset);
            last_off = c;
            if (nxt == 0) break;
            c += nxt;
        }
        *reinterpret_cast<ULONG*>(dest + last_off + desc->next_offset_offset) = 0;
    }

    *out_dest_used = dest_used;
    *out_emitted_count = emitted;
    return STATUS_SUCCESS;
}

}

bool dir_info_class_is_supported(FILE_INFORMATION_CLASS fic) {
    return find_class(fic) != nullptr;
}

bool dir_info_extract_name(
    FILE_INFORMATION_CLASS fic,
    const UCHAR* entry,
    ULONG remaining,
    ULONG* next_entry_offset,
    const WCHAR** name_buf,
    ULONG* name_length_bytes,
    ULONG* entry_record_bytes)
{
    if (next_entry_offset) *next_entry_offset = 0;
    if (name_buf) *name_buf = nullptr;
    if (name_length_bytes) *name_length_bytes = 0;
    if (entry_record_bytes) *entry_record_bytes = 0;
    const class_descriptor_t* desc = find_class(fic);
    if (desc == nullptr) return false;
    if (entry == nullptr || remaining < desc->record_min_size) return false;
    ULONG next = *reinterpret_cast<const ULONG*>(entry + desc->next_offset_offset);
    ULONG nl = *reinterpret_cast<const ULONG*>(entry + desc->name_length_offset);
    if (desc->name_buffer_offset + nl > remaining) return false;
    if (next_entry_offset) *next_entry_offset = next;
    if (name_buf) *name_buf = reinterpret_cast<const WCHAR*>(entry + desc->name_buffer_offset);
    if (name_length_bytes) *name_length_bytes = nl;
    if (entry_record_bytes) {
        *entry_record_bytes = (next != 0) ? next : (desc->name_buffer_offset + nl);
    }
    return true;
}

void dir_merge_state_reset(PSHADOW_DIR_ENUM_STATE state) {
    if (state == nullptr) return;
    state->shadow_emit_index = 0;
    state->shadow_done = 0;
    state->total_shadow_emitted = 0;
}

NTSTATUS dir_merge_synthesize(
    PFLT_FILTER filter,
    PFLT_INSTANCE instance,
    PSHADOW_STREAM_CONTEXT ctx,
    FILE_INFORMATION_CLASS fic,
    ULONG sl_flags,
    PCUNICODE_STRING file_pattern,
    UCHAR* user_buffer,
    ULONG user_buffer_capacity,
    PULONG bytes_already_in_user_buffer)
{
    if (filter == nullptr || instance == nullptr || ctx == nullptr || user_buffer == nullptr
        || bytes_already_in_user_buffer == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ctx->shadow_path.Buffer == nullptr || ctx->shadow_path.Length == 0) {
        return STATUS_SUCCESS;
    }
    const class_descriptor_t* desc = find_class(fic);
    if (desc == nullptr) {
        return STATUS_SUCCESS;
    }

    ULONG real_used = *bytes_already_in_user_buffer;
    if (real_used > user_buffer_capacity) real_used = user_buffer_capacity;

    bool restart = (sl_flags & SL_RESTART_SCAN) != 0;
    bool single = (sl_flags & SL_RETURN_SINGLE_ENTRY) != 0;

    if (restart) {
        dir_merge_state_reset(&ctx->enum_state);
    }

    bool shadow_done_before = (ctx->enum_state.shadow_done != 0);

    UCHAR* real_temp = nullptr;
    if (real_used > 0) {
        real_temp = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_PAGED, real_used, SHADOW_TAG_ENUM));
        if (real_temp == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(real_temp, user_buffer, real_used);
    }

    UCHAR* shadow_names = nullptr;
    ULONG shadow_names_size = 0;
    NTSTATUS cs = collect_shadow_names(
        filter, instance, &ctx->shadow_path, fic, file_pattern,
        &shadow_names, &shadow_names_size);
    UNREFERENCED_PARAMETER(cs);

    ULONG shadow_packed_capacity = user_buffer_capacity;
    UCHAR* shadow_packed = nullptr;
    ULONG shadow_packed_used = 0;
    ULONG shadow_emitted = 0;

    if (!shadow_done_before) {
        shadow_packed = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_PAGED, shadow_packed_capacity, SHADOW_TAG_ENUM));
        if (shadow_packed == nullptr) {
            if (real_temp) ExFreePoolWithTag(real_temp, SHADOW_TAG_ENUM);
            if (shadow_names) ExFreePoolWithTag(shadow_names, SHADOW_TAG_ENUM);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ULONG skip_count = ctx->enum_state.shadow_emit_index;
        ULONG cap_for_shadow = user_buffer_capacity;
        if (real_used > 0 && !single && user_buffer_capacity > real_used) {
            ULONG room = user_buffer_capacity - real_used;
            cap_for_shadow = (room < user_buffer_capacity / 2) ? user_buffer_capacity / 2 : room;
            if (cap_for_shadow < desc->record_min_size + 256 * sizeof(WCHAR)) {
                cap_for_shadow = user_buffer_capacity;
            }
        }
        if (cap_for_shadow > shadow_packed_capacity) cap_for_shadow = shadow_packed_capacity;

        NTSTATUS qs = query_shadow_entries_packed(
            filter, instance, &ctx->shadow_path, fic, file_pattern,
            restart, skip_count,
            single ? 1 : 0,
            shadow_packed, cap_for_shadow,
            &shadow_packed_used, &shadow_emitted);
        UNREFERENCED_PARAMETER(qs);

        if (shadow_emitted == 0) {
            ctx->enum_state.shadow_done = 1;
            ExFreePoolWithTag(shadow_packed, SHADOW_TAG_ENUM);
            shadow_packed = nullptr;
            shadow_packed_used = 0;
        } else {
            ctx->enum_state.shadow_emit_index += shadow_emitted;
            ctx->enum_state.total_shadow_emitted += shadow_emitted;
        }
    }

    ULONG dst_cursor = 0;
    ULONG last_record_off = (ULONG)-1;
    if (shadow_packed_used > 0) {
        RtlCopyMemory(user_buffer, shadow_packed, shadow_packed_used);
        ULONG sc = 0;
        while (sc < shadow_packed_used) {
            ULONG n = *reinterpret_cast<const ULONG*>(user_buffer + sc + desc->next_offset_offset);
            last_record_off = sc;
            if (n == 0) break;
            sc += n;
        }
        dst_cursor = shadow_packed_used;
        shadow_stats_inc_dir_merge_emits();
    }

    if (!single && real_used > 0 && real_temp != nullptr) {
        ULONG src_cursor = 0;
        while (src_cursor < real_used) {
            if (real_used - src_cursor < desc->record_min_size) break;
            ULONG rn = *reinterpret_cast<const ULONG*>(real_temp + src_cursor + desc->next_offset_offset);
            ULONG rnl = *reinterpret_cast<const ULONG*>(real_temp + src_cursor + desc->name_length_offset);
            if (src_cursor + desc->name_buffer_offset + rnl > real_used) break;
            const WCHAR* rname = reinterpret_cast<const WCHAR*>(
                real_temp + src_cursor + desc->name_buffer_offset);

            bool shadowed = false;
            if (shadow_names != nullptr && shadow_names_size > 0) {
                shadowed = name_in_shadow_set(shadow_names, shadow_names_size, rname, rnl);
            }

            ULONG no_pad = desc->name_buffer_offset + rnl;
            ULONG padded = align_up_8(no_pad);

            if (!shadowed) {
                if (dst_cursor + padded > user_buffer_capacity) break;
                RtlCopyMemory(user_buffer + dst_cursor, real_temp + src_cursor, no_pad);
                ULONG pad_bytes = padded - no_pad;
                if (pad_bytes > 0) {
                    RtlZeroMemory(user_buffer + dst_cursor + no_pad, pad_bytes);
                }
                if (last_record_off != (ULONG)-1) {
                    *reinterpret_cast<ULONG*>(user_buffer + last_record_off + desc->next_offset_offset)
                        = dst_cursor - last_record_off;
                }
                *reinterpret_cast<ULONG*>(user_buffer + dst_cursor + desc->next_offset_offset) = 0;
                last_record_off = dst_cursor;
                dst_cursor += padded;
            }
            if (rn == 0) break;
            src_cursor += rn;
        }
    } else if (single && shadow_packed_used == 0 && real_used > 0 && real_temp != nullptr) {
        if (real_used <= user_buffer_capacity) {
            ULONG rnl = *reinterpret_cast<const ULONG*>(real_temp + desc->name_length_offset);
            const WCHAR* rname = reinterpret_cast<const WCHAR*>(real_temp + desc->name_buffer_offset);
            bool shadowed = false;
            if (shadow_names != nullptr && shadow_names_size > 0) {
                shadowed = name_in_shadow_set(shadow_names, shadow_names_size, rname, rnl);
            }
            if (!shadowed) {
                ULONG no_pad = desc->name_buffer_offset + rnl;
                ULONG padded = align_up_8(no_pad);
                if (padded > user_buffer_capacity) padded = no_pad;
                RtlCopyMemory(user_buffer, real_temp, no_pad);
                ULONG pad_bytes = padded - no_pad;
                if (pad_bytes > 0) {
                    RtlZeroMemory(user_buffer + no_pad, pad_bytes);
                }
                *reinterpret_cast<ULONG*>(user_buffer + desc->next_offset_offset) = 0;
                dst_cursor = padded;
                last_record_off = 0;
            }
        }
    }

    if (last_record_off != (ULONG)-1) {
        *reinterpret_cast<ULONG*>(user_buffer + last_record_off + desc->next_offset_offset) = 0;
    }

    *bytes_already_in_user_buffer = dst_cursor;

    if (shadow_packed != nullptr) ExFreePoolWithTag(shadow_packed, SHADOW_TAG_ENUM);
    if (shadow_names != nullptr) ExFreePoolWithTag(shadow_names, SHADOW_TAG_ENUM);
    if (real_temp != nullptr) ExFreePoolWithTag(real_temp, SHADOW_TAG_ENUM);
    return STATUS_SUCCESS;
}
