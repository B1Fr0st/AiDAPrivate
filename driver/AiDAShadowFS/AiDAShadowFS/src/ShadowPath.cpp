#include "ShadowPath.h"
#include "SandboxRegistry.h"
#include "Logging.h"

#include <ntstrsafe.h>

namespace {
    const WCHAR* k_cow_suffix = L"\\__cow";
    const ULONG k_cow_suffix_chars = 6;

    __forceinline bool ascii_case_iequal(WCHAR a, WCHAR b) {
        if (a >= L'A' && a <= L'Z') a = static_cast<WCHAR>(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = static_cast<WCHAR>(b - L'A' + L'a');
        return a == b;
    }

    bool unicode_starts_with_i(PCUNICODE_STRING haystack, PCUNICODE_STRING needle) {
        if (haystack == nullptr || needle == nullptr) return false;
        if (haystack->Buffer == nullptr || needle->Buffer == nullptr) return false;
        if (haystack->Length < needle->Length) return false;
        ULONG nchars = needle->Length / sizeof(WCHAR);
        for (ULONG i = 0; i < nchars; ++i) {
            if (!ascii_case_iequal(haystack->Buffer[i], needle->Buffer[i])) {
                return false;
            }
        }
        return true;
    }

    bool unicode_starts_with_literal_i(PCUNICODE_STRING haystack, const WCHAR* needle) {
        if (haystack == nullptr || haystack->Buffer == nullptr || needle == nullptr) return false;
        ULONG hchars = haystack->Length / sizeof(WCHAR);
        ULONG i = 0;
        while (needle[i] != L'\0') {
            if (i >= hchars) return false;
            if (!ascii_case_iequal(haystack->Buffer[i], needle[i])) return false;
            ++i;
        }
        return true;
    }

    bool unicode_contains_literal_i(PCUNICODE_STRING haystack, const WCHAR* needle) {
        if (haystack == nullptr || haystack->Buffer == nullptr || needle == nullptr) return false;
        ULONG nlen = 0;
        while (needle[nlen] != L'\0') ++nlen;
        if (nlen == 0) return true;
        ULONG hlen = haystack->Length / sizeof(WCHAR);
        if (hlen < nlen) return false;
        for (ULONG i = 0; i + nlen <= hlen; ++i) {
            bool match = true;
            for (ULONG j = 0; j < nlen; ++j) {
                if (!ascii_case_iequal(haystack->Buffer[i + j], needle[j])) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }
}

NTSTATUS shadow_path_init() {
    return STATUS_SUCCESS;
}

void shadow_path_cleanup() {
}

NTSTATUS shadow_path_free(PUNICODE_STRING path) {
    if (path == nullptr) return STATUS_SUCCESS;
    if (path->Buffer != nullptr) {
        ExFreePoolWithTag(path->Buffer, SHADOW_TAG_PATH);
        path->Buffer = nullptr;
    }
    path->Length = 0;
    path->MaximumLength = 0;
    return STATUS_SUCCESS;
}

bool shadow_is_path_under_root(PCUNICODE_STRING candidate, PCUNICODE_STRING root) {
    if (candidate == nullptr || root == nullptr) return false;
    if (candidate->Buffer == nullptr || root->Buffer == nullptr) return false;
    if (root->Length == 0) return false;
    if (candidate->Length < root->Length) return false;

    UNICODE_STRING trimmed_root = *root;
    if (trimmed_root.Length >= sizeof(WCHAR)) {
        ULONG last_char = (trimmed_root.Length / sizeof(WCHAR)) - 1;
        if (trimmed_root.Buffer[last_char] == L'\\') {
            trimmed_root.Length -= sizeof(WCHAR);
        }
    }

    if (candidate->Length < trimmed_root.Length) return false;
    if (!unicode_starts_with_i(candidate, &trimmed_root)) return false;

    if (candidate->Length == trimmed_root.Length) return true;
    ULONG next_char_idx = trimmed_root.Length / sizeof(WCHAR);
    if (next_char_idx < (candidate->Length / sizeof(WCHAR))) {
        WCHAR sep = candidate->Buffer[next_char_idx];
        if (sep == L'\\' || sep == L'/') {
            return true;
        }
    }
    return false;
}

bool shadow_is_named_pipe(PCUNICODE_STRING path) {
    if (path == nullptr) return false;
    return unicode_starts_with_literal_i(path, L"\\Device\\NamedPipe")
        || unicode_starts_with_literal_i(path, L"\\??\\pipe\\")
        || unicode_starts_with_literal_i(path, L"\\\\.\\pipe\\")
        || unicode_starts_with_literal_i(path, L"\\\\?\\pipe\\");
}

bool shadow_is_unc_remote(PCUNICODE_STRING path) {
    if (path == nullptr) return false;
    return unicode_starts_with_literal_i(path, L"\\Device\\Mup\\")
        || unicode_starts_with_literal_i(path, L"\\Device\\LanmanRedirector\\")
        || unicode_starts_with_literal_i(path, L"\\??\\UNC\\");
}

bool shadow_is_raw_volume_or_disk(PCUNICODE_STRING path) {
    if (path == nullptr) return false;
    if (unicode_starts_with_literal_i(path, L"\\Device\\PhysicalDrive")) return true;
    if (unicode_starts_with_literal_i(path, L"\\Device\\Harddisk0\\")
        && unicode_contains_literal_i(path, L"\\Partition")) return true;
    if (unicode_starts_with_literal_i(path, L"\\Device\\Volume{")) return true;
    if (unicode_starts_with_literal_i(path, L"\\GLOBAL??\\PhysicalDrive")) return true;
    if (unicode_starts_with_literal_i(path, L"\\??\\PhysicalDrive")) return true;
    return false;
}

bool shadow_path_has_ads_colon(PCUNICODE_STRING path) {
    if (path == nullptr || path->Buffer == nullptr) return false;
    ULONG chars = path->Length / sizeof(WCHAR);
    if (chars < 2) return false;
    ULONG last_sep = 0;
    bool have_sep = false;
    for (ULONG i = 0; i < chars; ++i) {
        WCHAR c = path->Buffer[i];
        if (c == L'\\' || c == L'/') {
            last_sep = i;
            have_sep = true;
        }
    }
    ULONG start = have_sep ? (last_sep + 1) : 0;
    for (ULONG i = start; i < chars; ++i) {
        if (path->Buffer[i] == L':') {
            if (i + 1 < chars) {
                WCHAR n = path->Buffer[i + 1];
                if (n == L'\0') return false;
            }
            return true;
        }
    }
    return false;
}

bool shadow_path_is_volume_root(PCUNICODE_STRING path) {
    if (path == nullptr || path->Buffer == nullptr) return false;
    ULONG chars = path->Length / sizeof(WCHAR);
    if (chars == 0) return false;

    if (chars < 9) return false;
    if (!ascii_case_iequal(path->Buffer[0], L'\\')) return false;
    if (!unicode_starts_with_literal_i(path, L"\\Device\\")) return false;

    ULONG idx = 8;
    ULONG slash_count = 0;
    while (idx < chars) {
        WCHAR c = path->Buffer[idx];
        if (c == L'\\' || c == L'/') {
            ++slash_count;
            if (slash_count > 1) {
                return false;
            }
        }
        ++idx;
    }
    if (slash_count == 0) {
        return true;
    }
    if (slash_count == 1
        && (path->Buffer[chars - 1] == L'\\' || path->Buffer[chars - 1] == L'/')) {
        return true;
    }
    return false;
}

NTSTATUS shadow_path_build(
    PCUNICODE_STRING sandbox_root,
    PCUNICODE_STRING original_path,
    PUNICODE_STRING shadow_path)
{
    if (sandbox_root == nullptr || original_path == nullptr || shadow_path == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    if (sandbox_root->Buffer == nullptr || original_path->Buffer == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING trimmed_root = *sandbox_root;
    if (trimmed_root.Length >= sizeof(WCHAR)) {
        ULONG last_char = (trimmed_root.Length / sizeof(WCHAR)) - 1;
        if (trimmed_root.Buffer[last_char] == L'\\') {
            trimmed_root.Length -= sizeof(WCHAR);
        }
    }

    PCUNICODE_STRING orig = original_path;
    UNICODE_STRING rel;
    rel.Buffer = orig->Buffer;
    rel.Length = orig->Length;
    rel.MaximumLength = orig->MaximumLength;

    ULONG orig_chars = orig->Length / sizeof(WCHAR);
    ULONG i = 0;
    if (orig_chars >= 8) {
        const WCHAR* p = orig->Buffer;
        if ((p[0] == L'\\' || p[0] == L'/') &&
            ascii_case_iequal(p[1], L'D') && ascii_case_iequal(p[2], L'e') &&
            ascii_case_iequal(p[3], L'v') && ascii_case_iequal(p[4], L'i') &&
            ascii_case_iequal(p[5], L'c') && ascii_case_iequal(p[6], L'e') &&
            (p[7] == L'\\' || p[7] == L'/')) {
            i = 8;
            ULONG slash_count = 0;
            while (i < orig_chars) {
                WCHAR c = orig->Buffer[i];
                if (c == L'\\' || c == L'/') {
                    ++slash_count;
                    if (slash_count == 1) {
                        break;
                    }
                }
                ++i;
            }
        }
    }

    if (i < orig_chars) {
        rel.Buffer = orig->Buffer + i;
        rel.Length = static_cast<USHORT>((orig_chars - i) * sizeof(WCHAR));
        rel.MaximumLength = rel.Length;
    } else {
        rel.Buffer = orig->Buffer;
        rel.Length = orig->Length;
        rel.MaximumLength = orig->Length;
    }

    USHORT need_bytes = static_cast<USHORT>(
        trimmed_root.Length
        + k_cow_suffix_chars * sizeof(WCHAR)
        + rel.Length
        + sizeof(WCHAR));

    if (need_bytes < trimmed_root.Length || need_bytes >= 0x8000) {
        return STATUS_NAME_TOO_LONG;
    }

    PWCHAR buf = static_cast<PWCHAR>(
        ExAllocatePool2(POOL_FLAG_PAGED, need_bytes, SHADOW_TAG_PATH));
    if (buf == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    USHORT pos_bytes = 0;
    RtlCopyMemory(buf, trimmed_root.Buffer, trimmed_root.Length);
    pos_bytes = trimmed_root.Length;

    RtlCopyMemory(reinterpret_cast<PUCHAR>(buf) + pos_bytes,
                  k_cow_suffix,
                  k_cow_suffix_chars * sizeof(WCHAR));
    pos_bytes += static_cast<USHORT>(k_cow_suffix_chars * sizeof(WCHAR));

    if (rel.Length > 0) {
        bool needs_sep = (rel.Buffer[0] != L'\\' && rel.Buffer[0] != L'/');
        if (needs_sep) {
            *reinterpret_cast<PWCHAR>(reinterpret_cast<PUCHAR>(buf) + pos_bytes) = L'\\';
            pos_bytes += sizeof(WCHAR);
        }
        RtlCopyMemory(reinterpret_cast<PUCHAR>(buf) + pos_bytes,
                      rel.Buffer,
                      rel.Length);
        pos_bytes += rel.Length;
    }

    *reinterpret_cast<PWCHAR>(reinterpret_cast<PUCHAR>(buf) + pos_bytes) = L'\0';

    shadow_path->Buffer = buf;
    shadow_path->Length = pos_bytes;
    shadow_path->MaximumLength = need_bytes;
    return STATUS_SUCCESS;
}

bool shadow_path_compute_shadow_dir(
    PCUNICODE_STRING sandbox_root,
    PCUNICODE_STRING directory_path,
    PUNICODE_STRING out_shadow_dir)
{
    if (out_shadow_dir == nullptr) return false;
    out_shadow_dir->Buffer = nullptr;
    out_shadow_dir->Length = 0;
    out_shadow_dir->MaximumLength = 0;
    NTSTATUS s = shadow_path_build(sandbox_root, directory_path, out_shadow_dir);
    return NT_SUCCESS(s);
}

NTSTATUS shadow_ensure_parent_directories(PCUNICODE_STRING path) {
    if (path == nullptr || path->Buffer == nullptr || path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG chars = path->Length / sizeof(WCHAR);
    if (chars == 0) return STATUS_SUCCESS;

    ULONG last_sep = 0;
    bool have_sep = false;
    for (ULONG i = 0; i < chars; ++i) {
        if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/') {
            last_sep = i;
            have_sep = true;
        }
    }
    if (!have_sep) return STATUS_SUCCESS;
    if (last_sep == 0) return STATUS_SUCCESS;

    USHORT parent_bytes = static_cast<USHORT>(last_sep * sizeof(WCHAR));
    PWCHAR scratch = static_cast<PWCHAR>(
        ExAllocatePool2(POOL_FLAG_PAGED, parent_bytes + sizeof(WCHAR), SHADOW_TAG_PATH));
    if (scratch == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(scratch, path->Buffer, parent_bytes);
    scratch[last_sep] = L'\0';

    ULONG cursor = 0;
    while (cursor < last_sep) {
        ULONG seg_end = cursor;
        while (seg_end < last_sep && scratch[seg_end] != L'\\' && scratch[seg_end] != L'/') {
            ++seg_end;
        }
        if (seg_end == cursor) {
            ++cursor;
            continue;
        }

        WCHAR saved = scratch[seg_end];
        scratch[seg_end] = L'\0';

        if (seg_end > 8) {
            UNICODE_STRING segment;
            segment.Buffer = scratch;
            segment.Length = static_cast<USHORT>(seg_end * sizeof(WCHAR));
            segment.MaximumLength = segment.Length;

            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, &segment,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

            HANDLE dirh = NULL;
            IO_STATUS_BLOCK iosb = {};
            NTSTATUS s = ZwCreateFile(
                &dirh,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                &oa,
                &iosb,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN_IF,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0);
            if (NT_SUCCESS(s) && dirh != NULL) {
                if (iosb.Information == FILE_CREATED) {
                    SHADOW_LOG_INFO("ensure_parent_directories created segment='%wZ'", &segment);
                }
                ZwClose(dirh);
            } else if (!NT_SUCCESS(s)) {
                SHADOW_LOG_WARN("ensure_parent_directories ZwCreateFile FAILED segment='%wZ' status=0x%08lX",
                    &segment, s);
            }
        }

        scratch[seg_end] = saved;
        cursor = seg_end + 1;
    }

    ExFreePoolWithTag(scratch, SHADOW_TAG_PATH);
    return STATUS_SUCCESS;
}

bool shadow_directory_exists(
    PFLT_FILTER filter,
    PFLT_INSTANCE instance,
    PCUNICODE_STRING path)
{
    if (filter == nullptr || instance == nullptr) return false;
    if (path == nullptr || path->Buffer == nullptr || path->Length == 0) return false;

    HANDLE h = nullptr;
    PFILE_OBJECT fo = nullptr;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb = {};
    InitializeObjectAttributes(&oa,
        const_cast<PUNICODE_STRING>(path),
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);

    NTSTATUS s = FltCreateFileEx(
        filter,
        instance,
        &h,
        &fo,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
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
    if (NT_SUCCESS(s)) {
        if (h != nullptr) FltClose(h);
        if (fo != nullptr) ObDereferenceObject(fo);
        return true;
    }
    return false;
}

NTSTATUS shadow_create_empty_shadow(
    PFLT_FILTER filter,
    PFLT_INSTANCE instance,
    PCUNICODE_STRING shadow)
{
    if (filter == nullptr || instance == nullptr || shadow == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    if (shadow->Buffer == nullptr) return STATUS_INVALID_PARAMETER;

    NTSTATUS pdir = shadow_ensure_parent_directories(shadow);
    if (!NT_SUCCESS(pdir)) {
        SHADOW_LOG_WARN("create_empty_shadow ensure_parent_FAILED shadow='%wZ' status=0x%08lX",
            shadow, pdir);
    }

    HANDLE h = nullptr;
    PFILE_OBJECT fo = nullptr;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb = {};
    InitializeObjectAttributes(&oa,
        const_cast<PUNICODE_STRING>(shadow),
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);

    NTSTATUS s = FltCreateFileEx(
        filter,
        instance,
        &h,
        &fo,
        FILE_GENERIC_WRITE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (NT_SUCCESS(s)) {
        SHADOW_LOG_INFO("create_empty_shadow ok shadow='%wZ' info=%lu",
            shadow, (unsigned long)iosb.Information);
        if (h != nullptr) FltClose(h);
        if (fo != nullptr) ObDereferenceObject(fo);
        return STATUS_SUCCESS;
    }

    SHADOW_LOG_WARN("create_empty_shadow FAILED shadow='%wZ' status=0x%08lX", shadow, s);
    return s;
}

namespace {
    bool query_basic_info(
        PFLT_INSTANCE instance,
        PFILE_OBJECT fo,
        FILE_BASIC_INFORMATION* out_basic)
    {
        if (out_basic == nullptr) return false;
        RtlZeroMemory(out_basic, sizeof(*out_basic));
        ULONG ret_len = 0;
        NTSTATUS s = FltQueryInformationFile(
            instance,
            fo,
            out_basic,
            sizeof(*out_basic),
            FileBasicInformation,
            &ret_len);
        if (!NT_SUCCESS(s)) {
            return false;
        }
        return true;
    }

    void apply_basic_info(
        PFLT_INSTANCE instance,
        PFILE_OBJECT fo,
        const FILE_BASIC_INFORMATION& basic)
    {
        FILE_BASIC_INFORMATION copy = basic;
        ULONG ret_len = 0;
        NTSTATUS s = FltSetInformationFile(
            instance,
            fo,
            &copy,
            sizeof(copy),
            FileBasicInformation);
        UNREFERENCED_PARAMETER(ret_len);
        if (!NT_SUCCESS(s)) {
            SHADOW_LOG_WARN("apply_basic_info FltSetInformationFile FAILED status=0x%08lX", s);
        }
    }
}

NTSTATUS shadow_copy_original_to_shadow_ex(
    PFLT_FILTER filter,
    PFLT_INSTANCE instance,
    PCUNICODE_STRING original,
    PCUNICODE_STRING shadow,
    bool only_if_exists,
    SHADOW_COPY_RESULT* out_result)
{
    if (out_result != nullptr) {
        RtlZeroMemory(out_result, sizeof(*out_result));
    }

    if (filter == nullptr || instance == nullptr || original == nullptr || shadow == nullptr) {
        if (out_result) out_result->status = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }
    if (original->Buffer == nullptr || shadow->Buffer == nullptr) {
        if (out_result) out_result->status = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = shadow_ensure_parent_directories(shadow);
    if (!NT_SUCCESS(status)) {
        SHADOW_LOG_WARN("copy_original_to_shadow ensure_parent FAILED status=0x%08lX shadow='%wZ'",
            status, shadow);
        if (out_result) out_result->status = status;
        return status;
    }

    HANDLE src_handle = NULL;
    PFILE_OBJECT src_object = NULL;
    OBJECT_ATTRIBUTES src_oa;
    IO_STATUS_BLOCK iosb = {};
    InitializeObjectAttributes(&src_oa,
        const_cast<PUNICODE_STRING>(original),
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);

    status = FltCreateFileEx(
        filter,
        instance,
        &src_handle,
        &src_object,
        FILE_GENERIC_READ,
        &src_oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND
            || status == STATUS_OBJECT_PATH_NOT_FOUND
            || status == STATUS_NO_SUCH_FILE) {
            if (out_result) {
                out_result->status = STATUS_SUCCESS;
                out_result->original_existed = 0;
            }
            return STATUS_SUCCESS;
        }
        if (out_result) out_result->status = status;
        SHADOW_LOG_WARN("copy_original_to_shadow open_src_FAILED original='%wZ' status=0x%08lX",
            original, status);
        return status;
    }

    {
        FILE_ATTRIBUTE_TAG_INFORMATION tag_info = {};
        ULONG tag_ret = 0;
        NTSTATUS tag_s = FltQueryInformationFile(
            instance,
            src_object,
            &tag_info,
            sizeof(tag_info),
            FileAttributeTagInformation,
            &tag_ret);
        if (NT_SUCCESS(tag_s)
            && (tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            FltClose(src_handle);
            ObDereferenceObject(src_object);
            if (out_result) {
                out_result->status = STATUS_SUCCESS;
                out_result->original_existed = 1;
                out_result->is_reparse_point = 1;
            }
            SHADOW_LOG_INFO("copy_original_to_shadow source_is_reparse_point original='%wZ' (skipping copy)",
                original);
            return STATUS_SUCCESS;
        }
    }
    if (out_result) out_result->original_existed = 1;
    UNREFERENCED_PARAMETER(only_if_exists);

    LARGE_INTEGER end_of_file = {};
    FILE_STANDARD_INFORMATION std_info = {};
    NTSTATUS qst = FltQueryInformationFile(
        instance,
        src_object,
        &std_info,
        sizeof(std_info),
        FileStandardInformation,
        NULL);
    if (NT_SUCCESS(qst)) {
        end_of_file = std_info.EndOfFile;
    }

    FILE_BASIC_INFORMATION src_basic = {};
    bool have_src_basic = query_basic_info(instance, src_object, &src_basic);

    HANDLE dst_handle = NULL;
    PFILE_OBJECT dst_object = NULL;
    OBJECT_ATTRIBUTES dst_oa;
    IO_STATUS_BLOCK diosb = {};
    InitializeObjectAttributes(&dst_oa,
        const_cast<PUNICODE_STRING>(shadow),
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);

    status = FltCreateFileEx(
        filter,
        instance,
        &dst_handle,
        &dst_object,
        FILE_GENERIC_WRITE,
        &dst_oa,
        &diosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);
    if (!NT_SUCCESS(status)) {
        FltClose(src_handle);
        ObDereferenceObject(src_object);
        if (out_result) out_result->status = status;
        SHADOW_LOG_WARN("copy_original_to_shadow open_dst_FAILED shadow='%wZ' status=0x%08lX",
            shadow, status);
        return status;
    }
    if (out_result) {
        out_result->shadow_created = (diosb.Information == FILE_CREATED) ? 1 : 0;
    }

    bool needs_copy = false;
    if (diosb.Information == FILE_CREATED) {
        needs_copy = true;
    } else {
        FILE_STANDARD_INFORMATION dst_info = {};
        NTSTATUS dqst = FltQueryInformationFile(
            instance,
            dst_object,
            &dst_info,
            sizeof(dst_info),
            FileStandardInformation,
            NULL);
        if (NT_SUCCESS(dqst) && dst_info.EndOfFile.QuadPart == 0 && end_of_file.QuadPart > 0) {
            needs_copy = true;
        }
    }

    LONG64 total_copied = 0;
    if (needs_copy && end_of_file.QuadPart > 0) {
        const ULONG chunk = 256 * 1024;
        PUCHAR chunk_buf = static_cast<PUCHAR>(
            ExAllocatePool2(POOL_FLAG_PAGED, chunk, SHADOW_TAG_BUF));
        if (chunk_buf == nullptr) {
            FltClose(dst_handle);
            ObDereferenceObject(dst_object);
            FltClose(src_handle);
            ObDereferenceObject(src_object);
            if (out_result) out_result->status = STATUS_INSUFFICIENT_RESOURCES;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        LARGE_INTEGER offset = {};
        LONGLONG remaining = end_of_file.QuadPart;
        NTSTATUS chunk_status = STATUS_SUCCESS;
        while (remaining > 0) {
            ULONG to_read = chunk;
            if (static_cast<LONGLONG>(to_read) > remaining) {
                to_read = static_cast<ULONG>(remaining);
            }
            ULONG bytes_read = 0;
            chunk_status = FltReadFile(
                instance,
                src_object,
                &offset,
                to_read,
                chunk_buf,
                FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                &bytes_read,
                NULL,
                NULL);
            if (!NT_SUCCESS(chunk_status) || bytes_read == 0) {
                break;
            }

            ULONG bytes_written = 0;
            chunk_status = FltWriteFile(
                instance,
                dst_object,
                &offset,
                bytes_read,
                chunk_buf,
                FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                &bytes_written,
                NULL,
                NULL);
            if (!NT_SUCCESS(chunk_status) || bytes_written != bytes_read) {
                if (NT_SUCCESS(chunk_status)) chunk_status = STATUS_FILE_CORRUPT_ERROR;
                break;
            }
            offset.QuadPart += bytes_read;
            remaining -= bytes_read;
            total_copied += static_cast<LONG64>(bytes_read);
        }

        ExFreePoolWithTag(chunk_buf, SHADOW_TAG_BUF);
        if (NT_SUCCESS(chunk_status) && total_copied > 0) {
            shadow_stats_inc_copies();
            shadow_stats_add_bytes_copied(total_copied);
        }
        status = chunk_status;
    }

    if (NT_SUCCESS(status) && have_src_basic) {
        apply_basic_info(instance, dst_object, src_basic);
    }

    FltClose(dst_handle);
    ObDereferenceObject(dst_object);
    FltClose(src_handle);
    ObDereferenceObject(src_object);

    if (out_result) {
        out_result->status = status;
        out_result->bytes_copied = total_copied;
    }
    return status;
}

NTSTATUS shadow_copy_original_to_shadow(
    PFLT_FILTER filter,
    PFLT_INSTANCE instance,
    PCUNICODE_STRING original,
    PCUNICODE_STRING shadow)
{
    SHADOW_COPY_RESULT res = {};
    return shadow_copy_original_to_shadow_ex(filter, instance, original, shadow, false, &res);
}
