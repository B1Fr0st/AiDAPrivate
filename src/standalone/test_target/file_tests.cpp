#include "file_tests.h"
#include "test_log.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace test_target {
namespace file_io {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[FILE] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static wchar_t s_test_dir[MAX_PATH] = {0};

static void ensure_test_dir() {
    if (s_test_dir[0] != L'\0') return;

    wchar_t temp[MAX_PATH];
    GetTempPathW(MAX_PATH, temp);
    wsprintfW(s_test_dir, L"%saida_test_target\\", temp);

    CreateDirectoryW(s_test_dir, nullptr);
    log("Test directory: %S", s_test_dir);
}

static void build_path(wchar_t* out, int out_max, const wchar_t* filename) {
    ensure_test_dir();
    wsprintfW(out, L"%s%s", s_test_dir, filename);
}

#pragma optimize("", off)

void __declspec(noinline) test_text_file(const config_t& cfg) {
    log("Text file test starting...");
    ensure_test_dir();

    wchar_t path[MAX_PATH];
    build_path(path, MAX_PATH, L"test_text.txt");

    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        log("Failed to create text file: %lu", GetLastError());
        return;
    }

    const char* lines[] = {
        "AiDA Test Target - Text File Test\r\n",
        "Line 2: The quick brown fox jumps over the lazy dog.\r\n",
        "Line 3: ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n",
        "Line 4: 0123456789 !@#$%^&*()\r\n",
        "Line 5: Unicode test placeholder\r\n",
        "Line 6: Hex: 0xDEADBEEF 0xCAFEBABE\r\n",
        "Line 7: Lorem ipsum dolor sit amet.\r\n",
        "Line 8: AiDA_TestTarget_TextFile_Marker\r\n",
        "Line 9: End of test data.\r\n",
    };

    DWORD total_written = 0;
    for (int i = 0; i < 9; ++i) {
        DWORD written = 0;
        WriteFile(hFile, lines[i], (DWORD)strlen(lines[i]), &written, nullptr);
        total_written += written;
    }

    CloseHandle(hFile);
    log("Wrote text file '%S' (%lu bytes)", path, total_written);

    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        char buf[2048] = {0};
        DWORD read_bytes = 0;
        ReadFile(hFile, buf, sizeof(buf) - 1, &read_bytes, nullptr);
        CloseHandle(hFile);
        log("Read back %lu bytes from text file", read_bytes);

        if (strstr(buf, "AiDA Test Target") != nullptr) {
            log("Text file content verification: PASS");
        } else {
            log("Text file content verification: FAIL");
        }
    }

    log("Text file test complete");
}

void __declspec(noinline) test_binary_file(const config_t& cfg) {
    log("Binary file test starting...");
    ensure_test_dir();

    wchar_t path[MAX_PATH];
    build_path(path, MAX_PATH, L"test_binary.bin");

    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        log("Failed to create binary file: %lu", GetLastError());
        return;
    }

    uint8_t header[16] = { 'A','I','D','A', 0x00,0x01, 0xDE,0xAD,0xBE,0xEF, 0xCA,0xFE,0xBA,0xBE, 0x00,0x00 };
    DWORD written = 0;
    WriteFile(hFile, header, 16, &written, nullptr);

    uint8_t pattern[256];
    for (int i = 0; i < 256; ++i) pattern[i] = (uint8_t)i;
    WriteFile(hFile, pattern, 256, &written, nullptr);

    uint8_t repeat[64];
    for (int i = 0; i < 64; ++i) repeat[i] = (uint8_t)(i ^ 0xAA);
    WriteFile(hFile, repeat, 64, &written, nullptr);

    CloseHandle(hFile);

    DWORD file_size = 16 + 256 + 64;
    log("Wrote binary file '%S' (%lu bytes)", path, file_size);

    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        uint8_t read_header[16] = {0};
        DWORD read_bytes = 0;
        ReadFile(hFile, read_header, 16, &read_bytes, nullptr);
        CloseHandle(hFile);

        int match = (memcmp(read_header, header, 16) == 0);
        log("Binary file header verification: %s", match ? "PASS" : "FAIL");
    }

    log("Binary file test complete");
}

void __declspec(noinline) test_large_file(const config_t& cfg) {
    log("Large file test starting (64KB)...");
    ensure_test_dir();

    wchar_t path[MAX_PATH];
    build_path(path, MAX_PATH, L"test_large.bin");

    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        log("Failed to create large file: %lu", GetLastError());
        return;
    }


    uint8_t block[4096];
    DWORD total = 0;
    for (int page = 0; page < 16; ++page) {
        for (int i = 0; i < 4096; ++i)
            block[i] = (uint8_t)((i + page * 4096) & 0xFF);
        DWORD written = 0;
        WriteFile(hFile, block, 4096, &written, nullptr);
        total += written;
    }

    CloseHandle(hFile);
    log("Wrote large file '%S' (%lu bytes)", path, total);


    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER file_size;
        GetFileSizeEx(hFile, &file_size);
        CloseHandle(hFile);
        log("Large file size: %lld bytes (expected 65536)", file_size.QuadPart);
        log("Large file size verification: %s", file_size.QuadPart == 65536 ? "PASS" : "FAIL");
    }

    log("Large file test complete");
}

void __declspec(noinline) test_rename_copy_delete(const config_t& cfg) {
    log("Rename/copy/delete test starting...");
    ensure_test_dir();

    wchar_t src[MAX_PATH], dst_rename[MAX_PATH], dst_copy[MAX_PATH];
    build_path(src, MAX_PATH, L"test_rename_src.txt");
    build_path(dst_rename, MAX_PATH, L"test_rename_dst.txt");
    build_path(dst_copy, MAX_PATH, L"test_copy_dst.txt");


    HANDLE hFile = CreateFileW(src, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        const char* data = "AiDA rename/copy test data";
        DWORD written = 0;
        WriteFile(hFile, data, (DWORD)strlen(data), &written, nullptr);
        CloseHandle(hFile);
        log("Created source file '%S' (%lu bytes)", src, written);
    }


    if (CopyFileW(src, dst_copy, FALSE)) {
        log("CopyFile '%S' -> '%S': SUCCESS", src, dst_copy);
    } else {
        log("CopyFile failed: %lu", GetLastError());
    }


    if (MoveFileW(src, dst_rename)) {
        log("MoveFile '%S' -> '%S': SUCCESS", src, dst_rename);
    } else {
        log("MoveFile failed: %lu", GetLastError());
    }


    DWORD attrs = GetFileAttributesW(dst_rename);
    log("Renamed file exists: %s", (attrs != INVALID_FILE_ATTRIBUTES) ? "YES" : "NO");


    DeleteFileW(dst_rename);
    DeleteFileW(dst_copy);
    log("Deleted renamed and copied files");


    attrs = GetFileAttributesW(dst_rename);
    log("Renamed file after delete: %s", (attrs == INVALID_FILE_ATTRIBUTES) ? "GONE" : "STILL EXISTS");

    log("Rename/copy/delete test complete");
}

void __declspec(noinline) test_directory_ops(const config_t& cfg) {
    log("Directory operations test starting...");
    ensure_test_dir();

    wchar_t subdir[MAX_PATH], subsubdir[MAX_PATH];
    build_path(subdir, MAX_PATH, L"subdir_test\\");
    wsprintfW(subsubdir, L"%snested\\", subdir);


    CreateDirectoryW(subdir, nullptr);
    CreateDirectoryW(subsubdir, nullptr);
    log("Created directories: %S and %S", subdir, subsubdir);


    for (int i = 0; i < 5; ++i) {
        wchar_t filepath[MAX_PATH];
        wsprintfW(filepath, L"%sfile_%d.txt", subdir, i);
        HANDLE h = CreateFileW(filepath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            char data[64];
            sprintf_s(data, sizeof(data), "Subdir file %d content", i);
            DWORD written = 0;
            WriteFile(h, data, (DWORD)strlen(data), &written, nullptr);
            CloseHandle(h);
        }
    }
    log("Created 5 files in subdirectory");


    wchar_t search_pattern[MAX_PATH];
    wsprintfW(search_pattern, L"%s*", subdir);

    WIN32_FIND_DATAW find_data;
    HANDLE hFind = FindFirstFileW(search_pattern, &find_data);
    int file_count = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(find_data.cFileName, L".") != 0 && wcscmp(find_data.cFileName, L"..") != 0) {
                const wchar_t* type = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? L"DIR" : L"FILE";
                log("  [%S] %S (size=%lu)", type, find_data.cFileName, find_data.nFileSizeLow);
                file_count++;
            }
        } while (FindNextFileW(hFind, &find_data));
        FindClose(hFind);
    }
    log("Enumerated %d entries in subdirectory", file_count);


    for (int i = 0; i < 5; ++i) {
        wchar_t filepath[MAX_PATH];
        wsprintfW(filepath, L"%sfile_%d.txt", subdir, i);
        DeleteFileW(filepath);
    }
    RemoveDirectoryW(subsubdir);
    RemoveDirectoryW(subdir);
    log("Cleaned up subdirectory tree");

    log("Directory operations test complete");
}

void __declspec(noinline) test_memory_mapped(const config_t& cfg) {
    log("Memory-mapped file test starting...");
    ensure_test_dir();

    wchar_t path[MAX_PATH];
    build_path(path, MAX_PATH, L"test_mmap.bin");


    HANDLE hFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        log("Failed to create mmap file: %lu", GetLastError());
        return;
    }


    uint8_t data[4096];
    for (int i = 0; i < 4096; ++i) data[i] = (uint8_t)(i * 3 + 17);
    DWORD written = 0;
    WriteFile(hFile, data, 4096, &written, nullptr);
    log("Wrote 4096 bytes to mmap file");


    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READWRITE, 0, 4096, L"AiDA_TestTarget_MMap");
    if (!hMap) {
        log("CreateFileMapping failed: %lu", GetLastError());
        CloseHandle(hFile);
        return;
    }
    log("Created file mapping handle=%p", hMap);


    void* view = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
    if (!view) {
        log("MapViewOfFile failed: %lu", GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return;
    }
    log("Mapped view at %p (4096 bytes)", view);


    int match = (memcmp(view, data, 4096) == 0);
    log("Memory-mapped content verification: %s", match ? "PASS" : "FAIL");


    uint8_t* mapped = (uint8_t*)view;
    mapped[0] = 0xAA;
    mapped[1] = 0xBB;
    mapped[2] = 0xCC;
    mapped[3] = 0xDD;
    log("Modified first 4 bytes via mapping: AA BB CC DD");


    FlushViewOfFile(view, 4096);
    log("Flushed mapped view");

    UnmapViewOfFile(view);
    CloseHandle(hMap);
    CloseHandle(hFile);


    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        uint8_t check[4] = {0};
        DWORD read_bytes = 0;
        ReadFile(hFile, check, 4, &read_bytes, nullptr);
        CloseHandle(hFile);
        log("Persisted bytes: %02X %02X %02X %02X (expected AA BB CC DD)",
            check[0], check[1], check[2], check[3]);
    }

    log("Memory-mapped file test complete");
}

void __declspec(noinline) test_file_locking(const config_t& cfg) {
    log("File locking test starting...");
    ensure_test_dir();

    wchar_t path[MAX_PATH];
    build_path(path, MAX_PATH, L"test_lock.bin");

    HANDLE hFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        log("Failed to create lock file: %lu", GetLastError());
        return;
    }


    uint8_t data[1024];
    for (int i = 0; i < 1024; ++i) data[i] = (uint8_t)(i & 0xFF);
    DWORD written = 0;
    WriteFile(hFile, data, 1024, &written, nullptr);


    BOOL locked = LockFile(hFile, 0, 0, 512, 0);
    log("LockFile(0-512): %s", locked ? "SUCCESS" : "FAILED");


    BOOL locked2 = LockFile(hFile, 512, 0, 512, 0);
    log("LockFile(512-1024): %s", locked2 ? "SUCCESS" : "FAILED");


    if (locked) {
        UnlockFile(hFile, 0, 0, 512, 0);
        log("UnlockFile(0-512): SUCCESS");
    }
    if (locked2) {
        UnlockFile(hFile, 512, 0, 512, 0);
        log("UnlockFile(512-1024): SUCCESS");
    }

    CloseHandle(hFile);
    log("File locking test complete");
}

void __declspec(noinline) test_readonly_file(const config_t& cfg) {
    log("Read-only file test starting...");
    ensure_test_dir();

    wchar_t path[MAX_PATH];
    build_path(path, MAX_PATH, L"test_readonly.txt");


    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        const char* data = "AiDA read-only test file";
        DWORD written = 0;
        WriteFile(hFile, data, (DWORD)strlen(data), &written, nullptr);
        CloseHandle(hFile);
        log("Created file '%S'", path);
    }


    SetFileAttributesW(path, FILE_ATTRIBUTE_READONLY);
    log("Set FILE_ATTRIBUTE_READONLY on '%S'", path);


    DWORD attrs = GetFileAttributesW(path);
    log("File attributes: 0x%08X (readonly=%s)",
        attrs, (attrs & FILE_ATTRIBUTE_READONLY) ? "YES" : "NO");


    HANDLE hFile2 = CreateFileW(path, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile2 == INVALID_HANDLE_VALUE) {
        log("Write access to read-only file: correctly denied (error=%lu)", GetLastError());
    } else {
        log("Write access to read-only file: unexpectedly succeeded");
        CloseHandle(hFile2);
    }


    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    log("Restored normal attributes for cleanup");

    log("Read-only file test complete");
}

void __declspec(noinline) test_hidden_file(const config_t& cfg) {
    log("Hidden file test starting...");
    ensure_test_dir();

    wchar_t path[MAX_PATH];
    build_path(path, MAX_PATH, L"test_hidden.txt");


    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        const char* data = "AiDA hidden file test";
        DWORD written = 0;
        WriteFile(hFile, data, (DWORD)strlen(data), &written, nullptr);
        CloseHandle(hFile);
        log("Created hidden file '%S'", path);
    }


    DWORD attrs = GetFileAttributesW(path);
    log("File attributes: 0x%08X (hidden=%s)",
        attrs, (attrs & FILE_ATTRIBUTE_HIDDEN) ? "YES" : "NO");


    wchar_t search[MAX_PATH];
    build_path(search, MAX_PATH, L"*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    int hidden_found = 0;
    int total_found = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            total_found++;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
                hidden_found++;
                log("  Found hidden: %S", fd.cFileName);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    log("Directory scan: %d total, %d hidden", total_found, hidden_found);


    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);

    log("Hidden file test complete");
}

void __declspec(noinline) cleanup_test_files(const config_t& cfg) {
    log("Cleaning up test files...");

    if (s_test_dir[0] == L'\0') {
        log("No test directory to clean");
        return;
    }

    const wchar_t* files[] = {
        L"test_text.txt", L"test_binary.bin", L"test_large.bin",
        L"test_mmap.bin", L"test_lock.bin", L"test_readonly.txt",
        L"test_hidden.txt",
    };

    int deleted = 0;
    for (int i = 0; i < 7; ++i) {
        wchar_t path[MAX_PATH];
        build_path(path, MAX_PATH, files[i]);
        SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(path)) deleted++;
    }

    RemoveDirectoryW(s_test_dir);
    log("Cleanup: deleted %d files, removed test directory", deleted);
}

#pragma optimize("", on)

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== File I/O tests starting ===");

    test_text_file(cfg);
    test_binary_file(cfg);
    test_large_file(cfg);
    test_rename_copy_delete(cfg);
    test_directory_ops(cfg);
    test_memory_mapped(cfg);
    test_file_locking(cfg);
    test_readonly_file(cfg);
    test_hidden_file(cfg);
    cleanup_test_files(cfg);

    log("=== File I/O tests complete ===");
}

}
}
