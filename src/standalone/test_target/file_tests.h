#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdint>
#include <atomic>

namespace test_target {
namespace file_io {

struct config_t {
    bool verbose;
};

void run_all(const config_t& cfg, std::atomic<bool>& running);

void test_text_file(const config_t& cfg);
void test_binary_file(const config_t& cfg);
void test_large_file(const config_t& cfg);
void test_rename_copy_delete(const config_t& cfg);
void test_directory_ops(const config_t& cfg);
void test_memory_mapped(const config_t& cfg);
void test_file_locking(const config_t& cfg);
void test_readonly_file(const config_t& cfg);
void test_hidden_file(const config_t& cfg);
void cleanup_test_files(const config_t& cfg);

}
}
