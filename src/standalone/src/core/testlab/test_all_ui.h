#pragma once
#include <Windows.h>
#include <atomic>

namespace test_all_features {
    void phase_ui_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)());
}
