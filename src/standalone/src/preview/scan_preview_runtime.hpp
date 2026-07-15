#pragma once

#include "../core/infra/taskflow_runtime.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <utility>

namespace aida::preview::scan {

struct receipt_t {
	std::uint64_t serial = 0;
	std::string action;
	std::string detail;
};

inline std::mutex g_receipt_mutex;
inline receipt_t g_receipt;

inline void record(std::string action, std::string detail)
{
	std::lock_guard<std::mutex> lock(g_receipt_mutex);
	++g_receipt.serial;
	g_receipt.action = std::move(action);
	g_receipt.detail = std::move(detail);
}

}
