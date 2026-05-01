#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "work_queue.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "standalone_driver.hpp"
#include "embedded_resources.hpp"


#ifdef small
#  undef small
#endif
#ifdef near
#  undef near
#endif
#ifdef NEAR
#  undef NEAR
#  define NEAR
#endif
#ifdef far
#  undef far
#endif
#ifdef FAR
#  undef FAR
#  define FAR
#endif
#ifdef pascal
#  undef pascal
#endif
#ifdef cdecl
#  undef cdecl
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "libdecomp.hh"
#include "sleigh_arch.hh"
#include "loadimage.hh"
#include "architecture.hh"
#include "action.hh"
#include "funcdata.hh"
#include "printc.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace ghidra_decompiler {


struct ghidra_result_t {
	uint64_t function_addr = 0;
	std::string function_name;
	std::string pseudocode;
	bool complete = false;
	bool is_error = false;
	std::string error_text;
	double elapsed_ms = 0.0;
};


struct batch_entry_t {
	uint64_t address = 0;
	ghidra_result_t result;
};


inline std::atomic<bool>* s_cancel_ptr = nullptr;


class aida_buffer_load_image_t : public ghidra::LoadImage {
	const uint8_t* buf_;
	size_t buf_size_;
	uint64_t base_addr_;

public:
	aida_buffer_load_image_t(const uint8_t* data, size_t size, uint64_t base)
		: ghidra::LoadImage("aida_buffer"), buf_(data), buf_size_(size), base_addr_(base) {}

	void loadFill(ghidra::uint1* ptr, ghidra::int4 size, const ghidra::Address& addr) override {
		if (s_cancel_ptr && s_cancel_ptr->load(std::memory_order_acquire)) {
			std::memset(ptr, 0, static_cast<size_t>(size));
			return;
		}

		uint64_t offset = addr.getOffset();
		std::memset(ptr, 0, static_cast<size_t>(size));

		if (offset >= base_addr_ && offset < base_addr_ + buf_size_) {
			size_t buf_off = static_cast<size_t>(offset - base_addr_);
			size_t avail = buf_size_ - buf_off;
			size_t to_copy = (std::min)(static_cast<size_t>(size), avail);
			std::memcpy(ptr, buf_ + buf_off, to_copy);
		}
	}

	std::string getArchType(void) const override {
		return "x86:LE:64:default";
	}

	void adjustVma(long) override {}
};


class aida_architecture_t : public ghidra::SleighArchitecture {
	ghidra::LoadImage* custom_loader_;

public:
	aida_architecture_t(ghidra::LoadImage* loader, const std::string& targ, std::ostream* err)
		: ghidra::SleighArchitecture("aida", targ, err), custom_loader_(loader) {}

	void buildLoader(ghidra::DocumentStorage&) override {
		loader = custom_loader_;
	}
};


struct state_t {
	std::mutex init_mtx;
	std::atomic<bool> initialized{false};
	std::string specs_dir;
	std::ostringstream err_stream;
};

inline state_t g_state;


namespace detail {

inline std::string get_exe_directory() {
	char path[MAX_PATH] = {};
	GetModuleFileNameA(nullptr, path, MAX_PATH);
	std::string full(path);
	auto pos = full.find_last_of("\\/");
	if (pos != std::string::npos)
		return full.substr(0, pos);
	return ".";
}

inline std::string find_specs_dir() {
	std::string exe_dir = get_exe_directory();
	std::string candidate = exe_dir + "\\ghidra_specs";
	DWORD attr = GetFileAttributesA(candidate.c_str());
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
		return candidate;

	candidate = exe_dir + "\\..\\ghidra_specs";
	attr = GetFileAttributesA(candidate.c_str());
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
		return candidate;

#ifdef GHIDRA_SPECS_DIR
#define AIDA_GHIDRA_SPECS_STR_IMPL(x) #x
#define AIDA_GHIDRA_SPECS_STR(x) AIDA_GHIDRA_SPECS_STR_IMPL(x)
	std::string cmake_dir = AIDA_GHIDRA_SPECS_STR(GHIDRA_SPECS_DIR);
	#undef AIDA_GHIDRA_SPECS_STR
	#undef AIDA_GHIDRA_SPECS_STR_IMPL
	attr = GetFileAttributesA(cmake_dir.c_str());
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
		return cmake_dir;
#endif

	return "";
}


static constexpr int WATCHDOG_TIMEOUT_MS = 10000;

inline ghidra_result_t do_decompile(aida_architecture_t* arch,
                                    uint64_t entry_addr,
                                    std::atomic<bool>* cancel = nullptr)
{
	ghidra_result_t result;
	result.function_addr = entry_addr;

	auto start_time = std::chrono::high_resolution_clock::now();

	ghidra::AddrSpace* code_space = arch->translate->getDefaultCodeSpace();
	if (!code_space) {
		result.is_error = true;
		result.error_text = "no default code space available";
		return result;
	}

	ghidra::Address addr(code_space, entry_addr);

	char name_buf[64];
	std::snprintf(name_buf, sizeof(name_buf), "sub_%llx",
	              static_cast<unsigned long long>(entry_addr));
	std::string func_name(name_buf);

	ghidra::Scope* global_scope = arch->symboltab->getGlobalScope();

	ghidra::Funcdata* fd = global_scope->queryFunction(addr);
	if (fd) {
		if (fd->isProcStarted())
			arch->clearAnalysis(fd);
	}
	else {
		ghidra::FunctionSymbol* sym = global_scope->addFunction(addr, func_name);
		fd = sym->getFunction();
	}

	if (fd->hasNoCode()) {
		result.is_error = true;
		result.error_text = "no code at the specified address";
		return result;
	}


	arch->allacts.getCurrent()->reset(*fd);

	std::atomic<bool> perform_done{false};
	std::atomic<bool> timed_out{false};
	ghidra::int4 perform_res = -1;


	std::atomic<bool> local_cancel{false};
	std::atomic<bool>* prev_cancel = s_cancel_ptr;
	s_cancel_ptr = &local_cancel;


	if (cancel && cancel->load(std::memory_order_acquire))
		local_cancel.store(true, std::memory_order_release);

	work_queue::post([&]() {
		try {
			perform_res = arch->allacts.getCurrent()->perform(*fd);
		} catch (...) {
			perform_res = -1;
		}
		perform_done.store(true, std::memory_order_release);
	});


	auto deadline = std::chrono::steady_clock::now() +
	                std::chrono::milliseconds(WATCHDOG_TIMEOUT_MS);

	while (!perform_done.load(std::memory_order_acquire)) {

		if (cancel && cancel->load(std::memory_order_acquire)) {
			local_cancel.store(true, std::memory_order_release);
		}

		if (std::chrono::steady_clock::now() >= deadline) {
			timed_out.store(true, std::memory_order_release);


			local_cancel.store(true, std::memory_order_release);

			auto grace = std::chrono::steady_clock::now() +
			             std::chrono::milliseconds(3000);
			while (!perform_done.load(std::memory_order_acquire)) {
				if (std::chrono::steady_clock::now() >= grace) {


					s_cancel_ptr = prev_cancel;
					result.is_error = true;
					result.error_text = "decompilation timed out (function too complex or obfuscated)";
					return result;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
			}
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}

	s_cancel_ptr = prev_cancel;

	if (timed_out.load()) {
		result.is_error = true;
		result.error_text = "decompilation timed out (function too complex or obfuscated)";
		return result;
	}

	if (cancel && cancel->load(std::memory_order_acquire)) {
		result.is_error = true;
		result.error_text = "decompilation cancelled";
		return result;
	}

	(void)perform_res;

	std::ostringstream oss;
	arch->print->setOutputStream(&oss);
	arch->print->docFunction(fd);

	result.pseudocode = oss.str();
	result.function_name = fd->getName();
	result.complete = true;

	auto end_time = std::chrono::high_resolution_clock::now();
	result.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

	return result;
}


struct temp_arch_t {
	std::unique_ptr<aida_buffer_load_image_t> loader;
	std::unique_ptr<aida_architecture_t> arch;
	std::ostringstream err;

	temp_arch_t(const uint8_t* data, size_t size, uint64_t base,
	            const std::string& specs_dir)
	{
		loader = std::make_unique<aida_buffer_load_image_t>(data, size, base);
		arch = std::make_unique<aida_architecture_t>(loader.get(), "x86:LE:64:default", &err);
		ghidra::DocumentStorage store;
		arch->init(store);
	}

	~temp_arch_t() = default;

	temp_arch_t(const temp_arch_t&) = delete;
	temp_arch_t& operator=(const temp_arch_t&) = delete;
};

}


inline bool init(const std::string& specs_dir = "") {
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	if (g_state.initialized.load())
		return true;

	std::string dir = specs_dir;
	if (dir.empty())
		dir = detail::find_specs_dir();


	if (dir.empty()) {
		dir = embedded_resources::extract_ghidra_specs();
		if (!dir.empty()) {

			static std::string s_temp_specs_dir;
			s_temp_specs_dir = dir;
			std::atexit([]() {
				embedded_resources::delete_specs_dir(s_temp_specs_dir);
			});
		}
	}

	if (dir.empty())
		return false;

	try {
		g_state.specs_dir = dir;
		std::vector<std::string> paths;
		paths.push_back(dir);
		ghidra::startDecompilerLibrary(paths);
		g_state.initialized.store(true);
		return true;
	}
	catch (ghidra::LowlevelError& err) {
		g_state.err_stream << "ghidra init error: " << err.explain << "\n";
		return false;
	}
	catch (ghidra::DecoderError& err) {
		g_state.err_stream << "ghidra decoder error: " << err.explain << "\n";
		return false;
	}
	catch (...) {
		g_state.err_stream << "ghidra init: unknown error\n";
		return false;
	}
}


inline ghidra_result_t decompile_function(uint64_t entry_addr,
                                          std::atomic<bool>* cancel = nullptr)
{
	ghidra_result_t result;
	result.function_addr = entry_addr;

	if (!g_state.initialized.load()) {
		if (!init()) {
			result.is_error = true;
			result.error_text = "ghidra decompiler not initialized: " + g_state.err_stream.str();
			return result;
		}
	}


	constexpr size_t PREREAD_SIZE = 0x40000;
	std::vector<uint8_t> mem;
	driver_bridge::read_memory(entry_addr, PREREAD_SIZE, mem);

	if (mem.empty()) {
		result.is_error = true;
		result.error_text = "failed to read memory at target address";
		return result;
	}

	try {
		detail::temp_arch_t ta(mem.data(), mem.size(), entry_addr, g_state.specs_dir);
		result = detail::do_decompile(ta.arch.get(), entry_addr, cancel);
	}
	catch (ghidra::LowlevelError& err) {
		result.is_error = true;
		result.error_text = err.explain;
	}
	catch (ghidra::DecoderError& err) {
		result.is_error = true;
		result.error_text = err.explain;
	}
	catch (...) {
		result.is_error = true;
		result.error_text = "unknown decompilation error";
	}

	return result;
}


inline ghidra_result_t decompile_buffer(const uint8_t* data, size_t size,
                                         uint64_t base_addr, uint64_t entry_addr,
                                         std::atomic<bool>* cancel = nullptr)
{
	ghidra_result_t result;
	result.function_addr = entry_addr;

	if (!g_state.initialized.load()) {
		if (!init()) {
			result.is_error = true;
			result.error_text = "ghidra decompiler not initialized";
			return result;
		}
	}

	try {
		detail::temp_arch_t ta(data, size, base_addr, g_state.specs_dir);
		result = detail::do_decompile(ta.arch.get(), entry_addr, cancel);
	}
	catch (ghidra::LowlevelError& e) {
		result.is_error = true;
		result.error_text = e.explain;
	}
	catch (ghidra::DecoderError& e) {
		result.is_error = true;
		result.error_text = e.explain;
	}
	catch (...) {
		result.is_error = true;
		result.error_text = "unknown decompilation error (buffer mode)";
	}

	return result;
}


inline bool preload_module(uint64_t base, size_t size, std::vector<uint8_t>& out) {
	out.clear();
	if (size == 0 || size > 0x10000000) return false;
	driver_bridge::read_memory(base, size, out);
	return !out.empty();
}


inline void batch_decompile(const uint8_t* buffer, size_t buf_size, uint64_t base,
                            const std::vector<uint64_t>& entries,
                            std::vector<ghidra_result_t>& results,
                            std::atomic<int>* progress = nullptr,
                            std::atomic<bool>* cancel = nullptr)
{
	results.clear();
	results.resize(entries.size());

	if (entries.empty()) return;

	if (!g_state.initialized.load()) {
		if (!init()) {
			for (auto& r : results) {
				r.is_error = true;
				r.error_text = "ghidra decompiler not initialized";
			}
			return;
		}
	}

	unsigned int num_threads = std::thread::hardware_concurrency();
	if (num_threads == 0) num_threads = 4;
	if (num_threads > static_cast<unsigned int>(entries.size()))
		num_threads = static_cast<unsigned int>(entries.size());


	std::vector<std::vector<size_t>> partitions(num_threads);
	for (size_t i = 0; i < entries.size(); ++i)
		partitions[i % num_threads].push_back(i);

	std::vector<std::thread> workers;
	workers.reserve(num_threads);

	for (unsigned int t = 0; t < num_threads; ++t) {
		workers.emplace_back([&, t]() {
			auto& my_indices = partitions[t];
			if (my_indices.empty()) return;


			std::unique_ptr<aida_buffer_load_image_t> w_loader;
			std::unique_ptr<aida_architecture_t> w_arch;
			std::ostringstream w_err;

			try {
				w_loader = std::make_unique<aida_buffer_load_image_t>(buffer, buf_size, base);
				w_arch = std::make_unique<aida_architecture_t>(w_loader.get(), "x86:LE:64:default", &w_err);
				ghidra::DocumentStorage store;
				w_arch->init(store);
				w_loader.release();
			}
			catch (...) {
				for (size_t idx : my_indices) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = "worker architecture init failed";
				}
				if (progress) progress->fetch_add(static_cast<int>(my_indices.size()),
				                                  std::memory_order_relaxed);
				return;
			}

			for (size_t idx : my_indices) {
				if (cancel && cancel->load(std::memory_order_acquire)) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = "cancelled";
					if (progress) progress->fetch_add(1, std::memory_order_relaxed);
					continue;
				}

				try {
					results[idx] = detail::do_decompile(w_arch.get(), entries[idx], cancel);
				}
				catch (ghidra::LowlevelError& err) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = err.explain;
				}
				catch (ghidra::DecoderError& err) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = err.explain;
				}
				catch (...) {
					results[idx].function_addr = entries[idx];
					results[idx].is_error = true;
					results[idx].error_text = "unknown error";
				}

				if (progress) progress->fetch_add(1, std::memory_order_relaxed);
			}
		});
	}

	for (auto& w : workers)
		w.join();
}


inline std::string last_error() {
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	return g_state.err_stream.str();
}

inline bool is_initialized() {
	return g_state.initialized.load();
}

inline void shutdown() {
	std::lock_guard<std::mutex> lk(g_state.init_mtx);
	if (!g_state.initialized.load())
		return;

	try {
		ghidra::shutdownDecompilerLibrary();
	}
	catch (...) {}

	g_state.initialized.store(false);
}

}
