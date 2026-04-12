#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "standalone_driver.hpp"

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

class aida_live_load_image_t : public ghidra::LoadImage {
public:
	aida_live_load_image_t() : ghidra::LoadImage("aida_live") {}

	void loadFill(ghidra::uint1* ptr, ghidra::int4 size, const ghidra::Address& addr) override {
		uint64_t offset = addr.getOffset();
		std::vector<uint8_t> data;
		driver_bridge::read_memory(offset, static_cast<size_t>(size), data);
		if (static_cast<ghidra::int4>(data.size()) >= size) {
			std::memcpy(ptr, data.data(), static_cast<size_t>(size));
		}
		else {
			std::memset(ptr, 0, static_cast<size_t>(size));
			if (!data.empty())
				std::memcpy(ptr, data.data(), data.size());
		}
	}

	std::string getArchType(void) const override {
		return "x86:LE:64:default";
	}

	void adjustVma(long) override {}
};

class aida_buffer_load_image_t : public ghidra::LoadImage {
	const uint8_t* buf_;
	size_t buf_size_;
	uint64_t base_addr_;

public:
	aida_buffer_load_image_t(const uint8_t* data, size_t size, uint64_t base)
		: ghidra::LoadImage("aida_buffer"), buf_(data), buf_size_(size), base_addr_(base) {}

	void loadFill(ghidra::uint1* ptr, ghidra::int4 size, const ghidra::Address& addr) override {
		uint64_t offset = addr.getOffset();
		std::memset(ptr, 0, static_cast<size_t>(size));
		if (offset >= base_addr_ && (offset + size) <= (base_addr_ + buf_size_)) {
			std::memcpy(ptr, buf_ + (offset - base_addr_), static_cast<size_t>(size));
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
	std::mutex mtx;
	std::atomic<bool> initialized{false};
	aida_live_load_image_t* live_loader = nullptr;
	aida_architecture_t* arch = nullptr;
	std::ostringstream err_stream;
	std::string specs_dir;
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
	std::string cmake_dir = GHIDRA_SPECS_DIR;
	attr = GetFileAttributesA(cmake_dir.c_str());
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
		return cmake_dir;
#endif

	return "";
}

inline ghidra_result_t do_decompile(aida_architecture_t* arch, uint64_t entry_addr) {
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
	std::snprintf(name_buf, sizeof(name_buf), "sub_%llx", static_cast<unsigned long long>(entry_addr));
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
	ghidra::int4 res = arch->allacts.getCurrent()->perform(*fd);
	(void)res;

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

}

inline bool init(const std::string& specs_dir = "") {
	std::lock_guard<std::mutex> lk(g_state.mtx);
	if (g_state.initialized.load())
		return true;

	std::string dir = specs_dir;
	if (dir.empty())
		dir = detail::find_specs_dir();

	if (dir.empty())
		return false;

	try {
		g_state.specs_dir = dir;
		std::vector<std::string> paths;
		paths.push_back(dir);
		ghidra::startDecompilerLibrary(paths);

		g_state.live_loader = new aida_live_load_image_t();
		g_state.arch = new aida_architecture_t(
			g_state.live_loader, "x86:LE:64:default", &g_state.err_stream);

		ghidra::DocumentStorage store;
		g_state.arch->init(store);

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

inline ghidra_result_t decompile_function(uint64_t entry_addr) {
	std::lock_guard<std::mutex> lk(g_state.mtx);

	ghidra_result_t result;
	result.function_addr = entry_addr;

	if (!g_state.initialized.load()) {
		if (!init()) {
			result.is_error = true;
			result.error_text = "ghidra decompiler not initialized: " + g_state.err_stream.str();
			return result;
		}
	}

	try {
		return detail::do_decompile(g_state.arch, entry_addr);
	}
	catch (ghidra::LowlevelError& err) {
		result.is_error = true;
		result.error_text = err.explain;
		return result;
	}
	catch (ghidra::DecoderError& err) {
		result.is_error = true;
		result.error_text = err.explain;
		return result;
	}
	catch (...) {
		result.is_error = true;
		result.error_text = "unknown decompilation error";
		return result;
	}
}

inline ghidra_result_t decompile_buffer(const uint8_t* data, size_t size,
                                         uint64_t base_addr, uint64_t entry_addr) {
	ghidra_result_t result;
	result.function_addr = entry_addr;

	std::string dir;
	{
		std::lock_guard<std::mutex> lk(g_state.mtx);
		dir = g_state.specs_dir;
	}

	if (dir.empty())
		dir = detail::find_specs_dir();
	if (dir.empty()) {
		result.is_error = true;
		result.error_text = "ghidra specs directory not found";
		return result;
	}

	try {
		std::vector<std::string> paths;
		paths.push_back(dir);

		std::ostringstream err;
		aida_buffer_load_image_t* buf_loader = new aida_buffer_load_image_t(data, size, base_addr);
		aida_architecture_t* buf_arch = new aida_architecture_t(
			buf_loader, "x86:LE:64:default", &err);

		ghidra::DocumentStorage store;
		buf_arch->init(store);

		result = detail::do_decompile(buf_arch, entry_addr);

		delete buf_arch;

		return result;
	}
	catch (ghidra::LowlevelError& e) {
		result.is_error = true;
		result.error_text = e.explain;
		return result;
	}
	catch (ghidra::DecoderError& e) {
		result.is_error = true;
		result.error_text = e.explain;
		return result;
	}
	catch (...) {
		result.is_error = true;
		result.error_text = "unknown decompilation error (buffer mode)";
		return result;
	}
}

inline std::string last_error() {
	std::lock_guard<std::mutex> lk(g_state.mtx);
	return g_state.err_stream.str();
}

inline bool is_initialized() {
	return g_state.initialized.load();
}

inline void shutdown() {
	std::lock_guard<std::mutex> lk(g_state.mtx);
	if (!g_state.initialized.load())
		return;

	try {
		ghidra::shutdownDecompilerLibrary();
	}
	catch (...) {}

	delete g_state.arch;
	g_state.arch = nullptr;
	g_state.live_loader = nullptr;
	g_state.initialized.store(false);
}

}
