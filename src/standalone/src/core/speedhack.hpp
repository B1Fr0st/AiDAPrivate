#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "standalone_driver.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace speedhack {

struct state_t {
	bool     active = false;
	float    speed = 1.0f;
	uint32_t target_pid = 0;
	bool     patched_qpc = false;
	bool     patched_gtc64 = false;
	std::vector<uint8_t> original_qpc_bytes;
	std::vector<uint8_t> original_gtc64_bytes;
	uint64_t shellcode_addr = 0;
	uint64_t data_addr = 0;
	uint64_t qpc_addr = 0;
	uint64_t gtc64_addr = 0;
	std::string err;
};

inline state_t g_state;

static constexpr size_t HOOK_PATCH_SIZE = 14;
static constexpr size_t TRAMPOLINE_SIZE = 32;
static constexpr size_t SHELLCODE_REGION_SIZE = 0x1000;

static constexpr size_t DATA_SPEED_MULT    = 0x00;
static constexpr size_t DATA_BASE_QPC      = 0x08;
static constexpr size_t DATA_BASE_REAL_QPC = 0x10;
static constexpr size_t DATA_BASE_TICK     = 0x18;
static constexpr size_t DATA_BASE_REAL_TICK = 0x20;
static constexpr size_t DATA_QPC_TRAMP     = 0x28;
static constexpr size_t DATA_GTC64_TRAMP   = 0x30;
static constexpr size_t DATA_BLOCK_SIZE    = 0x40;

static constexpr size_t QPC_HOOK_OFFSET       = 0x000;
static constexpr size_t GTC64_HOOK_OFFSET     = 0x080;
static constexpr size_t QPC_TRAMPOLINE_OFFSET = 0x100;
static constexpr size_t GTC64_TRAMPOLINE_OFFSET = 0x140;

inline std::string last_error() { return g_state.err; }
inline bool is_active() { return g_state.active; }
inline float get_speed() { return g_state.speed; }

inline void build_jmp_abs(uint8_t* buf, uint64_t target) {
	buf[0] = 0xFF; buf[1] = 0x25;
	buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x00;
	std::memcpy(buf + 6, &target, 8);
}

inline void build_trampoline(std::vector<uint8_t>& out, size_t tramp_offset,
							 const std::vector<uint8_t>& orig_bytes,
							 uint64_t original_func_addr) {
	size_t copied = std::min<size_t>(orig_bytes.size(), HOOK_PATCH_SIZE);
	for (size_t i = 0; i < copied; ++i)
		out[tramp_offset + i] = orig_bytes[i];

	uint64_t return_addr = original_func_addr + copied;
	uint8_t jmp[14];
	build_jmp_abs(jmp, return_addr);
	for (size_t i = 0; i < 14; ++i)
		out[tramp_offset + copied + i] = jmp[i];
}

inline void build_qpc_hook(std::vector<uint8_t>& sc, uint64_t data_addr_val, uint64_t tramp_addr) {
	size_t o = QPC_HOOK_OFFSET;

	sc[o++] = 0x53;
	sc[o++] = 0x56;
	sc[o++] = 0x57;
	sc[o++] = 0x48; sc[o++] = 0x83; sc[o++] = 0xEC; sc[o++] = 0x30;

	sc[o++] = 0x48; sc[o++] = 0x89; sc[o++] = 0xCE;

	sc[o++] = 0x48; sc[o++] = 0xBF;
	std::memcpy(&sc[o], &data_addr_val, 8); o += 8;

	sc[o++] = 0x48; sc[o++] = 0xB8;
	std::memcpy(&sc[o], &tramp_addr, 8); o += 8;
	sc[o++] = 0x48; sc[o++] = 0x89; sc[o++] = 0xF1;
	sc[o++] = 0xFF; sc[o++] = 0xD0;

	sc[o++] = 0x48; sc[o++] = 0x8B; sc[o++] = 0x06;

	sc[o++] = 0x48; sc[o++] = 0x2B; sc[o++] = 0x47; sc[o++] = 0x10;

	sc[o++] = 0xF2; sc[o++] = 0x48; sc[o++] = 0x0F; sc[o++] = 0x2A; sc[o++] = 0xC0;

	sc[o++] = 0xF2; sc[o++] = 0x0F; sc[o++] = 0x59; sc[o++] = 0x07;

	sc[o++] = 0xF2; sc[o++] = 0x48; sc[o++] = 0x0F; sc[o++] = 0x2C; sc[o++] = 0xC0;

	sc[o++] = 0x48; sc[o++] = 0x03; sc[o++] = 0x47; sc[o++] = 0x08;

	sc[o++] = 0x48; sc[o++] = 0x89; sc[o++] = 0x06;

	sc[o++] = 0xB8; sc[o++] = 0x01; sc[o++] = 0x00; sc[o++] = 0x00; sc[o++] = 0x00;

	sc[o++] = 0x48; sc[o++] = 0x83; sc[o++] = 0xC4; sc[o++] = 0x30;
	sc[o++] = 0x5F;
	sc[o++] = 0x5E;
	sc[o++] = 0x5B;
	sc[o++] = 0xC3;
}

inline void build_gtc64_hook(std::vector<uint8_t>& sc, uint64_t data_addr_val, uint64_t tramp_addr) {
	size_t o = GTC64_HOOK_OFFSET;

	sc[o++] = 0x53;
	sc[o++] = 0x56;
	sc[o++] = 0x48; sc[o++] = 0x83; sc[o++] = 0xEC; sc[o++] = 0x28;

	sc[o++] = 0x48; sc[o++] = 0xBE;
	std::memcpy(&sc[o], &data_addr_val, 8); o += 8;

	sc[o++] = 0x48; sc[o++] = 0xB8;
	std::memcpy(&sc[o], &tramp_addr, 8); o += 8;
	sc[o++] = 0xFF; sc[o++] = 0xD0;

	sc[o++] = 0x48; sc[o++] = 0x89; sc[o++] = 0xC3;

	sc[o++] = 0x48; sc[o++] = 0x2B; sc[o++] = 0x5E; sc[o++] = 0x20;

	sc[o++] = 0xF2; sc[o++] = 0x48; sc[o++] = 0x0F; sc[o++] = 0x2A; sc[o++] = 0xC3;

	sc[o++] = 0xF2; sc[o++] = 0x0F; sc[o++] = 0x59; sc[o++] = 0x06;

	sc[o++] = 0xF2; sc[o++] = 0x48; sc[o++] = 0x0F; sc[o++] = 0x2C; sc[o++] = 0xC0;

	sc[o++] = 0x48; sc[o++] = 0x03; sc[o++] = 0x46; sc[o++] = 0x18;

	sc[o++] = 0x48; sc[o++] = 0x83; sc[o++] = 0xC4; sc[o++] = 0x28;
	sc[o++] = 0x5E;
	sc[o++] = 0x5B;
	sc[o++] = 0xC3;
}

inline uint64_t resolve_api_in_target(const char* module_name, const char* func_name) {
	if (!driver_bridge::using_kernel_driver()) return 0;
	auto mods = driver_bridge::enumerate_modules();
	for (const auto& m : mods) {
		std::string lower_name = m.name;
		std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
					   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		std::string lower_target = module_name;
		std::transform(lower_target.begin(), lower_target.end(), lower_target.begin(),
					   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		if (lower_name.find(lower_target) != std::string::npos) {
			uint64_t addr = driver_bridge::resolve_export(m.base, func_name);
			if (addr != 0) return addr;
		}
	}
	return 0;
}

inline bool enable(float speed) {
	if (g_state.active) {
		g_state.err = "speedhack already active";
		return false;
	}
	if (!driver_bridge::is_loaded()) {
		g_state.err = "driver not loaded";
		return false;
	}
	uint32_t pid = driver_bridge::attached_pid();
	if (pid == 0) {
		g_state.err = "no process attached";
		return false;
	}
	if (!driver_bridge::using_kernel_driver()) {
		g_state.err = "device not connected";
		return false;
	}

	uint64_t qpc_addr = resolve_api_in_target("kernelbase.dll", "QueryPerformanceCounter");
	if (qpc_addr == 0)
		qpc_addr = resolve_api_in_target("kernel32.dll", "QueryPerformanceCounter");
	if (qpc_addr == 0) {
		g_state.err = "failed to resolve QueryPerformanceCounter";
		return false;
	}

	uint64_t gtc64_addr = resolve_api_in_target("kernelbase.dll", "GetTickCount64");
	if (gtc64_addr == 0)
		gtc64_addr = resolve_api_in_target("kernel32.dll", "GetTickCount64");
	if (gtc64_addr == 0) {
		g_state.err = "failed to resolve GetTickCount64";
		return false;
	}

	uint64_t sc_addr = driver_bridge::allocate_memory(SHELLCODE_REGION_SIZE);
	if (sc_addr == 0) {
		g_state.err = "failed to allocate shellcode memory";
		return false;
	}

	uint64_t d_addr = driver_bridge::allocate_memory(DATA_BLOCK_SIZE);
	if (d_addr == 0) {
		driver_bridge::free_memory(sc_addr);
		g_state.err = "failed to allocate data memory";
		return false;
	}

	std::vector<uint8_t> orig_qpc;
	if (!driver_bridge::read_memory(qpc_addr, HOOK_PATCH_SIZE, orig_qpc) || orig_qpc.size() < HOOK_PATCH_SIZE) {
		driver_bridge::free_memory(sc_addr);
		driver_bridge::free_memory(d_addr);
		g_state.err = "failed to read QPC bytes";
		return false;
	}

	std::vector<uint8_t> orig_gtc64;
	if (!driver_bridge::read_memory(gtc64_addr, HOOK_PATCH_SIZE, orig_gtc64) || orig_gtc64.size() < HOOK_PATCH_SIZE) {
		driver_bridge::free_memory(sc_addr);
		driver_bridge::free_memory(d_addr);
		g_state.err = "failed to read GTC64 bytes";
		return false;
	}

	LARGE_INTEGER qpc_now;
	QueryPerformanceCounter(&qpc_now);
	uint64_t tick_now = GetTickCount64();

	int64_t base_qpc_val = qpc_now.QuadPart;
	int64_t base_real_qpc_val = qpc_now.QuadPart;
	uint64_t base_tick_val = tick_now;
	uint64_t base_real_tick_val = tick_now;
	double speed_d = static_cast<double>(speed);

	uint64_t qpc_tramp = sc_addr + QPC_TRAMPOLINE_OFFSET;
	uint64_t gtc64_tramp = sc_addr + GTC64_TRAMPOLINE_OFFSET;

	std::vector<uint8_t> data_block(DATA_BLOCK_SIZE, 0);
	std::memcpy(data_block.data() + DATA_SPEED_MULT, &speed_d, 8);
	std::memcpy(data_block.data() + DATA_BASE_QPC, &base_qpc_val, 8);
	std::memcpy(data_block.data() + DATA_BASE_REAL_QPC, &base_real_qpc_val, 8);
	std::memcpy(data_block.data() + DATA_BASE_TICK, &base_tick_val, 8);
	std::memcpy(data_block.data() + DATA_BASE_REAL_TICK, &base_real_tick_val, 8);
	std::memcpy(data_block.data() + DATA_QPC_TRAMP, &qpc_tramp, 8);
	std::memcpy(data_block.data() + DATA_GTC64_TRAMP, &gtc64_tramp, 8);

	if (!driver_bridge::write_memory(d_addr, data_block)) {
		driver_bridge::free_memory(sc_addr);
		driver_bridge::free_memory(d_addr);
		g_state.err = "failed to write data block";
		return false;
	}

	std::vector<uint8_t> sc(SHELLCODE_REGION_SIZE, 0xCC);
	build_trampoline(sc, QPC_TRAMPOLINE_OFFSET, orig_qpc, qpc_addr);
	build_trampoline(sc, GTC64_TRAMPOLINE_OFFSET, orig_gtc64, gtc64_addr);
	build_qpc_hook(sc, d_addr, qpc_tramp);
	build_gtc64_hook(sc, d_addr, gtc64_tramp);

	std::vector<uint8_t> sc_vec(sc.begin(), sc.end());
	if (!driver_bridge::write_memory(sc_addr, sc_vec)) {
		driver_bridge::free_memory(sc_addr);
		driver_bridge::free_memory(d_addr);
		g_state.err = "failed to write shellcode";
		return false;
	}

	uint8_t qpc_patch[HOOK_PATCH_SIZE];
	build_jmp_abs(qpc_patch, sc_addr + QPC_HOOK_OFFSET);
	std::vector<uint8_t> qpc_patch_vec(qpc_patch, qpc_patch + HOOK_PATCH_SIZE);
	if (!driver_bridge::write_memory(qpc_addr, qpc_patch_vec)) {
		driver_bridge::free_memory(sc_addr);
		driver_bridge::free_memory(d_addr);
		g_state.err = "failed to patch QPC";
		return false;
	}

	uint8_t gtc64_patch[HOOK_PATCH_SIZE];
	build_jmp_abs(gtc64_patch, sc_addr + GTC64_HOOK_OFFSET);
	std::vector<uint8_t> gtc64_patch_vec(gtc64_patch, gtc64_patch + HOOK_PATCH_SIZE);
	if (!driver_bridge::write_memory(gtc64_addr, gtc64_patch_vec)) {
		driver_bridge::write_memory(qpc_addr, orig_qpc);
		driver_bridge::free_memory(sc_addr);
		driver_bridge::free_memory(d_addr);
		g_state.err = "failed to patch GTC64";
		return false;
	}

	g_state.active = true;
	g_state.speed = speed;
	g_state.target_pid = pid;
	g_state.patched_qpc = true;
	g_state.patched_gtc64 = true;
	g_state.original_qpc_bytes = std::move(orig_qpc);
	g_state.original_gtc64_bytes = std::move(orig_gtc64);
	g_state.shellcode_addr = sc_addr;
	g_state.data_addr = d_addr;
	g_state.qpc_addr = qpc_addr;
	g_state.gtc64_addr = gtc64_addr;
	g_state.err.clear();
	return true;
}

inline bool disable() {
	if (!g_state.active) {
		g_state.err = "speedhack not active";
		return false;
	}
	if (!driver_bridge::using_kernel_driver()) {
		g_state.err = "device not connected";
		return false;
	}

	bool ok = true;

	if (g_state.patched_qpc && !g_state.original_qpc_bytes.empty()) {
		if (!driver_bridge::write_memory(g_state.qpc_addr, g_state.original_qpc_bytes)) {
			g_state.err = "failed to restore QPC";
			ok = false;
		}
	}

	if (g_state.patched_gtc64 && !g_state.original_gtc64_bytes.empty()) {
		if (!driver_bridge::write_memory(g_state.gtc64_addr, g_state.original_gtc64_bytes)) {
			g_state.err = "failed to restore GTC64";
			ok = false;
		}
	}

	if (g_state.shellcode_addr != 0)
		driver_bridge::free_memory(g_state.shellcode_addr);
	if (g_state.data_addr != 0)
		driver_bridge::free_memory(g_state.data_addr);

	g_state.active = false;
	g_state.speed = 1.0f;
	g_state.patched_qpc = false;
	g_state.patched_gtc64 = false;
	g_state.original_qpc_bytes.clear();
	g_state.original_gtc64_bytes.clear();
	g_state.shellcode_addr = 0;
	g_state.data_addr = 0;
	g_state.qpc_addr = 0;
	g_state.gtc64_addr = 0;
	if (ok) g_state.err.clear();
	return ok;
}

inline bool set_speed(float speed) {
	if (!g_state.active) {
		g_state.err = "speedhack not active";
		return false;
	}
	if (!driver_bridge::using_kernel_driver()) {
		g_state.err = "device not connected";
		return false;
	}

	LARGE_INTEGER qpc_now;
	QueryPerformanceCounter(&qpc_now);
	uint64_t tick_now = GetTickCount64();

	std::vector<uint8_t> old_data;
	if (!driver_bridge::read_memory(g_state.data_addr, DATA_BLOCK_SIZE, old_data) || old_data.size() < DATA_BLOCK_SIZE) {
		g_state.err = "failed to read data block";
		return false;
	}

	double old_speed = 0.0;
	int64_t old_base_qpc = 0, old_base_real_qpc = 0;
	uint64_t old_base_tick = 0, old_base_real_tick = 0;
	std::memcpy(&old_speed, old_data.data() + DATA_SPEED_MULT, 8);
	std::memcpy(&old_base_qpc, old_data.data() + DATA_BASE_QPC, 8);
	std::memcpy(&old_base_real_qpc, old_data.data() + DATA_BASE_REAL_QPC, 8);
	std::memcpy(&old_base_tick, old_data.data() + DATA_BASE_TICK, 8);
	std::memcpy(&old_base_real_tick, old_data.data() + DATA_BASE_REAL_TICK, 8);

	int64_t virtual_qpc = old_base_qpc +
		static_cast<int64_t>(static_cast<double>(qpc_now.QuadPart - old_base_real_qpc) * old_speed);
	uint64_t virtual_tick = old_base_tick +
		static_cast<uint64_t>(static_cast<double>(tick_now - old_base_real_tick) * old_speed);

	double new_speed = static_cast<double>(speed);
	int64_t new_base_real_qpc = qpc_now.QuadPart;
	uint64_t new_base_real_tick = tick_now;

	std::vector<uint8_t> new_data(DATA_BLOCK_SIZE, 0);
	std::memcpy(new_data.data() + DATA_SPEED_MULT, &new_speed, 8);
	std::memcpy(new_data.data() + DATA_BASE_QPC, &virtual_qpc, 8);
	std::memcpy(new_data.data() + DATA_BASE_REAL_QPC, &new_base_real_qpc, 8);
	std::memcpy(new_data.data() + DATA_BASE_TICK, &virtual_tick, 8);
	std::memcpy(new_data.data() + DATA_BASE_REAL_TICK, &new_base_real_tick, 8);
	std::memcpy(new_data.data() + DATA_QPC_TRAMP, old_data.data() + DATA_QPC_TRAMP, 8);
	std::memcpy(new_data.data() + DATA_GTC64_TRAMP, old_data.data() + DATA_GTC64_TRAMP, 8);

	if (!driver_bridge::write_memory(g_state.data_addr, new_data)) {
		g_state.err = "failed to write new speed";
		return false;
	}

	g_state.speed = speed;
	g_state.err.clear();
	return true;
}

}
