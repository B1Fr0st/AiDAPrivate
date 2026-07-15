#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../runtime/standalone_driver.hpp"
#include "../../preview/ui_task_executor.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace driver_bridge {

inline bool can_read_memory() { return true; }

inline std::vector<memory_region_t> enumerate_memory_regions_for(std::uint32_t, std::size_t)
{
	return {
		{0x00007FF7A4C00000, 0x1000, 0x1000, 0x02, 0x1000000},
		{0x00007FF7A4C01000, 0x98000, 0x1000, 0x20, 0x1000000},
		{0x00007FF7A4C99000, 0x26000, 0x1000, 0x02, 0x1000000},
		{0x00007FF7A4CBF000, 0x18000, 0x1000, 0x04, 0x1000000},
		{0x000001D23A100000, 0x240000, 0x1000, 0x04, 0x20000},
		{0x000001D23A340000, 0x10000, 0x1000, 0x40, 0x20000},
		{0x000000E8C5DF0000, 0x100000, 0x1000, 0x04, 0x20000},
		{0x00007FFDA1700000, 0x1F0000, 0x1000, 0x20, 0x1000000}
	};
}

inline std::vector<module_info_t> enumerate_modules_for(std::uint32_t)
{
	return {
		{0x00007FF7A4C00000, 0x001A0000, "sample.exe", "C:/Samples/sample.exe"},
		{0x00007FFDA1700000, 0x001F0000, "KERNEL32.DLL", "C:/Windows/System32/KERNEL32.DLL"},
		{0x00007FFDA1900000, 0x00216000, "ntdll.dll", "C:/Windows/System32/ntdll.dll"}
	};
}

inline std::vector<thread_info_t> enumerate_threads_for(std::uint32_t pid)
{
	return {
		{6872, pid, 10, 5, 0x00007FF7A4C16A32},
		{7044, pid, 8, 2, 0x00007FFDA19323C0},
		{7296, pid, 8, 5, 0x00007FFDA18F1B20}
	};
}

inline bool read_peb_for(std::uint32_t, peb_info_t& out)
{
	out.peb_address = 0x000000E8C5DFF000;
	out.image_base = 0x00007FF7A4C00000;
	out.process_heap = 0x000001D23A100000;
	out.ldr_address = 0x000001D23A101000;
	out.number_of_heaps = 3;
	out.max_heaps = 16;
	out.process_heaps = 0x000001D23A102000;
	return true;
}

inline bool read_memory_for(std::uint32_t, std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& out)
{
	static constexpr std::uint8_t pattern[] = {
		0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B,
		0xF9, 0x48, 0x8B, 0xDA, 0x48, 0x85, 0xD2, 0x74, 0x14, 0xE8, 0x42, 0x01,
		0x00, 0x00, 0x84, 0xC0, 0x75, 0x05, 0xCC, 0xC3
	};
	out.resize(size);
	for (std::size_t i = 0; i < size; ++i) out[i] = pattern[(address + i) % sizeof(pattern)];
	return true;
}

inline bool protect_memory_for(std::uint32_t, std::uint64_t, std::uint64_t, std::uint32_t new_protect, std::uint32_t* old_protect)
{
	if (old_protect) *old_protect = new_protect == 0x20 ? 0x04 : 0x20;
	return true;
}

}

#endif
