#include "aida_arch_map.hpp"
#include "../zydis_disasm.hpp"

#include <algorithm>
#include <cstring>

namespace aida_ghidra {

namespace {

constexpr uint16_t kMachineAmd64 = 0x8664;
constexpr uint16_t kMachineI386 = 0x014C;
constexpr uint16_t kMachineArm64 = 0xAA64;
constexpr uint16_t kMachineArmNT = 0x01C4;

uint16_t read_pe_machine(const DisasmFile& file)
{
	if (!file.loaded || file.sections.empty())
		return 0;

	uint64_t base = file.image_base;
	for (auto& s : file.sections) {
		if (s.bytes.size() < 0x400)
			continue;
		if (s.va > base)
			continue;
		uint64_t offset = base - s.va;
		if (offset + 0x400 > s.bytes.size())
			continue;
		const uint8_t* p = s.bytes.data() + static_cast<size_t>(offset);
		if (p[0] != 'M' || p[1] != 'Z')
			continue;
		uint32_t e_lfanew = 0;
		std::memcpy(&e_lfanew, p + 0x3C, 4);
		if (e_lfanew + 6 > 0x400)
			continue;
		const uint8_t* nt = p + e_lfanew;
		if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0)
			continue;
		uint16_t machine = 0;
		std::memcpy(&machine, nt + 4, 2);
		return machine;
	}
	return 0;
}

}

arch_descriptor_t detect_arch_from_machine(uint16_t pe_machine)
{
	arch_descriptor_t d;
	switch (pe_machine) {
	case kMachineAmd64:
		d.sleigh_id = "x86:LE:64:default";
		d.compiler_spec = "windows";
		d.bits = 64;
		d.is_big_endian = false;
		break;
	case kMachineI386:
		d.sleigh_id = "x86:LE:32:default";
		d.compiler_spec = "windows";
		d.bits = 32;
		d.is_big_endian = false;
		break;
	case kMachineArm64:
		d.sleigh_id = "AARCH64:LE:64:v8A";
		d.compiler_spec = "windows";
		d.bits = 64;
		d.is_big_endian = false;
		break;
	case kMachineArmNT:
		d.sleigh_id = "ARM:LE:32:v7";
		d.compiler_spec = "windows";
		d.bits = 32;
		d.is_big_endian = false;
		break;
	default:
		d.sleigh_id = "x86:LE:64:default";
		d.compiler_spec = "windows";
		d.bits = 64;
		d.is_big_endian = false;
		break;
	}
	return d;
}

arch_descriptor_t detect_arch_from_pe(const DisasmFile& file)
{
	uint16_t machine = read_pe_machine(file);
	if (machine == 0)
		return detect_arch_default_x64();
	return detect_arch_from_machine(machine);
}

arch_descriptor_t detect_arch_default_x64()
{
	arch_descriptor_t d;
	d.sleigh_id = "x86:LE:64:default";
	d.compiler_spec = "windows";
	d.bits = 64;
	d.is_big_endian = false;
	return d;
}

bool is_x86_family(const std::string& sleigh_id)
{
	if (sleigh_id.size() < 3)
		return false;
	return sleigh_id.compare(0, 3, "x86") == 0;
}

}
