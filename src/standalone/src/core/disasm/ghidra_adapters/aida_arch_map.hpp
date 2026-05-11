#pragma once

#include <cstdint>
#include <string>

struct DisasmFile;

namespace aida_ghidra {

struct arch_descriptor_t
{
	std::string sleigh_id;
	std::string compiler_spec;
	int bits = 64;
	bool is_big_endian = false;
};

arch_descriptor_t detect_arch_from_pe(const DisasmFile& file);
arch_descriptor_t detect_arch_from_machine(uint16_t pe_machine);
arch_descriptor_t detect_arch_default_x64();

bool is_x86_family(const std::string& sleigh_id);

}
