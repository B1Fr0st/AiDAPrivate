#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "standalone_driver.hpp"
#include "zydis_disasm.hpp"

#ifdef AIDA_STANDALONE
#include <Zydis/Zydis.h>
#endif

namespace aob_generator {

struct aob_byte_t {
	uint8_t value = 0;
	bool    wildcard = false;
};

struct signature_t {
	std::string          name;
	uint64_t             address = 0;
	std::vector<aob_byte_t> bytes;
	bool                 unique = false;
	int                  uniqueness_count = 0;
	std::string          module_name;
};

struct state_t {
	std::vector<signature_t> saved_signatures;
	signature_t              current;
	std::mutex               mutex;
	std::atomic<bool>        generating{false};
	std::atomic<bool>        validating{false};
	char                     address_input[32] = {};
	char                     name_input[64] = {};
	int                      instruction_count = 16;
	bool                     auto_wildcard = true;
	bool                     validate_uniqueness = true;
};

inline state_t g_state;

inline std::string format_signature(const signature_t& sig)
{
	std::string result;
	result.reserve(sig.bytes.size() * 3);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) result += ' ';
		if (sig.bytes[i].wildcard) {
			result += "??";
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02X", sig.bytes[i].value);
			result += buf;
		}
	}
	return result;
}

inline std::string format_ida_signature(const signature_t& sig)
{
	std::string result;
	result.reserve(sig.bytes.size() * 4);
	for (size_t i = 0; i < sig.bytes.size(); ++i) {
		if (i > 0) result += ' ';
		if (sig.bytes[i].wildcard) {
			result += '?';
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%02X", sig.bytes[i].value);
			result += buf;
		}
	}
	return result;
}

inline std::string format_code_signature(const signature_t& sig)
{
	std::string pattern = "\"";
	std::string mask = "\"";
	for (auto& b : sig.bytes) {
		char buf[8];
		if (b.wildcard) {
			pattern += "\\x00";
			mask += "?";
		} else {
			std::snprintf(buf, sizeof(buf), "\\x%02X", b.value);
			pattern += buf;
			mask += "x";
		}
	}
	pattern += "\"";
	mask += "\"";
	return pattern + ", " + mask;
}

namespace detail {

#ifdef AIDA_STANDALONE

struct decoded_instr_t {
	ZydisDecodedInstruction instr;
	ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT];
	uint64_t                address;
	uint8_t                 raw[15];
	uint8_t                 length;
};

inline bool should_wildcard_operand_bytes(const ZydisDecodedInstruction& instr,
                                           const ZydisDecodedOperand* operands,
                                           size_t op_count)
{
	for (size_t i = 0; i < op_count && i < instr.operand_count; ++i) {
		auto& op = operands[i];
		if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			if (op.imm.is_relative) return true;
			if (instr.raw.imm[0].size >= 32) return true;
		}
		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
			if (op.mem.base == ZYDIS_REGISTER_RIP) return true;
			if (op.mem.disp.has_displacement && instr.raw.disp.size >= 32) return true;
		}
	}
	return false;
}

inline void wildcard_dynamic_bytes(decoded_instr_t& di, std::vector<aob_byte_t>& out)
{
	bool needs_wildcard = should_wildcard_operand_bytes(di.instr, di.operands, ZYDIS_MAX_OPERAND_COUNT);

	for (uint8_t b = 0; b < di.length; ++b) {
		aob_byte_t ab;
		ab.value = di.raw[b];
		ab.wildcard = false;

		if (needs_wildcard) {
			if (di.instr.raw.disp.size > 0) {
				uint8_t disp_off = di.instr.raw.disp.offset;
				uint8_t disp_sz = static_cast<uint8_t>(di.instr.raw.disp.size / 8);
				if (b >= disp_off && b < disp_off + disp_sz) {
					ab.wildcard = true;
				}
			}
			for (int imm_idx = 0; imm_idx < 2; ++imm_idx) {
				if (di.instr.raw.imm[imm_idx].size > 0) {
					uint8_t imm_off = di.instr.raw.imm[imm_idx].offset;
					uint8_t imm_sz = static_cast<uint8_t>(di.instr.raw.imm[imm_idx].size / 8);
					if (b >= imm_off && b < imm_off + imm_sz) {
						ab.wildcard = true;
					}
				}
			}
		}

		out.push_back(ab);
	}
}

#endif

inline int count_pattern_in_data(const uint8_t* data, size_t data_len,
                                  const std::vector<aob_byte_t>& pattern)
{
	if (pattern.empty() || data_len < pattern.size()) return 0;
	int count = 0;
	size_t limit = data_len - pattern.size();
	for (size_t i = 0; i <= limit; ++i) {
		bool match = true;
		for (size_t j = 0; j < pattern.size(); ++j) {
			if (!pattern[j].wildcard && data[i + j] != pattern[j].value) {
				match = false;
				break;
			}
		}
		if (match) {
			++count;
			if (count > 1) return count;
		}
	}
	return count;
}

}

inline void generate_from_address(uint64_t address, int num_instructions, bool auto_wildcard)
{
#ifdef AIDA_STANDALONE
	if (g_state.generating.load()) return;
	g_state.generating.store(true);

	std::thread([address, num_instructions, auto_wildcard]() {
		signature_t sig;
		sig.address = address;

		auto modules = driver_bridge::enumerate_modules();
		for (auto& m : modules) {
			if (address >= m.base && address < m.base + m.size) {
				sig.module_name = m.name;
				break;
			}
		}

		size_t read_size = static_cast<size_t>(num_instructions) * 15;
		std::vector<uint8_t> code;
		driver_bridge::read_memory(address, read_size, code);
		if (code.empty()) {
			g_state.generating.store(false);
			return;
		}

		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		std::vector<detail::decoded_instr_t> instrs;
		uint64_t offset = 0;
		int decoded_count = 0;

		while (offset < code.size() && decoded_count < num_instructions) {
			detail::decoded_instr_t di{};
			di.address = address + offset;

			auto status = ZydisDecoderDecodeFull(
				&decoder, code.data() + offset, code.size() - offset,
				&di.instr, di.operands);

			if (!ZYAN_SUCCESS(status)) break;

			di.length = static_cast<uint8_t>(di.instr.length);
			std::memcpy(di.raw, code.data() + offset, di.length);

			instrs.push_back(di);
			offset += di.length;
			++decoded_count;
		}

		std::vector<aob_byte_t> pattern;
		for (auto& di : instrs) {
			if (auto_wildcard) {
				detail::wildcard_dynamic_bytes(di, pattern);
			} else {
				for (uint8_t b = 0; b < di.length; ++b) {
					aob_byte_t ab;
					ab.value = di.raw[b];
					ab.wildcard = false;
					pattern.push_back(ab);
				}
			}
		}

		sig.bytes = std::move(pattern);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = std::move(sig);
		}

		g_state.generating.store(false);
	}).detach();
#else
	(void)address;
	(void)num_instructions;
	(void)auto_wildcard;
#endif
}

inline void generate_from_file(const DisasmFile& file, uint64_t address, int num_instructions, bool auto_wildcard)
{
#ifdef AIDA_STANDALONE
	if (g_state.generating.load()) return;
	g_state.generating.store(true);

	auto file_copy = file;
	std::thread([file_copy, address, num_instructions, auto_wildcard]() {
		signature_t sig;
		sig.address = address;
		sig.module_name = file_copy.filename;

		const uint8_t* code_data = nullptr;
		size_t code_size = 0;
		uint64_t section_va = 0;
		for (auto& sec : file_copy.sections) {
			uint64_t sec_start = file_copy.image_base + sec.va;
			uint64_t sec_end = sec_start + sec.bytes.size();
			if (address >= sec_start && address < sec_end) {
				code_data = sec.bytes.data() + (address - sec_start);
				code_size = sec.bytes.size() - static_cast<size_t>(address - sec_start);
				section_va = sec.va;
				break;
			}
		}

		if (!code_data || code_size == 0) {
			g_state.generating.store(false);
			return;
		}

		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		std::vector<detail::decoded_instr_t> instrs;
		uint64_t offset = 0;
		int decoded_count = 0;

		while (offset < code_size && decoded_count < num_instructions) {
			detail::decoded_instr_t di{};
			di.address = address + offset;

			auto status = ZydisDecoderDecodeFull(
				&decoder, code_data + offset, code_size - offset,
				&di.instr, di.operands);

			if (!ZYAN_SUCCESS(status)) break;

			di.length = static_cast<uint8_t>(di.instr.length);
			std::memcpy(di.raw, code_data + offset, di.length);

			instrs.push_back(di);
			offset += di.length;
			++decoded_count;
		}

		std::vector<aob_byte_t> pattern;
		for (auto& di : instrs) {
			if (auto_wildcard) {
				detail::wildcard_dynamic_bytes(di, pattern);
			} else {
				for (uint8_t b = 0; b < di.length; ++b) {
					aob_byte_t ab;
					ab.value = di.raw[b];
					ab.wildcard = false;
					pattern.push_back(ab);
				}
			}
		}

		sig.bytes = std::move(pattern);

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			g_state.current = std::move(sig);
		}

		g_state.generating.store(false);
	}).detach();
#else
	(void)file;
	(void)address;
	(void)num_instructions;
	(void)auto_wildcard;
#endif
}

inline void validate_uniqueness_process(signature_t& sig)
{
	if (g_state.validating.load()) return;
	g_state.validating.store(true);

	std::thread([&sig]() {
		int total_count = 0;
		auto regions = driver_bridge::enumerate_memory_regions();

		for (auto& region : regions) {
			if (region.state != 0x1000) continue;
			uint32_t prot = region.protect & 0xFF;
			if (prot == 0x01) continue;
			if (region.size > 0x10000000) continue;

			std::vector<uint8_t> data;
			driver_bridge::read_memory(region.base, static_cast<size_t>(region.size), data);
			if (data.empty()) continue;

			total_count += detail::count_pattern_in_data(data.data(), data.size(), sig.bytes);
			if (total_count > 1) break;
		}

		{
			std::lock_guard<std::mutex> lk(g_state.mutex);
			sig.unique = (total_count == 1);
			sig.uniqueness_count = total_count;
		}

		g_state.validating.store(false);
	}).detach();
}

inline void validate_uniqueness_file(const DisasmFile& file, signature_t& sig)
{
	int total_count = 0;
	for (auto& sec : file.sections) {
		if (sec.bytes.empty()) continue;
		total_count += detail::count_pattern_in_data(sec.bytes.data(), sec.bytes.size(), sig.bytes);
		if (total_count > 1) break;
	}
	sig.unique = (total_count == 1);
	sig.uniqueness_count = total_count;
}

inline void save_current()
{
	std::lock_guard<std::mutex> lk(g_state.mutex);
	if (g_state.current.bytes.empty()) return;
	if (g_state.name_input[0])
		g_state.current.name = g_state.name_input;
	else {
		char buf[32];
		std::snprintf(buf, sizeof(buf), "sig_%llX", static_cast<unsigned long long>(g_state.current.address));
		g_state.current.name = buf;
	}
	g_state.saved_signatures.push_back(g_state.current);
}

}
