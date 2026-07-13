#include "signature_handlers_harness.h"

#include "../../src/core/mcp/compat/handlers/signatures.h"
#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"
#include "../../src/core/mcp/protocol/mcp_tool_contract.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;
using namespace aida::standalone::mcp::compat::handlers;
using protocol::cancellation_token_t;
using protocol::json;

void require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

void require_fixture(bool condition, std::string_view tool, std::string_view category,
                     std::string_view detail) {
    if (!condition) {
        throw std::runtime_error(
            std::string(tool) + " " + std::string(category) + " fixture: " +
            std::string(detail));
    }
}

struct fixture_instruction_t {
    std::uint64_t address;
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> stable_mask;
    signature_architecture_t architecture = signature_architecture_t::unknown;
};

class fixture_source_t final : public signature_source_t {
public:
    fixture_source_t() = default;

    void set_memory(std::vector<std::uint8_t> bytes, std::uint64_t base) {
        memory_ = std::move(bytes);
        base_ = base;
    }

    void add_instruction(std::uint64_t addr, std::initializer_list<std::uint8_t> byte_vals,
                         std::initializer_list<std::uint8_t> mask_vals,
                         signature_architecture_t arch = signature_architecture_t::x64) {
        fixture_instruction_t insn;
        insn.address = addr;
        insn.bytes.assign(byte_vals.begin(), byte_vals.end());
        insn.stable_mask.assign(mask_vals.begin(), mask_vals.end());
        insn.architecture = arch;
        instructions_[addr] = std::move(insn);
    }

    void add_function(std::string name, std::uint64_t start, std::uint64_t end) {
        functions_[std::move(name)] = {start, end, name};
    }

    void add_symbol(std::string name, std::uint64_t addr) {
        symbols_[std::move(name)] = addr;
    }

    void add_xref(std::uint64_t to, std::uint64_t from, bool code) {
        xrefs_[to].push_back({from, code});
    }

    void set_match_error(std::string error) {
        match_error_ = std::move(error);
    }

    void set_match_exhausted(bool exhausted) noexcept {
        match_exhausted_ = exhausted;
    }

    std::optional<std::uint64_t> resolve_address(std::string_view query) const override {
        if (query.size() >= 2 && query[0] == '0' && (query[1] == 'x' || query[1] == 'X')) {
            try {
                return std::stoull(std::string(query.substr(2)), nullptr, 16);
            } catch (...) {
                return std::nullopt;
            }
        }
        auto it = symbols_.find(std::string(query));
        if (it != symbols_.end()) return it->second;
        return std::nullopt;
    }

    std::optional<signature_instruction_t> instruction_at(std::uint64_t address) const override {
        auto it = instructions_.find(address);
        if (it == instructions_.end()) return std::nullopt;
        signature_instruction_t insn;
        insn.address = it->second.address;
        insn.architecture = it->second.architecture;
        insn.bytes = it->second.bytes;
        insn.stable_mask = it->second.stable_mask;
        return insn;
    }

    std::optional<signature_function_t> function_containing(std::uint64_t address) const override {
        for (const auto& [name, func] : functions_) {
            if (address >= func.start && address < func.end) {
                return func;
            }
        }
        return std::nullopt;
    }

    std::vector<signature_xref_t> xrefs_to(std::uint64_t address) const override {
        auto it = xrefs_.find(address);
        if (it == xrefs_.end()) return {};
        return it->second;
    }

    bool read_bytes(std::uint64_t address, std::size_t size,
                    std::vector<std::uint8_t>& bytes) const override {
        if (address < base_ || address + size > base_ + memory_.size()) {
            return false;
        }
        std::size_t offset = static_cast<std::size_t>(address - base_);
        bytes.assign(memory_.begin() + offset, memory_.begin() + offset + size);
        return true;
    }

    signature_match_result_t find_matches(
        const std::vector<std::uint8_t>& bytes,
        const std::vector<std::uint8_t>& stable_mask,
        std::size_t maximum_results,
        const protocol::cancellation_token_t& cancellation) const override {
        signature_match_result_t result;
        result.exhausted = false;

        if (bytes.empty() || bytes.size() > memory_.size()) {
            result.exhausted = true;
            return result;
        }

        for (std::size_t offset = 0; offset + bytes.size() <= memory_.size(); ++offset) {
            if (cancellation.cancelled()) {
                result.exhausted = false;
                return result;
            }
            bool match = true;
            for (std::size_t i = 0; i < bytes.size(); ++i) {
                bool is_stable = (i < stable_mask.size() && stable_mask[i] == 0xFF);
                if (is_stable && memory_[offset + i] != bytes[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                result.addresses.push_back(base_ + offset);
                if (result.addresses.size() >= maximum_results) {
                    result.exhausted = true;
                    break;
                }
            }
        }

        if (!match_error_.empty()) {
            result.error = match_error_;
        }
        if (match_exhausted_) {
            result.exhausted = true;
        }

        return result;
    }

private:
    std::vector<std::uint8_t> memory_;
    std::uint64_t base_ = 0;
    std::unordered_map<std::uint64_t, fixture_instruction_t> instructions_;
    std::unordered_map<std::string, signature_function_t> functions_;
    std::unordered_map<std::string, std::uint64_t> symbols_;
    std::unordered_map<std::uint64_t, std::vector<signature_xref_t>> xrefs_;
    std::string match_error_;
    bool match_exhausted_ = false;
};

fixture_source_t make_x86_source() {
    fixture_source_t src;
    src.set_memory({
        0x55,
        0x8B, 0xEC,
        0x83, 0xEC, 0x40,
        0x56,
        0x57,
        0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00,
        0xE8, 0x10, 0x00, 0x00, 0x00,
        0x8B, 0x45, 0xFC,
        0x5F,
        0x5E,
        0x8B, 0xE5,
        0x5D,
        0xC3,
    }, 0x00401000);

    src.add_instruction(0x00401000, {0x55}, {0xFF}, signature_architecture_t::x86);
    src.add_instruction(0x00401001, {0x8B, 0xEC}, {0xFF, 0xFF}, signature_architecture_t::x86);
    src.add_instruction(0x00401003, {0x83, 0xEC, 0x40}, {0xFF, 0xFF, 0x00}, signature_architecture_t::x86);
    src.add_instruction(0x00401006, {0x56}, {0xFF}, signature_architecture_t::x86);
    src.add_instruction(0x00401007, {0x57}, {0xFF}, signature_architecture_t::x86);
    src.add_instruction(0x00401008, {0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00}, signature_architecture_t::x86);
    src.add_instruction(0x0040100F, {0xE8, 0x10, 0x00, 0x00, 0x00}, {0xFF, 0x00, 0x00, 0x00, 0x00}, signature_architecture_t::x86);
    src.add_instruction(0x00401014, {0x8B, 0x45, 0xFC}, {0xFF, 0x00, 0x00}, signature_architecture_t::x86);
    src.add_instruction(0x00401017, {0x5F}, {0xFF}, signature_architecture_t::x86);
    src.add_instruction(0x00401018, {0x5E}, {0xFF}, signature_architecture_t::x86);
    src.add_instruction(0x00401019, {0x8B, 0xE5}, {0xFF, 0xFF}, signature_architecture_t::x86);
    src.add_instruction(0x0040101B, {0x5D}, {0xFF}, signature_architecture_t::x86);
    src.add_instruction(0x0040101C, {0xC3}, {0xFF}, signature_architecture_t::x86);

    src.add_function("_main", 0x00401000, 0x0040101D);
    src.add_symbol("_main", 0x00401000);
    src.add_symbol("_data", 0x00403000);
    src.add_xref(0x00403000, 0x0040100F, true);

    return src;
}

fixture_source_t make_x64_source() {
    fixture_source_t src;
    src.set_memory({
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18,
        0x57,
        0x48, 0x83, 0xEC, 0x20,
        0xE8, 0x07, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x90,
        0xC3,
    }, 0x140001000);

    src.add_instruction(0x140001000, {0x48, 0x89, 0x5C, 0x24, 0x08}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x140001005, {0x48, 0x89, 0x6C, 0x24, 0x10}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x14000100A, {0x48, 0x89, 0x74, 0x24, 0x18}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x14000100F, {0x57}, {0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x140001010, {0x48, 0x83, 0xEC, 0x20}, {0xFF, 0xFF, 0xFF, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x140001014, {0xE8, 0x07, 0x00, 0x00, 0x00}, {0xFF, 0x00, 0x00, 0x00, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x140001019, {0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x140001020, {0x90}, {0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x140001021, {0xC3}, {0xFF}, signature_architecture_t::x64);

    src.add_function("main", 0x140001000, 0x140001022);
    src.add_function("helper", 0x140001000, 0x140001022);
    src.add_symbol("main", 0x140001000);
    src.add_symbol("helper", 0x140001000);
    src.add_symbol("data_ptr", 0x140003000);
    src.add_xref(0x140003000, 0x140001014, true);
    src.add_xref(0x140003000, 0x140001019, true);

    return src;
}

fixture_source_t make_arm_source() {
    fixture_source_t src;
    src.set_memory({
        0x04, 0x40, 0x2D, 0xE9,
        0x00, 0x00, 0xA0, 0xE3,
        0x00, 0x30, 0xA0, 0xE3,
        0x00, 0x20, 0xA0, 0xE3,
        0x01, 0x00, 0x00, 0xEB,
        0x00, 0x00, 0xA0, 0xE1,
        0x04, 0x80, 0xBD, 0xE8,
        0x1E, 0xFF, 0x2F, 0xE1,
    }, 0x00010000);

    src.add_instruction(0x00010000, {0x04, 0x40, 0x2D, 0xE9}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::arm);
    src.add_instruction(0x00010004, {0x00, 0x00, 0xA0, 0xE3}, {0xFF, 0x00, 0xFF, 0xFF}, signature_architecture_t::arm);
    src.add_instruction(0x00010008, {0x00, 0x30, 0xA0, 0xE3}, {0xFF, 0x00, 0xFF, 0xFF}, signature_architecture_t::arm);
    src.add_instruction(0x0001000C, {0x00, 0x20, 0xA0, 0xE3}, {0xFF, 0x00, 0xFF, 0xFF}, signature_architecture_t::arm);
    src.add_instruction(0x00010010, {0x01, 0x00, 0x00, 0xEB}, {0xFF, 0x00, 0x00, 0x00}, signature_architecture_t::arm);
    src.add_instruction(0x00010014, {0x00, 0x00, 0xA0, 0xE1}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::arm);
    src.add_instruction(0x00010018, {0x04, 0x80, 0xBD, 0xE8}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::arm);
    src.add_instruction(0x0001001C, {0x1E, 0xFF, 0x2F, 0xE1}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::arm);

    src.add_function("arm_entry", 0x00010000, 0x00010020);
    src.add_symbol("arm_entry", 0x00010000);
    src.add_symbol("arm_data", 0x00020000);
    src.add_xref(0x00020000, 0x00010010, true);

    return src;
}

fixture_source_t make_aarch64_source() {
    fixture_source_t src;
    src.set_memory({
        0xFD, 0x7B, 0x01, 0xA9,
        0xFD, 0x03, 0x00, 0x91,
        0x00, 0x00, 0x80, 0xD2,
        0x00, 0x01, 0x80, 0xD2,
        0x01, 0x00, 0x00, 0x94,
        0xFD, 0x7B, 0x41, 0xA9,
        0xC0, 0x03, 0x5F, 0xD6,
    }, 0x00080000);

    src.add_instruction(0x00080000, {0xFD, 0x7B, 0x01, 0xA9}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::aarch64);
    src.add_instruction(0x00080004, {0xFD, 0x03, 0x00, 0x91}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::aarch64);
    src.add_instruction(0x00080008, {0x00, 0x00, 0x80, 0xD2}, {0xFF, 0x00, 0xFF, 0xFF}, signature_architecture_t::aarch64);
    src.add_instruction(0x0008000C, {0x00, 0x01, 0x80, 0xD2}, {0xFF, 0x00, 0xFF, 0xFF}, signature_architecture_t::aarch64);
    src.add_instruction(0x00080010, {0x01, 0x00, 0x00, 0x94}, {0xFF, 0x00, 0x00, 0x00}, signature_architecture_t::aarch64);
    src.add_instruction(0x00080014, {0xFD, 0x7B, 0x41, 0xA9}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::aarch64);
    src.add_instruction(0x00080018, {0xC0, 0x03, 0x5F, 0xD6}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::aarch64);

    src.add_function("aarch64_main", 0x00080000, 0x0008001C);
    src.add_symbol("aarch64_main", 0x00080000);
    src.add_symbol("aarch64_data", 0x00090000);
    src.add_xref(0x00090000, 0x00080010, true);

    return src;
}

fixture_source_t make_mips_source() {
    fixture_source_t src;
    src.set_memory({
        0x27, 0xBD, 0xFF, 0xE0,
        0xAF, 0xBF, 0x00, 0x1C,
        0xAF, 0xA4, 0x00, 0x18,
        0x0C, 0x00, 0x02, 0x00,
        0x8F, 0xBF, 0x00, 0x1C,
        0x03, 0xE0, 0x00, 0x08,
        0x27, 0xBD, 0x00, 0x20,
    }, 0x00400000);

    src.add_instruction(0x00400000, {0x27, 0xBD, 0xFF, 0xE0}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::mips);
    src.add_instruction(0x00400004, {0xAF, 0xBF, 0x00, 0x1C}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::mips);
    src.add_instruction(0x00400008, {0xAF, 0xA4, 0x00, 0x18}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::mips);
    src.add_instruction(0x0040000C, {0x0C, 0x00, 0x02, 0x00}, {0xFF, 0x00, 0x00, 0x00}, signature_architecture_t::mips);
    src.add_instruction(0x00400010, {0x8F, 0xBF, 0x00, 0x1C}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::mips);
    src.add_instruction(0x00400014, {0x03, 0xE0, 0x00, 0x08}, {0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::mips);
    src.add_instruction(0x00400018, {0x27, 0xBD, 0x00, 0x20}, {0xFF, 0xFF, 0x00, 0x00}, signature_architecture_t::mips);

    src.add_function("mips_main", 0x00400000, 0x0040001C);
    src.add_symbol("mips_main", 0x00400000);
    src.add_symbol("mips_data", 0x00500000);
    src.add_xref(0x00500000, 0x0040000C, true);

    return src;
}

fixture_source_t make_relocation_source() {
    fixture_source_t src;
    src.set_memory({
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x57,
        0x48, 0x83, 0xEC, 0x20,
        0xE8, 0x07, 0x00, 0x00, 0x00,
        0xE8, 0x12, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD,
        0x90,
        0xC3,
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x57,
        0x48, 0x83, 0xEC, 0x30,
        0xE8, 0x07, 0x00, 0x00, 0x00,
        0xC3,
    }, 0x10000);

    src.add_instruction(0x10000, {0x48, 0x89, 0x5C, 0x24, 0x08}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x10005, {0x48, 0x89, 0x6C, 0x24, 0x10}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x1000A, {0x57}, {0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x1000B, {0x48, 0x83, 0xEC, 0x20}, {0xFF, 0xFF, 0xFF, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x1000F, {0xE8, 0x07, 0x00, 0x00, 0x00}, {0xFF, 0x00, 0x00, 0x00, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x10014, {0xE8, 0x12, 0x00, 0x00, 0x00}, {0xFF, 0x00, 0x00, 0x00, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x10019, {0x48, 0x8B, 0x05, 0xAA, 0xBB, 0xCC, 0xDD}, {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x10020, {0x90}, {0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x10021, {0xC3}, {0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x10022, {0x48, 0x89, 0x5C, 0x24, 0x08}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x10027, {0x48, 0x89, 0x6C, 0x24, 0x10}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x1002C, {0x57}, {0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x1002D, {0x48, 0x83, 0xEC, 0x30}, {0xFF, 0xFF, 0xFF, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x10031, {0xE8, 0x07, 0x00, 0x00, 0x00}, {0xFF, 0x00, 0x00, 0x00, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x10036, {0xC3}, {0xFF}, signature_architecture_t::x64);

    src.add_function("reloc_func_a", 0x10000, 0x10022);
    src.add_function("reloc_func_b", 0x10022, 0x10037);
    src.add_symbol("reloc_func_a", 0x10000);
    src.add_symbol("reloc_func_b", 0x10022);
    src.add_symbol("reloc_target", 0x20000);
    src.add_symbol("reloc_data", 0x30000);
    src.add_xref(0x20000, 0x1000F, true);
    src.add_xref(0x20000, 0x10014, true);
    src.add_xref(0x30000, 0x10019, true);
    src.add_xref(0x20000, 0x10031, true);

    return src;
}

fixture_source_t make_non_unique_source() {
    fixture_source_t src;
    src.set_memory({
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x57,
        0x48, 0x83, 0xEC, 0x20,
        0xC3,
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x57,
        0x48, 0x83, 0xEC, 0x20,
        0xC3,
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x57,
        0x48, 0x83, 0xEC, 0x40,
        0xC3,
    }, 0x4000);

    src.add_instruction(0x4000, {0x48, 0x89, 0x5C, 0x24, 0x08}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x4005, {0x48, 0x89, 0x6C, 0x24, 0x10}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x400A, {0x57}, {0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x400B, {0x48, 0x83, 0xEC, 0x20}, {0xFF, 0xFF, 0xFF, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x400F, {0xC3}, {0xFF}, signature_architecture_t::x64);

    src.add_instruction(0x4010, {0x48, 0x89, 0x5C, 0x24, 0x08}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x4015, {0x48, 0x89, 0x6C, 0x24, 0x10}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x401A, {0x57}, {0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x401B, {0x48, 0x83, 0xEC, 0x20}, {0xFF, 0xFF, 0xFF, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x401F, {0xC3}, {0xFF}, signature_architecture_t::x64);

    src.add_instruction(0x4020, {0x48, 0x89, 0x5C, 0x24, 0x08}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x4025, {0x48, 0x89, 0x6C, 0x24, 0x10}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x402A, {0x57}, {0xFF}, signature_architecture_t::x64);
    src.add_instruction(0x402B, {0x48, 0x83, 0xEC, 0x40}, {0xFF, 0xFF, 0xFF, 0x00}, signature_architecture_t::x64);
    src.add_instruction(0x402F, {0xC3}, {0xFF}, signature_architecture_t::x64);

    src.add_function("dup_a", 0x4000, 0x4010);
    src.add_function("dup_b", 0x4010, 0x4020);
    src.add_function("dup_c", 0x4020, 0x4030);
    src.add_symbol("dup_a", 0x4000);
    src.add_symbol("dup_b", 0x4010);
    src.add_symbol("dup_c", 0x4020);
    src.add_symbol("shared_target", 0x5000);
    src.add_xref(0x5000, 0x400A, true);
    src.add_xref(0x5000, 0x401A, true);
    src.add_xref(0x5000, 0x402A, true);

    return src;
}

fixture_source_t make_instruction_bound_source() {
    fixture_source_t src;
    src.set_memory({0x10, 0x20, 0x30, 0x40, 0x50, 0x90}, 0x6000);
    src.add_instruction(
        0x6000,
        {0x10, 0x20, 0x30, 0x40, 0x50},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    src.add_instruction(0x6005, {}, {});
    src.add_symbol("oversized_instruction", 0x6000);
    src.add_symbol("empty_instruction", 0x6005);
    return src;
}

fixture_source_t make_xref_policy_source() {
    fixture_source_t src;
    src.set_memory({0xA1, 0xB2, 0xC3, 0xD4}, 0x7000);
    src.add_instruction(0x7000, {0xA1}, {0xFF});
    src.add_instruction(0x7001, {0xB2}, {0xFF});
    src.add_instruction(0x7002, {0xC3}, {0xFF});
    src.add_instruction(0x7003, {0xD4}, {0xFF});
    src.add_symbol("xref_policy_target", 0x8000);
    src.add_xref(0x8000, 0x7002, true);
    src.add_xref(0x8000, 0x7003, false);
    src.add_xref(0x8000, 0x7000, true);
    src.add_xref(0x8000, 0x7001, true);
    return src;
}

void verify_contracts(protocol::schema_runtime_t& schemas) {
    constexpr std::array<std::string_view, 4> names{{
        "make_signature",
        "make_signature_for_function",
        "make_signature_for_range",
        "find_xref_signatures",
    }};
    for (std::string_view name : names) {
        require(is_signature_tool_name(name),
                "is_signature_tool_name failed for a known signature tool");
        const auto* descriptor = aida::standalone::mcp::compat::find_contract(name);
        require(descriptor != nullptr,
                "signature generated descriptor is missing");
        auto contract = signature_tool_contract(name);
        require(contract.name == name,
                "signature contract name mismatch");
        require(descriptor->adapter_symbol ==
                    "aida::standalone::mcp::compat::adapters::" + std::string(name),
                "signature adapter symbol mismatch");
        require(contract.target_policy.requirement == protocol::target_requirement_t::optional &&
                    contract.target_policy.accepts_pid &&
                    contract.target_policy.accepts_bin_name,
                "signature target routing policy is not the generated optional selector policy");
        require(contract.effect_policy.effect == protocol::tool_effect_t::workspace_read &&
                    contract.effect_policy.lock == protocol::effect_lock_t::workspace_shared &&
                    contract.effect_policy.read_only && !contract.effect_policy.unsafe,
                "signature effect policy is not generated shared workspace read");
        require(protocol::validate_tool_contract(contract, schemas).valid,
                "signature generated contract does not validate through the schema runtime");
    }
    require(!is_signature_tool_name("not_a_signature_tool"),
            "is_signature_tool_name returned true for an unknown tool");
}

void verify_limits() {
    signature_limits_t defaults{};
    require(defaults.valid(), "default signature limits should be valid");

    signature_limits_t zeroed{};
    zeroed.maximum_queries = 0;
    require(!zeroed.valid(), "zeroed maximum_queries should be invalid");

    signature_limits_t oversized{};
    oversized.maximum_queries = 129;
    require(!oversized.valid(), "oversized maximum_queries should be invalid");

    signature_limits_t oversized_sig{};
    oversized_sig.maximum_signature_bytes = 4097;
    require(!oversized_sig.valid(), "oversized maximum_signature_bytes should be invalid");

    signature_limits_t oversized_range{};
    oversized_range.maximum_range_bytes = 4097;
    require(!oversized_range.valid(), "oversized maximum_range_bytes should be invalid");

    signature_limits_t oversized_xrefs{};
    oversized_xrefs.maximum_xrefs_per_query = 4097;
    require(!oversized_xrefs.valid(), "oversized maximum_xrefs_per_query should be invalid");

    signature_limits_t oversized_top{};
    oversized_top.maximum_top = 65;
    require(!oversized_top.valid(), "oversized maximum_top should be invalid");

    signature_limits_t oversized_insn{};
    oversized_insn.maximum_instruction_bytes = 65;
    require(!oversized_insn.valid(), "oversized maximum_instruction_bytes should be invalid");
}

signature_handler_context_t make_context(fixture_source_t& source,
                                         protocol::schema_runtime_t& schemas) {
    signature_handler_context_t ctx;
    ctx.source = &source;
    ctx.schemas = &schemas;
    ctx.limits = {};
    return ctx;
}

void verify_architecture_fixtures(protocol::schema_runtime_t& schemas, std::size_t& completed) {
    {
        auto src = make_x86_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x00401000"}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "x86_arch", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["addr"] == "0x401000", "make_signature", "x86_arch", "addr mismatch");
        require_fixture(!r["signature"].is_null(), "make_signature", "x86_arch", "signature should not be null");
        require_fixture(r["format"] == "ida", "make_signature", "x86_arch", "format should be ida");
        require_fixture(r.value("unique", false) == true, "make_signature", "x86_arch",
                        "x86 prologue signature should be unique");
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x140001000"}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "x64_arch", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["addr"] == "0x140001000", "make_signature", "x64_arch", "addr mismatch");
        require_fixture(!r["signature"].is_null(), "make_signature", "x64_arch", "signature should not be null");
        require_fixture(r.value("unique", false) == true, "make_signature", "x64_arch",
                        "x64 prologue signature should be unique");
        ++completed;
    }

    {
        auto src = make_arm_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x00010000"}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "arm_arch", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["addr"] == "0x10000", "make_signature", "arm_arch", "addr mismatch");
        require_fixture(!r["signature"].is_null(), "make_signature", "arm_arch", "signature should not be null");
        require_fixture(r.value("unique", false) == true, "make_signature", "arm_arch",
                        "ARM prologue signature should be unique");
        ++completed;
    }

    {
        auto src = make_aarch64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x00080000"}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "aarch64_arch", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["addr"] == "0x80000", "make_signature", "aarch64_arch", "addr mismatch");
        require_fixture(!r["signature"].is_null(), "make_signature", "aarch64_arch", "signature should not be null");
        require_fixture(r.value("unique", false) == true, "make_signature", "aarch64_arch",
                        "AArch64 prologue signature should be unique");
        ++completed;
    }

    {
        auto src = make_mips_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x00400000"}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "mips_arch", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["addr"] == "0x400000", "make_signature", "mips_arch", "addr mismatch");
        require_fixture(!r["signature"].is_null(), "make_signature", "mips_arch", "signature should not be null");
        require_fixture(r.value("unique", false) == true, "make_signature", "mips_arch",
                        "MIPS prologue signature should be unique");
        ++completed;
    }

    {
        auto src = make_x86_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x00401000"}, {"format", "mask"}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "x86_mask_format", result.text());
        const auto& sig = result.structured_content()["result"][0]["signature"];
        require_fixture(sig.is_string(), "make_signature", "x86_mask_format", "signature should be string");
        const auto sig_str = sig.get<std::string>();
        require_fixture(sig_str.find('x') != std::string::npos, "make_signature", "x86_mask_format",
                        "mask format should contain x characters for stable bytes");
        require_fixture(sig_str.find('?') != std::string::npos, "make_signature", "x86_mask_format",
                        "mask format should contain ? characters for wildcarded operands");
        ++completed;
    }

    {
        auto src = make_arm_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x00010000"}, {"format", "bitmask"}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "arm_bitmask_format", result.text());
        const auto& sig = result.structured_content()["result"][0]["signature"];
        require_fixture(sig.is_string(), "make_signature", "arm_bitmask_format", "signature should be string");
        const auto sig_str = sig.get<std::string>();
        require_fixture(sig_str.find('1') != std::string::npos, "make_signature", "arm_bitmask_format",
                        "bitmask format should contain 1 characters for stable bytes");
        require_fixture(sig_str.find('0') != std::string::npos, "make_signature", "arm_bitmask_format",
                        "bitmask format should contain 0 characters for wildcarded operands");
        ++completed;
    }

    {
        auto src = make_x86_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "_main"}};
        auto result = adapters::make_signature_for_function(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_sig_func", "x86_func", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["addr"] == "0x401000", "make_sig_func", "x86_func", "addr should be function start");
        require_fixture(r["name"] == "_main", "make_sig_func", "x86_func", "name should be function name");
        require_fixture(!r["signature"].is_null(), "make_sig_func", "x86_func", "signature should not be null");
        require_fixture(!r.contains("unique"), "make_sig_func", "x86_func",
                        "function result must omit the schema-incompatible unique field");
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "main"}};
        auto result = adapters::make_signature_for_function(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_sig_func", "x64_func", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["addr"] == "0x140001000", "make_sig_func", "x64_func", "addr should be function start");
        require_fixture(r["name"] == "main", "make_sig_func", "x64_func", "name should be function name");
        require_fixture(!r["signature"].is_null(), "make_sig_func", "x64_func", "signature should not be null");
        require_fixture(!r.contains("unique"), "make_sig_func", "x64_func",
                        "function result must omit the schema-incompatible unique field");
        ++completed;
    }
}

void verify_relocation_fixtures(protocol::schema_runtime_t& schemas, std::size_t& completed) {
    {
        auto src = make_relocation_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x1000F"}, {"wildcard_operands", true}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "reloc_wildcarded", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(!r["signature"].is_null(), "make_signature", "reloc_wildcarded",
                        "signature should not be null for call instruction");
        const auto sig_str = r["signature"].get<std::string>();
        require_fixture(sig_str.find("??") != std::string::npos, "make_signature", "reloc_wildcarded",
                        "wildcarded call instruction should contain ?? in ida format");
        require_fixture(r.value("unique", false) == true, "make_signature", "reloc_wildcarded",
                        "wildcarded call instruction signature should be unique across functions");
        ++completed;
    }

    {
        auto src = make_relocation_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x1000F"}, {"wildcard_operands", false}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "reloc_no_wildcard", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(!r["signature"].is_null(), "make_signature", "reloc_no_wildcard",
                        "signature should not be null");
        const auto sig_str = r["signature"].get<std::string>();
        require_fixture(sig_str.find("E8") != std::string::npos, "make_signature", "reloc_no_wildcard",
                        "call opcode E8 should be present in signature");
        ++completed;
    }

    {
        auto src = make_relocation_source();
        auto ctx = make_context(src, schemas);
        json args{{"start", "0x10019"}, {"end", "0x10020"}, {"wildcard_operands", true}, {"format", "mask"}};
        auto result = adapters::make_signature_for_range(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_sig_range", "reloc_range_mask", result.text());
        const auto& range = result.structured_content();
        const auto& sig = range["signature"];
        require_fixture(sig.is_string(), "make_sig_range", "reloc_range_mask", "signature should be string");
        const auto sig_str = sig.get<std::string>();
        require_fixture(sig_str.find('?') != std::string::npos, "make_sig_range", "reloc_range_mask",
                        "rip-relative MOV range with wildcard should contain ? in mask format");
        require_fixture(sig_str.find('x') != std::string::npos, "make_sig_range", "reloc_range_mask",
                        "range should contain stable x bytes in mask format");
        require_fixture(range.contains("unique") && range["unique"] == true,
                        "make_sig_range", "reloc_range_mask",
                        "range result must retain its schema-compatible unique field");
        ++completed;
    }

    {
        auto src = make_relocation_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "reloc_target"}};
        auto result = adapters::find_xref_signatures(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "find_xref", "reloc_xref", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["addr"] == "0x20000", "find_xref", "reloc_xref", "addr should resolve to reloc_target");
        require_fixture(r["signatures"].is_array(), "find_xref", "reloc_xref", "signatures should be array");
        require_fixture(r["signatures"].size() >= 1, "find_xref", "reloc_xref",
                        "should have at least one xref signature for reloc_target");
        require_fixture(r.value("total_xrefs", 0) >= 3, "find_xref", "reloc_xref",
                        "reloc_target should have at least 3 xrefs");
        bool found_wildcarded = false;
        for (const auto& sig_entry : r["signatures"]) {
            require_fixture(sig_entry.value("unique", false) == true,
                            "find_xref", "reloc_xref",
                            "xref results must contain only unique signatures");
            if (sig_entry["signature"].is_string()) {
                const auto s = sig_entry["signature"].get<std::string>();
                if (s.find("??") != std::string::npos) {
                    found_wildcarded = true;
                }
            }
        }
        require_fixture(found_wildcarded, "find_xref", "reloc_xref",
                        "at least one xref signature should contain wildcarded relocation operands");
        ++completed;
    }
}

void verify_non_unique_fixtures(protocol::schema_runtime_t& schemas, std::size_t& completed) {
    {
        auto src = make_non_unique_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x4000"}, {"wildcard_operands", true}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "non_unique_wildcarded", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(!r["signature"].is_null(), "make_signature", "non_unique_wildcarded",
                        "signature should not be null");
        require_fixture(r.value("unique", true) == false, "make_signature", "non_unique_wildcarded",
                        "duplicate function prologue with wildcarded operands should NOT be unique");
        ++completed;
    }

    {
        auto src = make_non_unique_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x4000"}, {"wildcard_operands", false}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "non_unique_no_wildcard", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(!r["signature"].is_null(), "make_signature", "non_unique_no_wildcard",
                        "signature should not be null");
        require_fixture(r.value("unique", true) == false, "make_signature", "non_unique_no_wildcard",
                        "duplicate function prologue without wildcarding should NOT be unique");
        ++completed;
    }

    {
        auto src = make_non_unique_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x4020"}, {"wildcard_operands", true}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "non_unique_third_copy", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r.value("unique", true) == false, "make_signature", "non_unique_third_copy",
                        "third duplicate prologue should NOT be unique even with different stack adjust");
        ++completed;
    }

    {
        auto src = make_non_unique_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "shared_target"}};
        auto result = adapters::find_xref_signatures(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "find_xref", "non_unique_xref", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["addr"] == "0x5000", "find_xref", "non_unique_xref", "addr mismatch");
        require_fixture(r.value("total_xrefs", 0) == 3, "find_xref", "non_unique_xref",
                        "shared_target should have exactly 3 xrefs");
        require_fixture(r["signatures"].is_array(), "find_xref", "non_unique_xref",
                        "signatures should be array");
        require_fixture(r["signatures"].empty(), "find_xref", "non_unique_xref",
                        "non-unique xref signatures must be omitted");
        ++completed;
    }
}

void verify_bounds_fixtures(protocol::schema_runtime_t& schemas, std::size_t& completed) {
    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x140001000"}, {"max_length", 5}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "bounds_max_length", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(!r["signature"].is_null(), "make_signature", "bounds_max_length",
                        "signature should not be null with max_length=5");
        const auto sig_str = r["signature"].get<std::string>();
        std::size_t byte_count = 0;
        for (char c : sig_str) {
            if (c == ' ') ++byte_count;
        }
        ++byte_count;
        require_fixture(byte_count <= 5, "make_signature", "bounds_max_length",
                        "signature should be truncated to at most 5 bytes");
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x140001000"}, {"format", "unsupported"}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_INPUT_INVALID",
                        "make_signature", "bounds_invalid_format", "unsupported format was not rejected");
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", ""}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_INPUT_INVALID",
                        "make_signature", "bounds_empty_addr", "empty addr was not rejected");
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        auto cancel = cancellation_token_t::create();
        cancel.cancel();
        auto result = adapters::make_signature(ctx, {{"addrs", "0x140001000"}}, cancel);
        require_fixture(result.is_error() && result.error_code() == "MCP_TOOL_CANCELLED",
                        "make_signature", "bounds_cancelled", "pre-dispatch cancellation was not observed");
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"start", "0x140001005"}, {"end", "0x140001000"}};
        auto result = adapters::make_signature_for_range(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_sig_range", "bounds_inverted", result.text());
        require_fixture(result.structured_content()["signature"].is_null(),
                        "make_sig_range", "bounds_inverted", "signature should be null for inverted range");
        require_fixture(result.structured_content().value("error", std::string()) ==
                            "end_must_be_greater_than_start",
                        "make_sig_range", "bounds_inverted", "error should indicate inverted range");
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"start", "0x99999"}, {"end", "0x140001000"}};
        auto result = adapters::make_signature_for_range(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_sig_range", "bounds_unresolved_start", result.text());
        require_fixture(result.structured_content()["addr"].is_null(),
                        "make_sig_range", "bounds_unresolved_start",
                        "addr should be null for unresolved start");
        ++completed;
    }

    {
        auto src = make_relocation_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "reloc_target"}, {"top", 1}};
        auto result = adapters::find_xref_signatures(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "find_xref", "bounds_top_limit", result.text());
        require_fixture(result.structured_content()["result"][0]["signatures"].size() <= 1,
                        "find_xref", "bounds_top_limit",
                        "top=1 should return at most one signature");
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x140001000"}, {"max_length", 0}};
        auto result = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "bounds_zero_max_length", result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r.value("unique", false) == true,
                        "make_signature", "bounds_zero_max_length",
                        "with max_length=0 the default should still be applied and produce a unique signature");
        ++completed;
    }
}

void verify_failure_and_xref_policy_fixtures(
    protocol::schema_runtime_t& schemas,
    std::size_t& completed) {
    {
        auto src = make_xref_policy_source();
        src.set_match_error("injected_match_failure");
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x7000"}, {"max_length", 1}};
        auto result = adapters::make_signature(
            ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "match_error",
                        result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["signature"].is_string(), "make_signature", "match_error",
                        "matcher errors must not discard generated bytes");
        require_fixture(r.value("unique", true) == false,
                        "make_signature", "match_error",
                        "matcher errors must prevent uniqueness claims");
        ++completed;
    }

    {
        auto src = make_xref_policy_source();
        src.set_match_exhausted(true);
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x7000"}, {"max_length", 1}};
        auto result = adapters::make_signature(
            ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "match_exhausted",
                        result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r.value("unique", true) == false,
                        "make_signature", "match_exhausted",
                        "an exhausted matcher must prevent uniqueness claims");
        ++completed;
    }

    {
        auto src = make_xref_policy_source();
        src.set_match_error("injected_range_match_failure");
        auto ctx = make_context(src, schemas);
        json args{{"start", "0x7000"}, {"end", "0x7001"}};
        auto result = adapters::make_signature_for_range(
            ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_sig_range", "match_error",
                        result.text());
        const auto& r = result.structured_content();
        require_fixture(r["signature"].is_string(), "make_sig_range", "match_error",
                        "range matcher errors must not discard generated bytes");
        require_fixture(r.value("unique", true) == false,
                        "make_sig_range", "match_error",
                        "range matcher errors must prevent uniqueness claims");
        ++completed;
    }

    {
        auto src = make_xref_policy_source();
        src.set_match_exhausted(true);
        auto ctx = make_context(src, schemas);
        json args{{"start", "0x7000"}, {"end", "0x7001"}};
        auto result = adapters::make_signature_for_range(
            ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_sig_range", "match_exhausted",
                        result.text());
        const auto& r = result.structured_content();
        require_fixture(r.value("unique", true) == false,
                        "make_sig_range", "match_exhausted",
                        "an exhausted range matcher must prevent uniqueness claims");
        ++completed;
    }

    {
        auto src = make_instruction_bound_source();
        auto ctx = make_context(src, schemas);
        ctx.limits.maximum_instruction_bytes = 4;
        json args{{"addrs", "oversized_instruction"}};
        auto result = adapters::make_signature(
            ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_signature", "instruction_size",
                        result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r["signature"].is_null(),
                        "make_signature", "instruction_size",
                        "oversized instructions must not produce signatures");
        require_fixture(r.value("error", std::string()) ==
                            "instruction_size_out_of_bounds",
                        "make_signature", "instruction_size",
                        "oversized instructions must return the bounded error");
        ++completed;
    }

    {
        auto src = make_instruction_bound_source();
        auto ctx = make_context(src, schemas);
        ctx.limits.maximum_instruction_bytes = 4;
        json args{{"start", "0x6000"}, {"end", "0x6005"}};
        auto result = adapters::make_signature_for_range(
            ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_sig_range", "instruction_size",
                        result.text());
        const auto& r = result.structured_content();
        require_fixture(r["signature"].is_null(),
                        "make_sig_range", "instruction_size",
                        "wildcarded ranges must reject oversized instructions");
        require_fixture(r.value("error", std::string()) ==
                            "instruction_size_out_of_bounds",
                        "make_sig_range", "instruction_size",
                        "wildcarded range must return the bounded instruction error");
        ++completed;
    }

    {
        auto src = make_instruction_bound_source();
        auto ctx = make_context(src, schemas);
        json args{{"start", "empty_instruction"}, {"end", "0x6006"}};
        auto result = adapters::make_signature_for_range(
            ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "make_sig_range", "empty_instruction",
                        result.text());
        const auto& r = result.structured_content();
        require_fixture(r["signature"].is_null(),
                        "make_sig_range", "empty_instruction",
                        "empty decoded instructions must not stall range processing");
        require_fixture(r.value("error", std::string()) ==
                            "instruction_size_out_of_bounds",
                        "make_sig_range", "empty_instruction",
                        "empty decoded instructions must return the bounded error");
        ++completed;
    }

    {
        auto src = make_xref_policy_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "xref_policy_target"}};
        auto result = adapters::find_xref_signatures(
            ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "find_xref", "code_only",
                        result.text());
        const auto& r = result.structured_content()["result"][0];
        require_fixture(r.value("total_xrefs", 0) == 3,
                        "find_xref", "code_only",
                        "total_xrefs must count only code references");
        require_fixture(r["signatures"].size() == 3,
                        "find_xref", "code_only",
                        "only the three code xrefs should produce signatures");
        for (const auto& signature : r["signatures"]) {
            require_fixture(signature["addr"] != "0x7003",
                            "find_xref", "code_only",
                            "non-code xrefs must never produce signatures");
        }
        ++completed;
    }

    {
        auto src = make_xref_policy_source();
        auto ctx = make_context(src, schemas);
        ctx.limits.maximum_xrefs_per_query = 2;
        json args{{"addrs", "xref_policy_target"}};
        auto result = adapters::find_xref_signatures(
            ctx, args, cancellation_token_t::create());
        require_fixture(!result.is_error(), "find_xref", "sorted_cap",
                        result.text());
        const auto& r = result.structured_content()["result"][0];
        const auto& signatures = r["signatures"];
        require_fixture(r.value("total_xrefs", 0) == 3,
                        "find_xref", "sorted_cap",
                        "the deterministic cap must preserve the full code-xref count");
        require_fixture(signatures.size() == 2,
                        "find_xref", "sorted_cap",
                        "the xref cap must retain exactly two signatures");
        require_fixture(signatures[0]["addr"] == "0x7000" &&
                            signatures[1]["addr"] == "0x7001",
                        "find_xref", "sorted_cap",
                        "xrefs must be address-sorted before applying the cap");
        ++completed;
    }
}

void verify_deterministic_formatting_fixtures(protocol::schema_runtime_t& schemas,
                                              std::size_t& completed) {
    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x140001000"}, {"format", "ida"}};
        auto result1 = adapters::make_signature(ctx, args, cancellation_token_t::create());
        auto result2 = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result1.is_error() && !result2.is_error(),
                        "make_signature", "deterministic_ida", "both calls should succeed");
        const auto& sig1 = result1.structured_content()["result"][0]["signature"];
        const auto& sig2 = result2.structured_content()["result"][0]["signature"];
        require_fixture(sig1.is_string() && sig2.is_string(),
                        "make_signature", "deterministic_ida", "signatures should be strings");
        require_fixture(sig1 == sig2, "make_signature", "deterministic_ida",
                        "two identical ida format calls must produce identical output");
        const auto sig_str = sig1.get<std::string>();
        require_fixture(sig_str.find("48") != std::string::npos,
                        "make_signature", "deterministic_ida",
                        "ida format should contain hex byte 48 for REX prefix");
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x140001000"}, {"format", "mask"}};
        auto result1 = adapters::make_signature(ctx, args, cancellation_token_t::create());
        auto result2 = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result1.is_error() && !result2.is_error(),
                        "make_signature", "deterministic_mask", "both calls should succeed");
        const auto& sig1 = result1.structured_content()["result"][0]["signature"];
        const auto& sig2 = result2.structured_content()["result"][0]["signature"];
        require_fixture(sig1 == sig2, "make_signature", "deterministic_mask",
                        "two identical mask format calls must produce identical output");
        const auto sig_str = sig1.get<std::string>();
        for (char c : sig_str) {
            require_fixture(c == 'x' || c == '?', "make_signature", "deterministic_mask",
                            "mask format should only contain x or ? characters");
        }
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x140001000"}, {"format", "bitmask"}};
        auto result1 = adapters::make_signature(ctx, args, cancellation_token_t::create());
        auto result2 = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result1.is_error() && !result2.is_error(),
                        "make_signature", "deterministic_bitmask", "both calls should succeed");
        const auto& sig1 = result1.structured_content()["result"][0]["signature"];
        const auto& sig2 = result2.structured_content()["result"][0]["signature"];
        require_fixture(sig1 == sig2, "make_signature", "deterministic_bitmask",
                        "two identical bitmask format calls must produce identical output");
        const auto sig_str = sig1.get<std::string>();
        for (char c : sig_str) {
            require_fixture(c == '1' || c == '0', "make_signature", "deterministic_bitmask",
                            "bitmask format should only contain 1 or 0 characters");
        }
        ++completed;
    }

    {
        auto src = make_x64_source();
        auto ctx = make_context(src, schemas);
        json args{{"addrs", "0x140001000"}, {"format", "x64dbg"}};
        auto result1 = adapters::make_signature(ctx, args, cancellation_token_t::create());
        auto result2 = adapters::make_signature(ctx, args, cancellation_token_t::create());
        require_fixture(!result1.is_error() && !result2.is_error(),
                        "make_signature", "deterministic_x64dbg", "both calls should succeed");
        const auto& sig1 = result1.structured_content()["result"][0]["signature"];
        const auto& sig2 = result2.structured_content()["result"][0]["signature"];
        require_fixture(sig1 == sig2, "make_signature", "deterministic_x64dbg",
                        "two identical x64dbg format calls must produce identical output");
        const auto sig_str = sig1.get<std::string>();
        require_fixture(sig_str.find(" ") != std::string::npos || sig_str.find("??") != std::string::npos,
                        "make_signature", "deterministic_x64dbg",
                        "x64dbg format should contain space-separated bytes or ?? wildcards");
        ++completed;
    }
}

}

bool run_signature_handlers_harness(std::string& failure) {
    try {
        protocol::schema_runtime_t schemas(64);

        verify_contracts(schemas);
        verify_limits();

        std::size_t completed = 0;
        verify_architecture_fixtures(schemas, completed);
        verify_relocation_fixtures(schemas, completed);
        verify_non_unique_fixtures(schemas, completed);
        verify_bounds_fixtures(schemas, completed);
        verify_failure_and_xref_policy_fixtures(schemas, completed);
        verify_deterministic_formatting_fixtures(schemas, completed);

        require(completed == 38,
                "signature handler harness did not execute all thirty-eight fixture families");
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
