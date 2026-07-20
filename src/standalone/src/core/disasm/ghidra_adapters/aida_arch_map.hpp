#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "../../analysis/workspace/compact_ir.hpp"
#include "../../analysis/workspace/workspace_identity.hpp"

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
std::optional<arch_descriptor_t> detect_arch_from_workspace(
	const aida::analysis::workspace_identity_t& identity);

inline bool is_x86_family(const std::string& sleigh_id)
{
	return sleigh_id.size() >= 3 && sleigh_id.compare(0, 3, "x86") == 0;
}

}

namespace aida::analysis::ghidra_adapter {

enum class ghidra_language_family_t : std::uint8_t {
    x86 = 0,
    arm = 1,
    aarch64 = 2,
    mips = 3,
    powerpc = 4,
    riscv = 5
};

struct ghidra_language_request_t {
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    endian_t endian = endian_t::little;
    std::uint8_t address_width_bits = 0;
};

struct ghidra_language_spec_t {
    ghidra_language_family_t family = ghidra_language_family_t::x86;
    std::string language_id;
    std::string compiler_spec_id;
    std::string language_root;
    ghidra_language_request_t request;
};

struct ghidra_staged_language_t {
    std::string language_id;
    std::vector<std::string> compiler_spec_ids;
};

struct ghidra_language_catalog_t {
    std::string staging_root;
    std::vector<ghidra_staged_language_t> languages;
};

struct ghidra_adapter_revision_t {
    binary_id_t binary_id;
    sha256_digest_t load_profile_hash;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;

    bool matches(const ghidra_adapter_revision_t& other) const noexcept;
};

struct ghidra_adapter_cache_key_t {
    sha256_digest_t digest;
    ghidra_adapter_revision_t revision;
    std::string language_id;
    std::string compiler_spec_id;
};

workspace_result_t<ghidra_language_request_t> make_ghidra_language_request(
    const workspace_identity_t& identity, const cancellation_token_t& cancel = {});
workspace_result_t<ghidra_language_request_t> make_ghidra_language_request(
    const workspace_image_t& image, const cancellation_token_t& cancel = {});
workspace_result_t<ghidra_language_spec_t> resolve_ghidra_language(
    const ghidra_language_request_t& request, const cancellation_token_t& cancel = {});
workspace_result_t<ghidra_language_spec_t> resolve_ghidra_language(
    const workspace_identity_t& identity, const cancellation_token_t& cancel = {});
workspace_result_t<ghidra_language_spec_t> resolve_ghidra_language(
    const workspace_image_t& image, const cancellation_token_t& cancel = {});
workspace_result_t<void> require_staged_ghidra_language(
    const ghidra_language_spec_t& spec, const ghidra_language_catalog_t& catalog,
    const cancellation_token_t& cancel = {});
workspace_result_t<void> require_staged_ghidra_language(
    const ghidra_language_spec_t& spec, const std::string& staging_root,
    const cancellation_token_t& cancel = {});

workspace_result_t<ghidra_adapter_revision_t> make_ghidra_adapter_revision(
    const workspace_identity_t& identity, const analysis_snapshot_t& snapshot,
    const cancellation_token_t& cancel = {});
workspace_result_t<ghidra_adapter_cache_key_t> make_ghidra_adapter_cache_key(
    const ghidra_adapter_revision_t& revision, const ghidra_language_spec_t& spec,
    const cancellation_token_t& cancel = {});

}
