#include "aida_arch_map.hpp"
#include "../zydis_disasm.hpp"

#include <algorithm>
#include <cstring>
#include <new>
#include <utility>

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
	if (file.machine != 0)
		return file.machine;

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

std::optional<arch_descriptor_t> detect_arch_from_workspace(
	const aida::analysis::workspace_identity_t& identity)
{
	auto resolved =
		aida::analysis::ghidra_adapter::resolve_ghidra_language(identity);
	if (!resolved)
		return std::nullopt;

	const auto& language = resolved.value();
	arch_descriptor_t descriptor;
	descriptor.sleigh_id = language.language_id;
	descriptor.compiler_spec = language.compiler_spec_id;
	descriptor.bits = static_cast<int>(language.request.address_width_bits);
	descriptor.is_big_endian =
		language.request.endian == aida::analysis::endian_t::big;
	if (descriptor.sleigh_id.empty() || descriptor.compiler_spec.empty() ||
		(descriptor.bits != 16 && descriptor.bits != 32 && descriptor.bits != 64))
		return std::nullopt;
	return descriptor;
}

bool is_x86_family(const std::string& sleigh_id)
{
	if (sleigh_id.size() < 3)
		return false;
	return sleigh_id.compare(0, 3, "x86") == 0;
}

}

namespace aida::analysis::ghidra_adapter {

namespace {

workspace_result_t<void> stopped(const cancellation_token_t& cancel,
                                 const char* phase) {
    if (!cancel.stop_requested())
        return workspace_result_t<void>::success();
    auto error = make_workspace_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                  : workspace_error_code_t::cancelled,
        cancel.deadline_exceeded() ? "Ghidra adapter deadline exceeded"
                                  : "Ghidra adapter operation cancelled",
        phase);
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return workspace_result_t<void>::failure(std::move(error));
}

workspace_result_t<ghidra_language_spec_t> unsupported(
    workspace_error_code_t code, const char* message, const char* phase) {
    return workspace_result_t<ghidra_language_spec_t>::failure(
        make_workspace_error(code, message, phase));
}

bool native_format(format_id_t format) noexcept {
    switch (format) {
    case format_id_t::pe32:
    case format_id_t::pe32_plus:
    case format_id_t::elf:
    case format_id_t::macho:
    case format_id_t::macho_fat:
    case format_id_t::coff:
        return true;
    default:
        return false;
    }
}

bool managed_format(format_id_t format) noexcept {
    switch (format) {
    case format_id_t::jar:
    case format_id_t::dex:
    case format_id_t::oat:
    case format_id_t::vdex:
    case format_id_t::classfile:
        return true;
    default:
        return false;
    }
}

bool windows_abi(abi_id_t abi) noexcept {
    switch (abi) {
    case abi_id_t::windows_x86:
    case abi_id_t::windows_x64:
    case abi_id_t::windows_arm64:
    case abi_id_t::windows_arm64ec:
        return true;
    default:
        return false;
    }
}

bool elf_abi(abi_id_t abi) noexcept {
    switch (abi) {
    case abi_id_t::linux_x86:
    case abi_id_t::linux_x64:
    case abi_id_t::linux_arm:
    case abi_id_t::linux_aarch64:
    case abi_id_t::linux_mips:
    case abi_id_t::linux_ppc:
    case abi_id_t::linux_ppc64:
    case abi_id_t::linux_riscv:
    case abi_id_t::android_arm:
    case abi_id_t::android_aarch64:
    case abi_id_t::android_x86:
    case abi_id_t::android_x86_64:
    case abi_id_t::sysv:
        return true;
    default:
        return false;
    }
}

bool darwin_abi(abi_id_t abi) noexcept {
    return abi == abi_id_t::darwin || abi == abi_id_t::darwin_x86_64 ||
           abi == abi_id_t::darwin_aarch64;
}

bool abi_matches_format(format_id_t format, abi_id_t abi) noexcept {
    switch (format) {
    case format_id_t::pe32:
    case format_id_t::pe32_plus:
        return windows_abi(abi);
    case format_id_t::elf:
        return elf_abi(abi);
    case format_id_t::macho:
    case format_id_t::macho_fat:
        return darwin_abi(abi);
    case format_id_t::coff:
        return windows_abi(abi) || abi == abi_id_t::sysv;
    default:
        return false;
    }
}

bool abi_matches_architecture(architecture_id_t architecture, abi_id_t abi) noexcept {
    switch (architecture) {
    case architecture_id_t::x86:
        return abi == abi_id_t::windows_x86 || abi == abi_id_t::linux_x86 ||
               abi == abi_id_t::android_x86 || abi == abi_id_t::sysv;
    case architecture_id_t::x86_64:
        return abi == abi_id_t::windows_x64 || abi == abi_id_t::linux_x64 ||
               abi == abi_id_t::android_x86_64 || abi == abi_id_t::darwin ||
               abi == abi_id_t::darwin_x86_64 || abi == abi_id_t::sysv;
    case architecture_id_t::arm:
        return abi == abi_id_t::linux_arm || abi == abi_id_t::android_arm ||
               abi == abi_id_t::sysv;
    case architecture_id_t::aarch64:
        return abi == abi_id_t::windows_arm64 || abi == abi_id_t::linux_aarch64 ||
               abi == abi_id_t::android_aarch64 || abi == abi_id_t::darwin ||
               abi == abi_id_t::darwin_aarch64 || abi == abi_id_t::sysv;
    case architecture_id_t::mips:
    case architecture_id_t::mips64:
        return abi == abi_id_t::linux_mips || abi == abi_id_t::sysv;
    case architecture_id_t::ppc:
        return abi == abi_id_t::linux_ppc || abi == abi_id_t::sysv;
    case architecture_id_t::ppc64:
        return abi == abi_id_t::linux_ppc64 || abi == abi_id_t::sysv;
    case architecture_id_t::riscv:
    case architecture_id_t::riscv32:
    case architecture_id_t::riscv64:
        return abi == abi_id_t::linux_riscv || abi == abi_id_t::sysv;
    default:
        return false;
    }
}

const char* compiler_for_abi(abi_id_t abi) noexcept {
    if (windows_abi(abi))
        return "windows";
    if (elf_abi(abi))
        return "gcc";
    if (darwin_abi(abi))
        return "default";
    return "";
}

std::uint8_t expected_width(architecture_mode_t mode) noexcept {
    switch (mode) {
    case architecture_mode_t::x86_16:
        return 16;
    case architecture_mode_t::x86_32:
    case architecture_mode_t::arm_a32:
    case architecture_mode_t::arm_thumb:
    case architecture_mode_t::mips32:
    case architecture_mode_t::ppc32:
    case architecture_mode_t::riscv32:
        return 32;
    case architecture_mode_t::x86_64:
    case architecture_mode_t::aarch64:
    case architecture_mode_t::mips64:
    case architecture_mode_t::ppc64:
    case architecture_mode_t::riscv64:
        return 64;
    default:
        return 0;
    }
}

workspace_result_t<void> validate_request(const ghidra_language_request_t& request,
                                          const cancellation_token_t& cancel) {
    auto stop = stopped(cancel, "ghidra.arch.resolve");
    if (!stop)
        return stop;
    if (managed_format(request.format) ||
        request.architecture == architecture_id_t::jvm_bytecode ||
        request.architecture == architecture_id_t::dalvik_bytecode ||
        request.mode == architecture_mode_t::jvm ||
        request.mode == architecture_mode_t::dalvik || request.abi == abi_id_t::jvm ||
        request.abi == abi_id_t::dalvik) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "managed JVM and Dalvik targets do not have a staged native Ghidra language",
            "ghidra.arch.managed"));
    }
    if (!native_format(request.format)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "workspace format is not a directly loadable native Ghidra image",
            "ghidra.arch.format"));
    }
    if (request.architecture == architecture_id_t::arm64ec ||
        request.abi == abi_id_t::windows_arm64ec) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "ARM64EC hybrid ABI does not map to a single native Ghidra compiler specification",
            "ghidra.arch.arm64ec"));
    }
    if (!workspace_architecture_mode_matches(request.architecture, request.mode)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "workspace architecture and execution mode do not form a native Ghidra target",
            "ghidra.arch.mode"));
    }
    if ((request.architecture == architecture_id_t::x86 ||
         request.architecture == architecture_id_t::x86_64) &&
        request.endian != endian_t::little) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "x86 Ghidra languages are staged only for little-endian workspace images",
            "ghidra.arch.endian"));
    }
    const std::uint8_t width = expected_width(request.mode);
    if (width == 0 || request.address_width_bits != width) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "workspace address width does not match its native execution mode",
            "ghidra.arch.width"));
    }
    if (!abi_matches_format(request.format, request.abi) ||
        !abi_matches_architecture(request.architecture, request.abi)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "workspace format, architecture, and ABI do not form a supported native Ghidra target",
            "ghidra.arch.abi"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_spec(const ghidra_language_spec_t& spec,
                                       const cancellation_token_t& cancel) {
    auto request_valid = validate_request(spec.request, cancel);
    if (!request_valid)
        return request_valid;
    auto resolved = resolve_ghidra_language(spec.request, cancel);
    if (!resolved)
        return workspace_result_t<void>::failure(resolved.error());
    if (resolved.value().family != spec.family ||
        resolved.value().language_id != spec.language_id ||
        resolved.value().compiler_spec_id != spec.compiler_spec_id ||
        resolved.value().language_root != spec.language_root) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "Ghidra language specification does not match the workspace target",
            "ghidra.arch.spec"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_revision(const ghidra_adapter_revision_t& revision,
                                           const cancellation_token_t& cancel) {
    auto stop = stopped(cancel, "ghidra.cache.key");
    if (!stop)
        return stop;
    if (revision.binary_id.empty() || revision.load_profile_hash.empty() ||
        revision.generation == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "Ghidra adapter revision is incomplete",
            "ghidra.cache.key"));
    }
    return workspace_result_t<void>::success();
}

}

bool ghidra_adapter_revision_t::matches(const ghidra_adapter_revision_t& other) const noexcept {
    return binary_id == other.binary_id && load_profile_hash == other.load_profile_hash &&
           generation == other.generation && analysis_revision == other.analysis_revision &&
           overlay_revision == other.overlay_revision;
}

workspace_result_t<ghidra_language_request_t> make_ghidra_language_request(
    const workspace_identity_t& identity, const cancellation_token_t& cancel) {
    auto stop = stopped(cancel, "ghidra.arch.identity");
    if (!stop)
        return workspace_result_t<ghidra_language_request_t>::failure(stop.error());
    ghidra_language_request_t request;
    request.format = identity.format();
    request.architecture = identity.architecture();
    request.mode = identity.architecture_mode();
    request.abi = identity.abi();
    request.endian = identity.endian();
    request.address_width_bits = expected_width(request.mode);
    if (request.address_width_bits == 0)
        return workspace_result_t<ghidra_language_request_t>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "workspace execution mode does not have a native Ghidra address width",
            "ghidra.arch.identity"));
    return workspace_result_t<ghidra_language_request_t>::success(std::move(request));
}

workspace_result_t<ghidra_language_request_t> make_ghidra_language_request(
    const workspace_image_t& image, const cancellation_token_t& cancel) {
    auto validation = validate_workspace_image(image, {}, false, cancel);
    if (!validation)
        return workspace_result_t<ghidra_language_request_t>::failure(validation.error());
    ghidra_language_request_t request;
    request.format = image.format;
    request.architecture = image.architecture;
    request.mode = image.architecture_mode;
    request.abi = image.abi;
    request.endian = image.endian;
    request.address_width_bits = image.address_width_bits;
    return workspace_result_t<ghidra_language_request_t>::success(std::move(request));
}

workspace_result_t<ghidra_language_spec_t> resolve_ghidra_language(
    const ghidra_language_request_t& request, const cancellation_token_t& cancel) {
    auto request_valid = validate_request(request, cancel);
    if (!request_valid)
        return workspace_result_t<ghidra_language_spec_t>::failure(request_valid.error());

    ghidra_language_spec_t spec;
    spec.request = request;
    spec.compiler_spec_id = compiler_for_abi(request.abi);
    if (spec.compiler_spec_id.empty())
        return unsupported(workspace_error_code_t::unsupported_format,
                           "workspace ABI has no native Ghidra compiler specification",
                           "ghidra.arch.compiler");

    switch (request.architecture) {
    case architecture_id_t::x86:
        spec.family = ghidra_language_family_t::x86;
        spec.language_root = "x86";
        spec.language_id = request.mode == architecture_mode_t::x86_16
            ? "x86:LE:16:Real Mode" : "x86:LE:32:default";
        break;
    case architecture_id_t::x86_64:
        spec.family = ghidra_language_family_t::x86;
        spec.language_root = "x86";
        spec.language_id = "x86:LE:64:default";
        break;
    case architecture_id_t::arm:
        spec.family = ghidra_language_family_t::arm;
        spec.language_root = "ARM";
        spec.language_id = request.endian == endian_t::little
            ? "ARM:LE:32:v7" : "ARM:BE:32:v7";
        break;
    case architecture_id_t::aarch64:
        spec.family = ghidra_language_family_t::aarch64;
        spec.language_root = "AARCH64";
        spec.language_id = request.endian == endian_t::little
            ? "AARCH64:LE:64:v8A" : "AARCH64:BE:64:v8A";
        break;
    case architecture_id_t::mips:
        spec.family = ghidra_language_family_t::mips;
        spec.language_root = "MIPS";
        spec.language_id = request.endian == endian_t::little
            ? (request.mode == architecture_mode_t::mips64 ? "MIPS:LE:64:default"
                                                           : "MIPS:LE:32:default")
            : (request.mode == architecture_mode_t::mips64 ? "MIPS:BE:64:default"
                                                           : "MIPS:BE:32:default");
        break;
    case architecture_id_t::mips64:
        spec.family = ghidra_language_family_t::mips;
        spec.language_root = "MIPS";
        spec.language_id = request.endian == endian_t::little
            ? "MIPS:LE:64:default" : "MIPS:BE:64:default";
        break;
    case architecture_id_t::ppc:
        spec.family = ghidra_language_family_t::powerpc;
        spec.language_root = "PowerPC";
        spec.language_id = request.endian == endian_t::little
            ? "PowerPC:LE:32:default" : "PowerPC:BE:32:default";
        break;
    case architecture_id_t::ppc64:
        spec.family = ghidra_language_family_t::powerpc;
        spec.language_root = "PowerPC";
        spec.language_id = request.endian == endian_t::little
            ? "PowerPC:LE:64:default" : "PowerPC:BE:64:default";
        break;
    case architecture_id_t::riscv:
        spec.family = ghidra_language_family_t::riscv;
        spec.language_root = "RISCV";
        spec.language_id = request.mode == architecture_mode_t::riscv64
            ? "RISCV:LE:64:default" : "RISCV:LE:32:default";
        break;
    case architecture_id_t::riscv32:
        spec.family = ghidra_language_family_t::riscv;
        spec.language_root = "RISCV";
        spec.language_id = "RISCV:LE:32:default";
        break;
    case architecture_id_t::riscv64:
        spec.family = ghidra_language_family_t::riscv;
        spec.language_root = "RISCV";
        spec.language_id = "RISCV:LE:64:default";
        break;
    default:
        return unsupported(workspace_error_code_t::unsupported_format,
                           "workspace architecture has no staged native Ghidra language",
                           "ghidra.arch.architecture");
    }

    if (request.mode == architecture_mode_t::x86_16)
        spec.compiler_spec_id = "default";

    if (request.architecture == architecture_id_t::riscv ||
        request.architecture == architecture_id_t::riscv32 ||
        request.architecture == architecture_id_t::riscv64) {
        if (request.endian != endian_t::little)
            return unsupported(workspace_error_code_t::unsupported_format,
                               "big-endian RISC-V has no staged native Ghidra language",
                               "ghidra.arch.riscv");
    }
    return workspace_result_t<ghidra_language_spec_t>::success(std::move(spec));
}

workspace_result_t<ghidra_language_spec_t> resolve_ghidra_language(
    const workspace_identity_t& identity, const cancellation_token_t& cancel) {
    auto request = make_ghidra_language_request(identity, cancel);
    if (!request)
        return workspace_result_t<ghidra_language_spec_t>::failure(request.error());
    return resolve_ghidra_language(request.value(), cancel);
}

workspace_result_t<ghidra_language_spec_t> resolve_ghidra_language(
    const workspace_image_t& image, const cancellation_token_t& cancel) {
    auto request = make_ghidra_language_request(image, cancel);
    if (!request)
        return workspace_result_t<ghidra_language_spec_t>::failure(request.error());
    return resolve_ghidra_language(request.value(), cancel);
}

workspace_result_t<void> require_staged_ghidra_language(
    const ghidra_language_spec_t& spec, const ghidra_language_catalog_t& catalog,
    const cancellation_token_t& cancel) {
    auto spec_valid = validate_spec(spec, cancel);
    if (!spec_valid)
        return spec_valid;
    if (catalog.staging_root.empty() || catalog.staging_root.size() > 32768 ||
        catalog.languages.empty() || catalog.languages.size() > 256) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "Ghidra language catalog does not contain a bounded staged language set",
            "ghidra.arch.stage"));
    }
    for (const auto& language : catalog.languages) {
        auto stop = stopped(cancel, "ghidra.arch.stage");
        if (!stop)
            return stop;
        if (language.language_id.size() > 512 || language.compiler_spec_ids.size() > 64)
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "Ghidra language catalog contains an invalid staged language record",
                "ghidra.arch.stage"));
        if (language.language_id != spec.language_id)
            continue;
        for (const auto& compiler : language.compiler_spec_ids) {
            if (compiler.size() > 256)
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "Ghidra language catalog contains an invalid compiler specification",
                    "ghidra.arch.stage"));
            if (compiler == spec.compiler_spec_id)
                return workspace_result_t<void>::success();
        }
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_format,
            "the staged Ghidra language does not contain the required compiler specification",
            "ghidra.arch.stage"));
    }
    return workspace_result_t<void>::failure(make_workspace_error(
        workspace_error_code_t::unsupported_format,
        "the required Ghidra language family is not staged",
        "ghidra.arch.stage"));
}

workspace_result_t<ghidra_adapter_revision_t> make_ghidra_adapter_revision(
    const workspace_identity_t& identity, const analysis_snapshot_t& snapshot,
    const cancellation_token_t& cancel) {
    auto stop = stopped(cancel, "ghidra.revision");
    if (!stop)
        return workspace_result_t<ghidra_adapter_revision_t>::failure(stop.error());
    auto snapshot_valid = validate_analysis_snapshot(snapshot, false, cancel);
    if (!snapshot_valid)
        return workspace_result_t<ghidra_adapter_revision_t>::failure(snapshot_valid.error());
    if (identity.binary_id().empty() || identity.load_profile_hash().empty() ||
        snapshot.binary_id != identity.binary_id() ||
        snapshot.load_profile_hash != identity.load_profile_hash()) {
        return workspace_result_t<ghidra_adapter_revision_t>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "analysis snapshot identity does not match the Ghidra adapter workspace",
            "ghidra.revision"));
    }
    ghidra_adapter_revision_t revision;
    revision.binary_id = identity.binary_id();
    revision.load_profile_hash = identity.load_profile_hash();
    revision.generation = snapshot.generation;
    revision.analysis_revision = snapshot.analysis_revision;
    revision.overlay_revision = snapshot.overlay_revision;
    auto revision_valid = validate_revision(revision, cancel);
    if (!revision_valid)
        return workspace_result_t<ghidra_adapter_revision_t>::failure(revision_valid.error());
    return workspace_result_t<ghidra_adapter_revision_t>::success(std::move(revision));
}

workspace_result_t<ghidra_adapter_cache_key_t> make_ghidra_adapter_cache_key(
    const ghidra_adapter_revision_t& revision, const ghidra_language_spec_t& spec,
    const cancellation_token_t& cancel) {
    auto revision_valid = validate_revision(revision, cancel);
    if (!revision_valid)
        return workspace_result_t<ghidra_adapter_cache_key_t>::failure(revision_valid.error());
    auto spec_valid = validate_spec(spec, cancel);
    if (!spec_valid)
        return workspace_result_t<ghidra_adapter_cache_key_t>::failure(spec_valid.error());
    std::string material;
    try {
        material.reserve(512 + spec.language_id.size() + spec.compiler_spec_id.size() +
                         spec.language_root.size());
        material.append("aida-ghidra-adapter-v1|");
        material.append(revision.binary_id.to_hex());
        material.push_back('|');
        material.append(revision.load_profile_hash.to_hex());
        material.push_back('|');
        material.append(std::to_string(revision.generation));
        material.push_back('|');
        material.append(std::to_string(revision.analysis_revision));
        material.push_back('|');
        material.append(std::to_string(revision.overlay_revision));
        material.push_back('|');
        material.append(spec.language_id);
        material.push_back('|');
        material.append(spec.compiler_spec_id);
        material.push_back('|');
        material.append(spec.language_root);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<ghidra_adapter_cache_key_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "Ghidra adapter cache-key material allocation failed",
            "ghidra.cache.key"));
    }
    auto digest = sha256_text(material, cancel);
    if (!digest)
        return workspace_result_t<ghidra_adapter_cache_key_t>::failure(digest.error());
    ghidra_adapter_cache_key_t key;
    key.digest = digest.take_value();
    key.revision = revision;
    key.language_id = spec.language_id;
    key.compiler_spec_id = spec.compiler_spec_id;
    return workspace_result_t<ghidra_adapter_cache_key_t>::success(std::move(key));
}

}
