#include "workspace_registry.hpp"

#include "../../helpers/diag_log.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

namespace aida::analysis {

void workspace_registry_t::bind_preview_workspace(
    std::shared_ptr<analysis_workspace_t> workspace) {
    if (!workspace)
        return;
    std::unique_lock lock(mutex_);
    const auto id = workspace->identity().binary_id();
    workspaces_[id] = std::move(workspace);
    ui_selection_ = id;
}

void workspace_registry_t::clear_preview_workspaces() {
    std::unique_lock lock(mutex_);
    ui_selection_.reset();
    pe_coff_metadata_.clear();
    workspaces_.clear();
}

std::shared_ptr<analysis_workspace_t> workspace_registry_t::selected_for_ui() const {
    std::shared_lock lock(mutex_);
    if (!ui_selection_)
        return {};
    const auto iterator = workspaces_.find(*ui_selection_);
    if (iterator == workspaces_.end() || iterator->second->closing() || iterator->second->closed())
        return {};
    return iterator->second;
}

workspace_registry_t& workspace_registry() {
    static workspace_registry_t registry;
    return registry;
}

}

#else

#include "workspace_identity.hpp"
#include "decompiler_service.hpp"
#include "../decompiler/decompile_batch_orchestrator.hpp"
#include "workspace_database.hpp"
#include "overlay_journal.hpp"
#include "apk_container.hpp"
#include "classfile_parser.hpp"
#include "coff_image.hpp"
#include "dex_image.hpp"
#include "elf_image.hpp"
#include "ipa_container.hpp"
#include "jar_container.hpp"
#include "macho_image.hpp"
#include "zip_container.hpp"
#include "../readers/pe_coff_reader.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <new>
#include <string_view>
#include <utility>

namespace aida::analysis {
namespace {

const std::array<std::uint8_t, 23> default_static_profile{{
    'a','i','d','a','-','p','e','-','x','8','6','-','b','a','s','e','l','i','n','e','-','v','1'
}};

const std::array<std::uint8_t, 28> default_live_profile{{
    'a','i','d','a','-','p','e','-','x','8','6','-','l','i','v','e','-','s','n','a','p','s','h','o','t','-','v','1'
}};

const std::array<std::uint8_t, 23> default_raw_code_profile{{
    'a','i','d','a','-','r','a','w','-','c','o','d','e','-','s','t','a','t','i','c','-','v','1'
}};

class canonical_profile_writer_t final {
public:
    canonical_profile_writer_t() {
        const std::array<std::uint8_t, 16> domain{{
            'A','i','D','A','W','o','r','k','s','p','a','c','e','L','P',0
        }};
        bytes_.insert(bytes_.end(), domain.begin(), domain.end());
        append_u64(4);
    }

    void append_u64(std::uint64_t value) {
        for (std::size_t index = 0; index < 8; ++index)
            bytes_.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
    }

    void append_bytes(const void* data, std::size_t size) {
        append_u64(size);
        const auto* first = static_cast<const std::uint8_t*>(data);
        if (size != 0)
            bytes_.insert(bytes_.end(), first, first + size);
    }

    void append_text(const std::string& value) {
        append_bytes(value.data(), value.size());
    }

    void append_digest(const sha256_digest_t& value) {
        append_bytes(value.bytes.data(), value.bytes.size());
    }

    const std::vector<std::uint8_t>& bytes() const noexcept {
        return bytes_;
    }

private:
    std::vector<std::uint8_t> bytes_;
};

workspace_result_t<void> validate_profile_input(std::size_t size) {
    constexpr std::size_t maximum_profile_bytes = 1U << 20;
    if (size <= maximum_profile_bytes)
        return workspace_result_t<void>::success();
    auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                                      "workspace load profile exceeds its limit",
                                      "workspace_open");
    error.size = size;
    error.details.emplace_back("limit", std::to_string(maximum_profile_bytes));
    return workspace_result_t<void>::failure(std::move(error));
}

template <std::size_t Size>
void append_profile(canonical_profile_writer_t& writer,
                     const std::vector<std::uint8_t>& requested,
                     const std::array<std::uint8_t, Size>& fallback) {
    if (requested.empty())
        writer.append_bytes(fallback.data(), fallback.size());
    else
        writer.append_bytes(requested.data(), requested.size());
}

workspace_result_t<sha256_digest_t> profile_hash(const std::vector<std::uint8_t>& profile,
                                                 bool is_live,
                                                 const cancellation_token_t& cancel) {
    auto validation = validate_profile_input(profile.size());
    if (!validation)
        return workspace_result_t<sha256_digest_t>::failure(validation.error());
    canonical_profile_writer_t writer;
    writer.append_u64(is_live ? 1 : 0);
    if (is_live)
        append_profile(writer, profile, default_live_profile);
    else
        append_profile(writer, profile, default_static_profile);
    return sha256_bytes(writer.bytes().data(), writer.bytes().size(), cancel);
}

workspace_result_t<sha256_digest_t> bind_profile_identity(
    const sha256_digest_t& base_hash,
    format_id_t format, architecture_id_t architecture, abi_id_t abi,
    endian_t endian, std::uint64_t image_base,
    const live_snapshot_request_t* live_request,
    const cancellation_token_t& cancel) {
    canonical_profile_writer_t writer;
    writer.append_digest(base_hash);
    writer.append_u64(static_cast<std::uint64_t>(format));
    writer.append_u64(static_cast<std::uint64_t>(architecture));
    writer.append_u64(static_cast<std::uint64_t>(abi));
    writer.append_u64(static_cast<std::uint64_t>(endian));
    writer.append_u64(image_base);
    if (live_request) {
        writer.append_u64(static_cast<std::uint64_t>(live_request->capture_address.space));
        writer.append_u64(live_request->capture_address.value);
        writer.append_u64(static_cast<std::uint64_t>(live_request->capture_address.architecture));
        writer.append_u64(static_cast<std::uint64_t>(live_request->capture_address.mode));
        writer.append_u64(live_request->capture_size);
        writer.append_u64(live_request->maximum_capture_size);
        writer.append_u64(live_request->pid);
        writer.append_u64(live_request->module_base);
        writer.append_u64(live_request->module_size);
        writer.append_text(live_request->module_name);
        writer.append_text(live_request->module_path);
    }
    return sha256_bytes(writer.bytes().data(), writer.bytes().size(), cancel);
}

workspace_result_t<sha256_digest_t> canonical_static_profile_hash(
    const open_provider_workspace_request_t& request, const pe_image_t& image,
    const cancellation_token_t& cancel) {
    auto profile_validation = validate_profile_input(request.load_profile.size());
    if (!profile_validation)
        return workspace_result_t<sha256_digest_t>::failure(profile_validation.error());
    auto settings_validation = request.analysis_settings.validate();
    if (!settings_validation)
        return workspace_result_t<sha256_digest_t>::failure(settings_validation.error());
    const auto parser_profile = make_pe_parser_profile(request.pe_limits);
    auto parser_validation = validate_pe_parser_profile(parser_profile);
    if (!parser_validation)
        return workspace_result_t<sha256_digest_t>::failure(parser_validation.error());
    if (image.parser_profile() != parser_profile)
        return workspace_result_t<sha256_digest_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "parsed image profile differs from admission settings",
                                 "workspace_open.profile"));
    try {
        canonical_profile_writer_t writer;
        writer.append_u64(static_cast<std::uint64_t>(target_kind_t::static_file));
        append_profile(writer, request.load_profile, default_static_profile);
        writer.append_u64(request.provider_options.max_lease_size);
        writer.append_u64(request.provider_options.read_chunk_size);
        const auto parser_bytes = image.parser_profile().canonical_bytes();
        writer.append_bytes(parser_bytes.data(), parser_bytes.size());
        const auto analyzer_parser =
            make_pe_parser_profile(request.analysis_settings.pe_limits).canonical_bytes();
        writer.append_bytes(analyzer_parser.data(), analyzer_parser.size());
        writer.append_text(request.analysis_settings.canonical_json());
        writer.append_u64(static_cast<std::uint64_t>(image.format()));
        writer.append_u64(static_cast<std::uint64_t>(image.architecture()));
        writer.append_u64(static_cast<std::uint64_t>(image.architecture_mode()));
        writer.append_u64(static_cast<std::uint64_t>(image.abi()));
        writer.append_u64(static_cast<std::uint64_t>(image.endian()));
        writer.append_u64(image.image_base());
        writer.append_u64(image.image_size());
        writer.append_u64(static_cast<std::uint64_t>(image.artifact_kind()));
        return sha256_bytes(writer.bytes().data(), writer.bytes().size(), cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<sha256_digest_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "workspace load profile allocation failed",
                                 "workspace_open.profile"));
    }
}

workspace_result_t<sha256_digest_t> canonical_normalized_static_profile_hash(
    const open_provider_workspace_request_t& request, const workspace_image_t& image,
    const std::optional<provider_member_metadata_t>& member,
    const cancellation_token_t& cancel) {
    auto profile_validation = validate_profile_input(request.load_profile.size());
    if (!profile_validation)
        return workspace_result_t<sha256_digest_t>::failure(profile_validation.error());
    auto settings_validation = request.analysis_settings.validate();
    if (!settings_validation)
        return workspace_result_t<sha256_digest_t>::failure(settings_validation.error());
    try {
        canonical_profile_writer_t writer;
        writer.append_u64(static_cast<std::uint64_t>(target_kind_t::static_file));
        writer.append_u64(5);
        if (request.raw_code_profile)
            append_profile(writer, request.load_profile, default_raw_code_profile);
        else
            append_profile(writer, request.load_profile, default_static_profile);
        writer.append_u64(request.provider_options.max_lease_size);
        writer.append_u64(request.provider_options.read_chunk_size);
        const bool pe_image = image.format == format_id_t::pe32 ||
                              image.format == format_id_t::pe32_plus;
        writer.append_u64(pe_image ? 1 : 0);
        if (pe_image) {
            const auto parser_profile = make_pe_parser_profile(request.pe_limits);
            auto parser_validation = validate_pe_parser_profile(parser_profile);
            if (!parser_validation)
                return workspace_result_t<sha256_digest_t>::failure(parser_validation.error());
            const auto parser_bytes = parser_profile.canonical_bytes();
            writer.append_bytes(parser_bytes.data(), parser_bytes.size());
            const auto analyzer_parser =
                make_pe_parser_profile(request.analysis_settings.pe_limits).canonical_bytes();
            writer.append_bytes(analyzer_parser.data(), analyzer_parser.size());
        } else {
            writer.append_bytes(nullptr, 0);
            writer.append_bytes(nullptr, 0);
        }
        writer.append_u64(static_cast<std::uint64_t>(image.format));
        writer.append_u64(static_cast<std::uint64_t>(image.architecture));
        writer.append_u64(static_cast<std::uint64_t>(image.architecture_mode));
        writer.append_u64(static_cast<std::uint64_t>(image.abi));
        writer.append_u64(static_cast<std::uint64_t>(image.endian));
        writer.append_u64(image.address_width_bits);
        writer.append_u64(image.image_base);
        writer.append_u64(image.image_size);
        writer.append_u64(image.header_size);
        writer.append_text(image.format_name);
        if (request.raw_code_profile) {
            const auto& raw = *request.raw_code_profile;
            writer.append_u64(raw.schema_version);
            writer.append_u64(static_cast<std::uint64_t>(raw.architecture));
            writer.append_u64(static_cast<std::uint64_t>(raw.architecture_mode));
            writer.append_u64(static_cast<std::uint64_t>(raw.abi));
            writer.append_u64(static_cast<std::uint64_t>(raw.endian));
            writer.append_u64(raw.address_width_bits);
            writer.append_u64(raw.image_base);
            writer.append_u64(raw.code_file_offset);
            writer.append_u64(raw.code_rva);
            writer.append_u64(raw.code_size);
            writer.append_u64(raw.entry_rva);
            writer.append_text(raw.symbol_name);
        }
        writer.append_text(request.analysis_settings.canonical_json());
        writer.append_u64(member.has_value() ? 1 : 0);
        if (member) {
            writer.append_text(member->normalized_member_path);
            writer.append_u64(member->container_offset);
            writer.append_u64(member->compressed_size);
            writer.append_u64(member->uncompressed_size);
            writer.append_u64(member->ordinal);
            writer.append_u64(member->depth);
            writer.append_u64(member->crc32);
            writer.append_u64(member->compressed ? 1 : 0);
        }
        return sha256_bytes(writer.bytes().data(), writer.bytes().size(), cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<sha256_digest_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "normalized workspace load profile allocation failed",
                                 "workspace_open.profile"));
    }
}

struct live_header_attestation_t {
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    std::uint64_t preferred_image_base = 0;
    std::uint64_t image_size = 0;
    sha256_digest_t header_hash;
    live_snapshot_metadata_t metadata;
};

workspace_result_t<live_header_attestation_t> attest_live_headers(
    const live_snapshot_request_t& source, const cancellation_token_t& cancel) {
    auto header_request = source;
    header_request.capture_address.value = source.module_base;
    header_request.capture_size = std::min<std::uint64_t>(source.module_size, 1ULL << 20);
    header_request.maximum_capture_size = 1ULL << 20;
    if (header_request.capture_size < sizeof(IMAGE_DOS_HEADER) + sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32))
        return workspace_result_t<live_header_attestation_t>::failure(
            make_workspace_error(workspace_error_code_t::malformed_pe,
                                 "live module is too small to contain PE headers",
                                 "workspace_open.live_attestation"));
    auto captured = live_snapshot_provider_t::capture(header_request, cancel);
    if (!captured)
        return workspace_result_t<live_header_attestation_t>::failure(captured.error());
    auto lease = captured.value()->lease(0, captured.value()->size(), cancel);
    if (!lease)
        return workspace_result_t<live_header_attestation_t>::failure(lease.error());
    const auto* bytes = lease.value().data();
    const auto size = lease.value().size();
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, bytes, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
        return workspace_result_t<live_header_attestation_t>::failure(
            make_workspace_error(workspace_error_code_t::malformed_pe,
                                 "live module DOS header is invalid",
                                 "workspace_open.live_attestation"));
    const auto nt_offset = static_cast<std::uint64_t>(dos.e_lfanew);
    const auto fixed_size = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (nt_offset > size || fixed_size > size - nt_offset)
        return workspace_result_t<live_header_attestation_t>::failure(
            make_workspace_error(workspace_error_code_t::malformed_pe,
                                 "live module NT header is truncated",
                                 "workspace_open.live_attestation"));
    DWORD signature = 0;
    IMAGE_FILE_HEADER file{};
    std::memcpy(&signature, bytes + nt_offset, sizeof(signature));
    std::memcpy(&file, bytes + nt_offset + sizeof(signature), sizeof(file));
    const auto optional_offset = nt_offset + fixed_size;
    if (signature != IMAGE_NT_SIGNATURE || file.SizeOfOptionalHeader < sizeof(WORD) ||
        optional_offset > size || file.SizeOfOptionalHeader > size - optional_offset)
        return workspace_result_t<live_header_attestation_t>::failure(
            make_workspace_error(workspace_error_code_t::malformed_pe,
                                 "live module NT optional header is invalid",
                                 "workspace_open.live_attestation"));
    WORD magic = 0;
    std::memcpy(&magic, bytes + optional_offset, sizeof(magic));
    live_header_attestation_t result;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        file.Machine == IMAGE_FILE_MACHINE_AMD64 &&
        file.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
        IMAGE_OPTIONAL_HEADER64 optional{};
        std::memcpy(&optional, bytes + optional_offset, sizeof(optional));
        result.format = format_id_t::pe32_plus;
        result.architecture = architecture_id_t::x86_64;
        result.abi = abi_id_t::windows_x64;
        result.preferred_image_base = optional.ImageBase;
        result.image_size = optional.SizeOfImage;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
               file.Machine == IMAGE_FILE_MACHINE_I386 &&
               file.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
        IMAGE_OPTIONAL_HEADER32 optional{};
        std::memcpy(&optional, bytes + optional_offset, sizeof(optional));
        result.format = format_id_t::pe32;
        result.architecture = architecture_id_t::x86;
        result.abi = abi_id_t::windows_x86;
        result.preferred_image_base = optional.ImageBase;
        result.image_size = optional.SizeOfImage;
    } else {
        return workspace_result_t<live_header_attestation_t>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_pe_arch,
                                 "live module headers are not PE x86 or x86-64",
                                 "workspace_open.live_attestation"));
    }
    if (result.preferred_image_base == 0 || result.image_size == 0 ||
        result.image_size != source.module_size)
        return workspace_result_t<live_header_attestation_t>::failure(
            make_workspace_error(workspace_error_code_t::target_stale,
                                 "live module headers disagree with module generation",
                                 "workspace_open.live_attestation"));
    result.header_hash = captured.value()->metadata().capture_hash;
    result.metadata = captured.value()->metadata();
    return workspace_result_t<live_header_attestation_t>::success(std::move(result));
}

bool same_live_attestation(const live_header_attestation_t& lhs,
                           const live_header_attestation_t& rhs) noexcept {
    return lhs.format == rhs.format && lhs.architecture == rhs.architecture &&
        lhs.abi == rhs.abi &&
        lhs.preferred_image_base == rhs.preferred_image_base &&
        lhs.image_size == rhs.image_size && lhs.header_hash == rhs.header_hash &&
        lhs.metadata.process == rhs.metadata.process &&
        lhs.metadata.module.base == rhs.metadata.module.base &&
        lhs.metadata.module.size == rhs.metadata.module.size &&
        lhs.metadata.module.normalized_name == rhs.metadata.module.normalized_name &&
        lhs.metadata.module.normalized_path == rhs.metadata.module.normalized_path;
}

workspace_result_t<sha256_digest_t> canonical_live_profile_hash(
    const open_live_workspace_request_t& request,
    const live_header_attestation_t& attestation,
    const live_snapshot_metadata_t& metadata,
    const sha256_digest_t& module_generation_hash,
    const cancellation_token_t& cancel) {
    auto profile_validation = validate_profile_input(request.capture_profile.size());
    if (!profile_validation)
        return workspace_result_t<sha256_digest_t>::failure(profile_validation.error());
    try {
        canonical_profile_writer_t writer;
        writer.append_u64(static_cast<std::uint64_t>(target_kind_t::live_snapshot));
        append_profile(writer, request.capture_profile, default_live_profile);
        writer.append_u64(static_cast<std::uint64_t>(attestation.format));
        writer.append_u64(static_cast<std::uint64_t>(attestation.architecture));
        writer.append_u64(static_cast<std::uint64_t>(attestation.abi));
        writer.append_u64(static_cast<std::uint64_t>(endian_t::little));
        writer.append_u64(metadata.module.base);
        writer.append_u64(attestation.preferred_image_base);
        writer.append_u64(attestation.image_size);
        writer.append_u64(static_cast<std::uint64_t>(request.snapshot.capture_address.space));
        writer.append_u64(metadata.capture_address);
        writer.append_u64(static_cast<std::uint64_t>(request.snapshot.capture_address.architecture));
        writer.append_u64(static_cast<std::uint64_t>(request.snapshot.capture_address.mode));
        writer.append_u64(metadata.capture_size);
        writer.append_u64(request.snapshot.maximum_capture_size);
        writer.append_u64(metadata.process.pid);
        writer.append_u64(metadata.process.creation_time_100ns);
        writer.append_text(metadata.process.normalized_process_path);
        writer.append_u64(metadata.module.base);
        writer.append_u64(metadata.module.size);
        writer.append_text(metadata.module.normalized_name);
        writer.append_text(metadata.module.normalized_path);
        writer.append_digest(module_generation_hash);
        writer.append_digest(attestation.header_hash);
        writer.append_digest(metadata.capture_hash);
        return sha256_bytes(writer.bytes().data(), writer.bytes().size(), cancel);
    } catch (const std::bad_alloc&) {
        return workspace_result_t<sha256_digest_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "live workspace profile allocation failed",
                                 "workspace_open.profile"));
    }
}

workspace_error_t ambiguous_error(const std::vector<std::shared_ptr<analysis_workspace_t>>& matches) {
    auto error = make_workspace_error(workspace_error_code_t::target_ambiguous,
                                      "target selector matches more than one workspace",
                                      "workspace_resolve");
    constexpr std::size_t maximum_reported_candidates = 32;
    error.details.emplace_back("candidate_count", std::to_string(matches.size()));
    for (std::size_t index = 0;
         index < std::min(matches.size(), maximum_reported_candidates); ++index) {
        const auto& workspace = matches[index];
        const auto& name = workspace->identity().bin_name();
        error.details.emplace_back("candidate", workspace->identity().binary_id().to_hex() + ":" +
            name.substr(0, std::min<std::size_t>(name.size(), 256)));
    }
    return error;
}

workspace_result_t<std::shared_ptr<analysis_workspace_t>> validate_live_handle(
    std::shared_ptr<analysis_workspace_t> workspace) {
    if (!workspace)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "target workspace was not found", "workspace_resolve"));
    if (workspace->closing() || workspace->closed())
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_stale,
                                 "target workspace is closing or closed", "workspace_resolve"));
    if (workspace->target_kind() == target_kind_t::live_snapshot) {
        const auto snapshot = std::dynamic_pointer_cast<const live_snapshot_provider_t>(
            workspace->provider_handle());
        if (!snapshot)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "live workspace provider type is invalid", "workspace_resolve"));
        auto current = snapshot->validate_current_identity();
        if (!current)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(current.error());
    }
    return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::success(std::move(workspace));
}

struct parsed_static_image_t {
    std::shared_ptr<const byte_provider_t> provider;
    std::shared_ptr<const workspace_image_t> normalized;
    std::shared_ptr<const pe_image_t> pe_adapter;
    std::shared_ptr<const pe_coff_metadata_result_t> pe_coff_metadata;
};

workspace_result_t<parsed_static_image_t> read_pe_coff_static_image(
    std::shared_ptr<const byte_provider_t> provider, const pe_parse_limits_t& pe_limits,
    const cancellation_token_t& cancel) {
    pe_coff_reader_limits_t limits;
    limits.pe_limits = pe_limits;
    auto reader_result = read_pe_coff_metadata(*provider, limits, cancel);
    if (!reader_result)
        return workspace_result_t<parsed_static_image_t>::failure(reader_result.error());
    try {
        std::shared_ptr<const pe_coff_metadata_result_t> metadata =
            std::make_shared<pe_coff_metadata_result_t>(reader_result.take_value());
        parsed_static_image_t result;
        result.provider = std::move(provider);
        result.normalized = std::shared_ptr<const workspace_image_t>(metadata,
                                                                      &metadata->record.image);
        result.pe_adapter = metadata->pe_adapter;
        result.pe_coff_metadata = std::move(metadata);
        return workspace_result_t<parsed_static_image_t>::success(std::move(result));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<parsed_static_image_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "PE/COFF admission metadata allocation failed",
                                 "workspace_open.detect"));
    }
}

struct resolved_container_member_t {
    std::shared_ptr<const byte_provider_t> provider;
    std::optional<provider_member_metadata_t> metadata;
    std::shared_ptr<const workspace_image_t> normalized;
};

struct provider_probe_t {
    std::array<std::uint8_t, 16> bytes{};
    std::size_t size = 0;
};

workspace_result_t<provider_probe_t> read_provider_probe(const byte_provider_t& provider,
                                                          const cancellation_token_t& cancel) {
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "workspace format detection was cancelled", "workspace_open.detect");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<provider_probe_t>::failure(std::move(error));
    }
    provider_probe_t probe;
    probe.size = static_cast<std::size_t>((std::min)(provider.size(),
        static_cast<std::uint64_t>(probe.bytes.size())));
    if (probe.size == 0)
        return workspace_result_t<provider_probe_t>::failure(
            make_workspace_error(workspace_error_code_t::malformed_image,
                                 "workspace provider is empty", "workspace_open.detect"));
    auto read = provider.read_exact(0, probe.bytes.data(), probe.size, cancel);
    if (!read)
        return workspace_result_t<provider_probe_t>::failure(read.error());
    return workspace_result_t<provider_probe_t>::success(std::move(probe));
}

bool probe_starts_with(const provider_probe_t& probe,
                       std::initializer_list<std::uint8_t> expected) noexcept {
    return probe.size >= expected.size() &&
           std::equal(expected.begin(), expected.end(), probe.bytes.begin());
}

bool probe_is_zip(const provider_probe_t& probe) noexcept {
    return probe_starts_with(probe, {'P', 'K', 3, 4}) ||
           probe_starts_with(probe, {'P', 'K', 5, 6}) ||
           probe_starts_with(probe, {'P', 'K', 7, 8});
}

workspace_result_t<std::shared_ptr<const workspace_image_t>> make_normalized_image(
    workspace_image_t image) {
    try {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::success(
            std::make_shared<const workspace_image_t>(std::move(image)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "normalized image allocation failed", "workspace_open.parse"));
    }
}

std::uint8_t raw_code_address_width(architecture_mode_t mode) noexcept {
    switch (mode) {
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

bool raw_code_abi_matches(architecture_id_t architecture, abi_id_t abi) noexcept {
    switch (architecture) {
    case architecture_id_t::x86:
        return abi == abi_id_t::windows_x86 || abi == abi_id_t::linux_x86 ||
            abi == abi_id_t::android_x86 || abi == abi_id_t::darwin ||
            abi == abi_id_t::sysv;
    case architecture_id_t::x86_64:
        return abi == abi_id_t::windows_x64 || abi == abi_id_t::linux_x64 ||
            abi == abi_id_t::android_x86_64 || abi == abi_id_t::darwin ||
            abi == abi_id_t::darwin_x86_64 || abi == abi_id_t::sysv;
    case architecture_id_t::arm:
        return abi == abi_id_t::linux_arm || abi == abi_id_t::android_arm ||
            abi == abi_id_t::darwin || abi == abi_id_t::sysv;
    case architecture_id_t::aarch64:
        return abi == abi_id_t::windows_arm64 || abi == abi_id_t::linux_aarch64 ||
            abi == abi_id_t::android_aarch64 || abi == abi_id_t::darwin ||
            abi == abi_id_t::darwin_aarch64 || abi == abi_id_t::sysv;
    case architecture_id_t::arm64ec:
        return abi == abi_id_t::windows_arm64ec;
    case architecture_id_t::mips:
    case architecture_id_t::mips64:
        return abi == abi_id_t::linux_mips || abi == abi_id_t::sysv;
    case architecture_id_t::ppc:
        return abi == abi_id_t::linux_ppc || abi == abi_id_t::darwin ||
            abi == abi_id_t::sysv;
    case architecture_id_t::ppc64:
        return abi == abi_id_t::linux_ppc64 || abi == abi_id_t::darwin ||
            abi == abi_id_t::sysv;
    case architecture_id_t::riscv:
    case architecture_id_t::riscv32:
    case architecture_id_t::riscv64:
        return abi == abi_id_t::linux_riscv || abi == abi_id_t::sysv;
    default:
        return false;
    }
}

workspace_result_t<std::shared_ptr<const workspace_image_t>> make_raw_code_image(
    const byte_provider_t& provider, const raw_code_profile_t& profile,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "raw-code admission was cancelled", "workspace_open.raw_code");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            std::move(error));
    }
    const auto expected_width = raw_code_address_width(profile.architecture_mode);
    const bool endian_supported =
        ((profile.architecture != architecture_id_t::x86 &&
          profile.architecture != architecture_id_t::x86_64 &&
          profile.architecture != architecture_id_t::arm64ec &&
          profile.architecture != architecture_id_t::riscv &&
          profile.architecture != architecture_id_t::riscv32 &&
          profile.architecture != architecture_id_t::riscv64) ||
         profile.endian == endian_t::little);
    if (profile.schema_version != 1 || expected_width == 0 ||
        profile.address_width_bits != expected_width ||
        !workspace_architecture_mode_matches(profile.architecture,
                                             profile.architecture_mode) ||
        !raw_code_abi_matches(profile.architecture, profile.abi) ||
        profile.endian > endian_t::big || !endian_supported ||
        profile.symbol_name.empty() || profile.symbol_name.size() > 4096 ||
        profile.symbol_name.find('\0') != std::string::npos) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "raw-code architecture profile is invalid",
                                 "workspace_open.raw_code"));
    }
    if (profile.code_size == 0 || profile.code_file_offset > provider.size() ||
        profile.code_size > provider.size() - profile.code_file_offset) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "raw-code file range exceeds the provider",
                                          "workspace_open.raw_code");
        error.offset = profile.code_file_offset;
        error.size = profile.code_size;
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            std::move(error));
    }
    if (profile.code_rva > (std::numeric_limits<std::uint64_t>::max)() -
            profile.code_size) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "raw-code virtual range overflows",
                                 "workspace_open.raw_code"));
    }
    const auto code_end = profile.code_rva + profile.code_size;
    if (profile.entry_rva < profile.code_rva || profile.entry_rva >= code_end) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
                                          "raw-code entry is outside the executable range",
                                          "workspace_open.raw_code");
        error.offset = profile.entry_rva;
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            std::move(error));
    }
    const auto address_limit = profile.address_width_bits == 32
        ? (std::uint64_t{1} << 32)
        : (std::numeric_limits<std::uint64_t>::max)();
    if ((profile.address_width_bits == 32 &&
         (profile.image_base >= address_limit || code_end > address_limit - profile.image_base)) ||
        (profile.address_width_bits == 64 &&
         profile.image_base > address_limit - code_end)) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "raw-code mapped range exceeds the address width",
                                 "workspace_open.raw_code"));
    }
    try {
        workspace_image_t image;
        image.format = format_id_t::raw_code;
        image.architecture = profile.architecture;
        image.architecture_mode = profile.architecture_mode;
        image.abi = profile.abi;
        image.endian = profile.endian;
        image.address_width_bits = profile.address_width_bits;
        image.image_base = profile.image_base;
        image.image_size = code_end;
        image.header_size = 0;
        image.format_name = "raw_code";
        image.provider_size = provider.size();
        image.member = provider.member_metadata();

        image_address_mapping_t mapping;
        mapping.source_space = address_space_id_t::file_offset;
        mapping.target_space = address_space_id_t::relative_virtual;
        mapping.source_start = profile.code_file_offset;
        mapping.target_start = profile.code_rva;
        mapping.size = profile.code_size;
        mapping.permissions = image_permission_read | image_permission_execute;
        image.address_mappings.push_back(mapping);

        image_section_t section;
        section.index = 1;
        section.name = ".text";
        section.virtual_address = profile.code_rva;
        section.virtual_size = profile.code_size;
        section.file_offset = profile.code_file_offset;
        section.file_size = profile.code_size;
        section.permissions = image_permission_read | image_permission_execute;
        image.sections.push_back(section);

        const address_t entry{address_space_id_t::relative_virtual,
                              profile.entry_rva, profile.architecture,
                              profile.architecture_mode};
        image.entry_points.push_back({entry, "raw_profile"});
        image_symbol_t symbol;
        symbol.ordinal = 1;
        symbol.name = profile.symbol_name;
        symbol.address = entry;
        symbol.size = code_end - profile.entry_rva;
        symbol.kind = image_symbol_kind_t::function;
        symbol.binding = image_symbol_binding_t::global;
        symbol.defined = true;
        image.symbols.push_back(std::move(symbol));

        auto validation = validate_workspace_image(image, {}, false, cancel);
        if (!validation)
            return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
                validation.error());
        return make_normalized_image(std::move(image));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const workspace_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "raw-code normalized image allocation failed",
                                 "workspace_open.raw_code"));
    }
}

workspace_result_t<parsed_static_image_t> admit_fat_macho_slice(
    std::shared_ptr<const byte_provider_t> provider, fat_image_t fat,
    const cancellation_token_t& cancel) {
    const auto slice = std::find_if(fat.slices.begin(), fat.slices.end(),
        [](const fat_slice_t& candidate) {
            return candidate.image != nullptr && candidate.image->member.has_value();
        });
    if (slice == fat.slices.end())
        return workspace_result_t<parsed_static_image_t>::failure(
            make_workspace_error(workspace_error_code_t::malformed_image,
                                 "fat Mach-O has no bindable normalized slice",
                                 "workspace_open.detect"));
    auto member_provider = subrange_provider_t::create_member(provider, slice->offset, slice->size,
                                                                *slice->image->member);
    if (!member_provider)
        return workspace_result_t<parsed_static_image_t>::failure(member_provider.error());
    auto normalized = parse_macho(*member_provider.value(), cancel);
    if (!normalized)
        return workspace_result_t<parsed_static_image_t>::failure(normalized.error());
    parsed_static_image_t result;
    result.provider = std::static_pointer_cast<const byte_provider_t>(member_provider.take_value());
    result.normalized = normalized.take_value();
    return workspace_result_t<parsed_static_image_t>::success(std::move(result));
}

workspace_result_t<parsed_static_image_t> parse_static_image(
    std::shared_ptr<const byte_provider_t> provider, const pe_parse_limits_t& pe_limits,
    const std::optional<raw_code_profile_t>& raw_code_profile,
    const cancellation_token_t& cancel) {
    if (!provider)
        return workspace_result_t<parsed_static_image_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace provider is required", "workspace_open.detect"));
    if (raw_code_profile) {
        auto image = make_raw_code_image(*provider, *raw_code_profile, cancel);
        if (!image)
            return workspace_result_t<parsed_static_image_t>::failure(image.error());
        parsed_static_image_t result;
        result.provider = std::move(provider);
        result.normalized = image.take_value();
        return workspace_result_t<parsed_static_image_t>::success(std::move(result));
    }
    auto probe_result = read_provider_probe(*provider, cancel);
    if (!probe_result)
        return workspace_result_t<parsed_static_image_t>::failure(probe_result.error());
    const auto& probe = probe_result.value();
    const auto normalized = [&provider](std::shared_ptr<const workspace_image_t> image) {
        parsed_static_image_t result;
        result.provider = provider;
        result.normalized = std::move(image);
        return workspace_result_t<parsed_static_image_t>::success(std::move(result));
    };
    if (probe_starts_with(probe, {'M', 'Z'})) {
        return read_pe_coff_static_image(std::move(provider), pe_limits, cancel);
    }
    if (probe_starts_with(probe, {0x7f, 'E', 'L', 'F'})) {
        auto image = parse_elf(*provider, cancel);
        if (!image)
            return workspace_result_t<parsed_static_image_t>::failure(image.error());
        auto normalized_image = make_normalized_image(image.take_value());
        if (!normalized_image)
            return workspace_result_t<parsed_static_image_t>::failure(normalized_image.error());
        return normalized(normalized_image.take_value());
    }
    const bool class_or_fat = probe_starts_with(probe, {0xca, 0xfe, 0xba, 0xbe});
    if (class_or_fat) {
        auto classfile = parse_classfile(*provider, cancel);
        if (classfile)
            return normalized(classfile.take_value());
        auto fat = parse_fat_macho(*provider, cancel);
        if (!fat)
            return workspace_result_t<parsed_static_image_t>::failure(classfile.error());
        return admit_fat_macho_slice(std::move(provider), fat.take_value(), cancel);
    }
    if (probe_starts_with(probe, {0xca, 0xfe, 0xba, 0xbf}) ||
        probe_starts_with(probe, {0xbe, 0xba, 0xfe, 0xca}) ||
        probe_starts_with(probe, {0xbf, 0xba, 0xfe, 0xca})) {
        auto fat = parse_fat_macho(*provider, cancel);
        if (!fat)
            return workspace_result_t<parsed_static_image_t>::failure(fat.error());
        return admit_fat_macho_slice(std::move(provider), fat.take_value(), cancel);
    }
    if (probe_starts_with(probe, {0xce, 0xfa, 0xed, 0xfe}) ||
        probe_starts_with(probe, {0xcf, 0xfa, 0xed, 0xfe}) ||
        probe_starts_with(probe, {0xfe, 0xed, 0xfa, 0xce}) ||
        probe_starts_with(probe, {0xfe, 0xed, 0xfa, 0xcf})) {
        auto image = parse_macho(*provider, cancel);
        if (!image)
            return workspace_result_t<parsed_static_image_t>::failure(image.error());
        return normalized(image.take_value());
    }
    if (probe_starts_with(probe, {'d', 'e', 'x', '\n'}) ||
        probe_starts_with(probe, {'c', 'd', 'e', 'x'}) ||
        probe_starts_with(probe, {'o', 'a', 't', '\n'}) ||
        probe_starts_with(probe, {'v', 'd', 'e', 'x'})) {
        auto container = detect_dex_container(*provider, cancel);
        if (!container)
            return workspace_result_t<parsed_static_image_t>::failure(container.error());
        if (container.value().kind == dex_container_kind_t::unknown)
            return workspace_result_t<parsed_static_image_t>::failure(
                make_workspace_error(workspace_error_code_t::unsupported_format,
                                     "Android runtime container kind is unsupported",
                                     "workspace_open.detect"));
        auto image = parse_dex(*provider, cancel);
        if (!image)
            return workspace_result_t<parsed_static_image_t>::failure(image.error());
        auto normalized_image = make_normalized_image(image.take_value());
        if (!normalized_image)
            return workspace_result_t<parsed_static_image_t>::failure(normalized_image.error());
        return normalized(normalized_image.take_value());
    }
    if (probe_starts_with(probe, {'!', '<', 'a', 'r', 'c', 'h', '>', '\n'})) {
        return read_pe_coff_static_image(std::move(provider), pe_limits, cancel);
    }
    if (probe_is_zip(probe))
        return workspace_result_t<parsed_static_image_t>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_format,
                                 "ZIP-backed workspace admission requires a normalized member provider",
                                 "workspace_open.detect"));
    auto coff = is_coff_file(*provider, cancel);
    if (!coff)
        return workspace_result_t<parsed_static_image_t>::failure(coff.error());
    if (coff.value())
        return read_pe_coff_static_image(std::move(provider), pe_limits, cancel);
    return workspace_result_t<parsed_static_image_t>::failure(
        make_workspace_error(workspace_error_code_t::unsupported_format,
                             "workspace bytes do not identify a supported format",
                             "workspace_open.detect"));
}

workspace_result_t<resolved_container_member_t> bind_container_member(
    std::shared_ptr<byte_provider_t> provider, std::string_view expected_path,
    std::shared_ptr<const workspace_image_t> normalized = {}) {
    if (!provider)
        return workspace_result_t<resolved_container_member_t>::failure(
            make_workspace_error(workspace_error_code_t::provider_unavailable,
                                 "container did not provide the requested member",
                                 "workspace_open.container"));
    const auto& member = provider->member_metadata();
    if (!member || (!expected_path.empty() && member->normalized_member_path != expected_path))
        return workspace_result_t<resolved_container_member_t>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "container member metadata does not bind the requested member",
                                 "workspace_open.container"));
    resolved_container_member_t result;
    result.provider = std::static_pointer_cast<const byte_provider_t>(std::move(provider));
    result.metadata = *member;
    result.normalized = std::move(normalized);
    return workspace_result_t<resolved_container_member_t>::success(std::move(result));
}

workspace_result_t<resolved_container_member_t> resolve_zip_member(
    std::shared_ptr<const byte_provider_t> provider, const std::string& member_path,
    const cancellation_token_t& cancel) {
    if (!provider)
        return workspace_result_t<resolved_container_member_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "container provider is required", "workspace_open.container"));
    auto probe = read_provider_probe(*provider, cancel);
    if (!probe)
        return workspace_result_t<resolved_container_member_t>::failure(probe.error());
    if (!probe_is_zip(probe.value()))
        return workspace_result_t<resolved_container_member_t>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_format,
                                 "workspace member selection requires ZIP-backed bytes",
                                 "workspace_open.container"));

    auto ipa = ipa_container_t::open(provider, {}, cancel);
    if (ipa) {
        const auto* member = ipa.value()->find_member(member_path);
        if (member) {
            auto opened = ipa.value()->open_member_provider(member_path, cancel);
            if (!opened)
                return workspace_result_t<resolved_container_member_t>::failure(opened.error());
            return bind_container_member(opened.take_value(), member_path);
        }
    }

    auto apk = apk_container_t::open(provider, {}, cancel);
    if (apk) {
        const auto& members = apk.value()->members();
        const auto iterator = std::find_if(members.begin(), members.end(),
            [&member_path](const apk_code_member_t& member) {
                return member.normalized_path == member_path;
            });
        if (iterator != members.end()) {
            const auto index = static_cast<std::size_t>(iterator - members.begin());
            auto opened = apk.value()->open_member_provider(index, cancel);
            if (!opened)
                return workspace_result_t<resolved_container_member_t>::failure(opened.error());
            return bind_container_member(opened.take_value(), member_path);
        }
    }

    auto jar = jar_container_t::open(provider, {}, cancel);
    if (jar) {
        const auto nested_separator = member_path.find("!/");
        if (nested_separator != std::string::npos) {
            auto integrity = jar.value()->zip()->verify_integrity(cancel);
            if (!integrity)
                return workspace_result_t<resolved_container_member_t>::failure(integrity.error());
            const std::string outer_path = member_path.substr(0, nested_separator);
            const std::string nested_path = member_path.substr(nested_separator + 2);
            auto nested = jar.value()->open_nested_container(outer_path, cancel);
            if (!nested)
                return workspace_result_t<resolved_container_member_t>::failure(nested.error());
            auto nested_integrity = nested.value()->zip()->verify_integrity(cancel);
            if (!nested_integrity)
                return workspace_result_t<resolved_container_member_t>::failure(
                    nested_integrity.error());
            const auto* nested_member = nested.value()->find_member(nested_path);
            if (!nested_member)
                return workspace_result_t<resolved_container_member_t>::failure(
                    make_workspace_error(workspace_error_code_t::target_not_found,
                                         "nested JAR member path was not found",
                                         "workspace_open.container"));
            if (nested_member->is_class) {
                auto record = nested.value()->parse_class_member(nested_path, cancel);
                if (!record)
                    return workspace_result_t<resolved_container_member_t>::failure(record.error());
                auto normalized = make_normalized_image(std::move(record.value().classfile.normalized));
                if (!normalized)
                    return workspace_result_t<resolved_container_member_t>::failure(normalized.error());
                return bind_container_member(std::move(record.value().provider), {},
                                             normalized.take_value());
            }
            auto opened = nested.value()->open_member_provider(nested_path, cancel);
            if (!opened)
                return workspace_result_t<resolved_container_member_t>::failure(opened.error());
            return bind_container_member(opened.take_value(), {});
        }
        const auto* member = jar.value()->find_member(member_path);
        if (member) {
            auto integrity = jar.value()->zip()->verify_integrity(cancel);
            if (!integrity)
                return workspace_result_t<resolved_container_member_t>::failure(integrity.error());
            if (member->is_class) {
                auto record = jar.value()->parse_class_member(member_path, cancel);
                if (!record)
                    return workspace_result_t<resolved_container_member_t>::failure(record.error());
                auto normalized = make_normalized_image(std::move(record.value().classfile.normalized));
                if (!normalized)
                    return workspace_result_t<resolved_container_member_t>::failure(normalized.error());
                return bind_container_member(std::move(record.value().provider), member_path,
                                             normalized.take_value());
            }
            auto opened = jar.value()->open_member_provider(member_path, cancel);
            if (!opened)
                return workspace_result_t<resolved_container_member_t>::failure(opened.error());
            return bind_container_member(opened.take_value(), member_path);
        }
    }

    auto zip = zip_container_t::open(provider, {}, cancel);
    if (!zip)
        return workspace_result_t<resolved_container_member_t>::failure(zip.error());
    const auto* member = zip.value()->find_member(member_path);
    if (!member || member->kind != zip_member_kind_t::regular_file)
        return workspace_result_t<resolved_container_member_t>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "ZIP member path does not identify a regular file",
                                 "workspace_open.container"));
    auto integrity = zip.value()->verify_integrity(cancel);
    if (!integrity)
        return workspace_result_t<resolved_container_member_t>::failure(integrity.error());
    auto opened = zip.value()->open_member_provider(member_path, cancel);
    if (!opened)
        return workspace_result_t<resolved_container_member_t>::failure(opened.error());
    return bind_container_member(opened.take_value(), member_path);
}

}

workspace_result_t<std::shared_ptr<analysis_workspace_t>> workspace_registry_t::open_static(
    const open_static_workspace_request_t& request,
    const cancellation_token_t& cancel) {
    auto provider_result = mapped_file_provider_t::open(request.source_path,
                                                        request.provider_options);
    if (!provider_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            provider_result.error());
    auto root_provider = provider_result.take_value();
    open_provider_workspace_request_t admission;
    admission.provider = std::static_pointer_cast<const byte_provider_t>(root_provider);
    admission.bin_name = request.bin_name;
    admission.raw_code_profile = request.raw_code_profile;
    admission.load_profile = request.load_profile;
    admission.provider_options = request.provider_options;
    admission.pe_limits = request.pe_limits;
    admission.analysis_settings = request.analysis_settings;
    std::shared_ptr<const workspace_image_t> pre_parsed_image;
    if (request.member_path) {
        auto member = resolve_zip_member(admission.provider, *request.member_path, cancel);
        if (!member)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(member.error());
        admission.provider = member.value().provider;
        admission.member_metadata = member.value().metadata;
        pre_parsed_image = member.value().normalized;
    }
    return admit_provider_impl(admission, cancel, [root_provider] {
        return root_provider->revalidate();
    }, std::move(pre_parsed_image));
}

workspace_result_t<std::shared_ptr<analysis_workspace_t>>
workspace_registry_t::admit_verified_provider(const open_provider_workspace_request_t& request,
                                              const cancellation_token_t& cancel) {
    auto revalidate = [provider = request.provider]() -> workspace_result_t<void> {
        const auto mapped = std::dynamic_pointer_cast<const mapped_file_provider_t>(provider);
        if (!mapped)
            return workspace_result_t<void>::success();
        return mapped->revalidate();
    };
    return admit_provider_impl(request, cancel, revalidate);
}

workspace_result_t<std::shared_ptr<analysis_workspace_t>> workspace_registry_t::admit_provider_impl(
    const open_provider_workspace_request_t& request, const cancellation_token_t& cancel,
    const std::function<workspace_result_t<void>()>& revalidate,
    std::shared_ptr<const workspace_image_t> pre_parsed_image) {
    if (!request.provider)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace provider is required", "workspace_open.provider"));
    if (request.bin_name.size() > 32768)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace name is too long", "workspace_open.provider"));
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "workspace admission was cancelled", "workspace_open.provider");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(std::move(error));
    }

    const auto& provider_member = request.provider->member_metadata();
    if (request.member_metadata && (!provider_member ||
        *request.member_metadata != *provider_member)) {
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "requested member metadata does not match the provider",
                                 "workspace_open.provider"));
    }
    auto source_binding = analysis_workspace_t::verify_provider_binding(request.provider, cancel);
    if (!source_binding)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            source_binding.error());
    workspace_result_t<parsed_static_image_t> parsed = pre_parsed_image
        ? workspace_result_t<parsed_static_image_t>::success(
            parsed_static_image_t{request.provider, std::move(pre_parsed_image), {}, {}})
        : parse_static_image(request.provider, request.pe_limits,
                             request.raw_code_profile, cancel);
    if (!parsed)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(parsed.error());
    const auto admitted_provider = parsed.value().provider ? parsed.value().provider : request.provider;
    if (!parsed.value().normalized || !admitted_provider)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::malformed_image,
                                 "parser did not produce a normalized image",
                                 "workspace_open.provider"));
    if ((parsed.value().normalized->format == format_id_t::raw_code) !=
        request.raw_code_profile.has_value())
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "raw-code normalized image lacks its explicit admission profile",
                                 "workspace_open.provider"));
    auto provider_binding = admitted_provider == request.provider
        ? std::move(source_binding)
        : analysis_workspace_t::verify_provider_binding(admitted_provider, cancel);
    if (!provider_binding)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            provider_binding.error());
    const auto& admitted_member = admitted_provider->member_metadata();
    if (admitted_member && admitted_member->normalized_member_path.empty())
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "provider member metadata has an empty normalized path",
                                 "workspace_open.provider"));
    const std::optional<provider_member_metadata_t> member = admitted_member;
    if (revalidate) {
        auto revalidated = revalidate();
        if (!revalidated)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                revalidated.error());
    }

    if (admitted_provider == request.provider && request.provider_options.pin_sections) {
        const auto mapped =
            std::dynamic_pointer_cast<const mapped_file_provider_t>(admitted_provider);
        if (mapped) {
            const auto pin_ranges =
                compute_admission_pin_ranges(*parsed.value().normalized);
            if (!pin_ranges.empty()) {
                auto pinned = mapped->pin_ranges(pin_ranges);
                if (!pinned) {
                    ::diag::log_tagged_fmt("workspace_registry",
                        "admission section pins rejected source='%s' ranges=%zu error='%s'",
                        request.bin_name.c_str(), pin_ranges.size(),
                        pinned.error().message.c_str());
                } else {
                    ::diag::log_tagged_fmt("workspace_registry",
                        "admission section pins applied source='%s' ranges=%zu",
                        request.bin_name.c_str(), pin_ranges.size());
                }
            }
        }
    }

    workspace_result_t<sha256_digest_t> profile_hash_result = parsed.value().pe_adapter && !member
        ? canonical_static_profile_hash(request, *parsed.value().pe_adapter, cancel)
        : canonical_normalized_static_profile_hash(request, *parsed.value().normalized, member, cancel);
    if (!profile_hash_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            profile_hash_result.error());

    const auto& provider_source = provider_binding.value().normalized_source;
    constexpr std::string_view member_marker = "#member:";
    const auto first_member_marker = provider_source.find(member_marker);
    std::string identity_source = provider_source;
    if (!member && first_member_marker != std::string::npos)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                 "non-member provider contains a member source identity",
                                 "workspace_open.provider"));
    if (member && first_member_marker != std::string::npos) {
        if (first_member_marker == 0)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                     "provider member source identity has no container source",
                                     "workspace_open.provider"));
        std::string_view final_member_component;
        auto marker = first_member_marker;
        while (marker != std::string::npos) {
            const auto component_start = marker + member_marker.size();
            const auto next_marker = provider_source.find(member_marker, component_start);
            const auto component_end = next_marker == std::string::npos
                ? provider_source.size() : next_marker;
            const std::string_view component(provider_source.data() + component_start,
                                             component_end - component_start);
            bool normalized = !component.empty() && component.size() <= 32768 &&
                component.front() != '/' && component.find('\\') == std::string_view::npos &&
                component.find('\0') == std::string_view::npos;
            std::size_t path_component_start = 0;
            while (normalized && path_component_start < component.size()) {
                const auto separator = component.find('/', path_component_start);
                const auto path_component_end = separator == std::string_view::npos
                    ? component.size() : separator;
                const auto path_component_size = path_component_end - path_component_start;
                normalized = path_component_size != 0 &&
                    !(path_component_size == 1 && component[path_component_start] == '.') &&
                    !(path_component_size == 2 && component[path_component_start] == '.' &&
                      component[path_component_start + 1] == '.');
                if (separator == std::string_view::npos)
                    break;
                path_component_start = separator + 1;
            }
            if (!normalized)
                return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                    make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                         "provider member source identity is malformed",
                                         "workspace_open.provider"));
            final_member_component = component;
            marker = next_marker;
        }
        std::string encoded_member_path;
        encoded_member_path.reserve(member->normalized_member_path.size());
        constexpr char hex_digits[] = "0123456789ABCDEF";
        for (const char raw : member->normalized_member_path) {
            const auto byte = static_cast<unsigned char>(raw);
            if (byte == '%' || byte == '#') {
                encoded_member_path.push_back('%');
                encoded_member_path.push_back(hex_digits[byte >> 4U]);
                encoded_member_path.push_back(hex_digits[byte & 0x0fU]);
            } else {
                encoded_member_path.push_back(static_cast<char>(byte));
            }
        }
        if (final_member_component != member->normalized_member_path &&
            final_member_component != encoded_member_path)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                                     "provider member source identity disagrees with member metadata",
                                     "workspace_open.provider"));
        identity_source.assign(provider_source.data(), first_member_marker);
    }

    workspace_identity_input_t identity_input;
    identity_input.bin_name = request.bin_name;
    identity_input.source_path = std::move(identity_source);
    if (member)
        identity_input.member_path = member->normalized_member_path;
    identity_input.content_hash = provider_binding.value().content_hash;
    identity_input.load_profile_hash = profile_hash_result.take_value();
    identity_input.target_kind = target_kind_t::static_file;
    identity_input.format = parsed.value().normalized->format;
    identity_input.architecture = parsed.value().normalized->architecture;
    identity_input.architecture_mode = parsed.value().normalized->architecture_mode;
    identity_input.abi = parsed.value().normalized->abi;
    identity_input.endian = parsed.value().normalized->endian;
    identity_input.image_base = parsed.value().normalized->image_base;
    auto identity_result = make_workspace_identity(std::move(identity_input));
    if (!identity_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            identity_result.error());

    workspace_result_t<std::shared_ptr<analysis_workspace_t>> workspace_result =
        parsed.value().pe_adapter
            ? analysis_workspace_t::create(identity_result.take_value(), admitted_provider,
                                           parsed.value().pe_adapter, provider_binding.take_value(), cancel)
            : analysis_workspace_t::create_normalized(identity_result.take_value(), admitted_provider,
                                                       parsed.value().normalized,
                                                       provider_binding.take_value(), cancel);
    if (!workspace_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            workspace_result.error());
    return insert_or_get(workspace_result.take_value(),
                         std::move(parsed.value().pe_coff_metadata));
}

workspace_result_t<std::shared_ptr<analysis_workspace_t>> workspace_registry_t::open_live(
    const open_live_workspace_request_t& request,
    const cancellation_token_t& cancel) {
    if (request.bin_name.size() > 32768)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live workspace name is too long", "workspace_open"));
    if ((request.format != format_id_t::pe32 && request.format != format_id_t::pe32_plus) ||
        (request.architecture != architecture_id_t::x86 &&
         request.architecture != architecture_id_t::x86_64) ||
        (request.abi != abi_id_t::windows_x86 && request.abi != abi_id_t::windows_x64))
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::unsupported_pe_arch,
                                 "live workspace must be PE x86 or x86-64", "workspace_open"));
    if ((request.format == format_id_t::pe32 &&
         (request.architecture != architecture_id_t::x86 || request.abi != abi_id_t::windows_x86)) ||
        (request.format == format_id_t::pe32_plus &&
         (request.architecture != architecture_id_t::x86_64 || request.abi != abi_id_t::windows_x64)))
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live format, architecture, and ABI disagree", "workspace_open"));
    if (request.snapshot.capture_address.architecture != request.architecture ||
        (request.architecture == architecture_id_t::x86 &&
         request.snapshot.capture_address.mode != architecture_mode_t::x86_32) ||
        (request.architecture == architecture_id_t::x86_64 &&
         request.snapshot.capture_address.mode != architecture_mode_t::x86_64))
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live snapshot address architecture disagrees with the workspace",
                                 "workspace_open"));
    auto base_profile_hash = profile_hash(request.capture_profile, true, cancel);
    if (!base_profile_hash)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            base_profile_hash.error());
    auto provider_result = live_snapshot_provider_t::capture(request.snapshot, cancel);
    if (!provider_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            provider_result.error());
    const auto& metadata = provider_result.value()->metadata();
    auto attestation = attest_live_headers(request.snapshot, cancel);
    if (!attestation)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            attestation.error());
    if (!(attestation.value().metadata.process == metadata.process) ||
        attestation.value().metadata.module.base != metadata.module.base ||
        attestation.value().metadata.module.size != metadata.module.size ||
        attestation.value().metadata.module.normalized_name != metadata.module.normalized_name ||
        attestation.value().metadata.module.normalized_path != metadata.module.normalized_path)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_stale,
                                 "live capture and header module generations disagree",
                                 "workspace_open.live_attestation"));
    if (request.format != attestation.value().format ||
        request.architecture != attestation.value().architecture ||
        request.abi != attestation.value().abi)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "caller-declared live format disagrees with captured headers",
                                 "workspace_open.live_attestation"));
    const std::uint64_t image_base = request.image_base == 0 ? metadata.module.base
                                                             : request.image_base;
    if (image_base != metadata.module.base)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live image base does not match the captured module",
                                 "workspace_open"));
    auto canonical_live_request = request.snapshot;
    canonical_live_request.module_base = metadata.module.base;
    canonical_live_request.module_size = metadata.module.size;
    std::array<std::uint8_t, 64> live_profile_material{};
    std::copy(base_profile_hash.value().bytes.begin(), base_profile_hash.value().bytes.end(),
              live_profile_material.begin());
    std::copy(attestation.value().header_hash.bytes.begin(),
              attestation.value().header_hash.bytes.end(), live_profile_material.begin() + 32);
    auto attested_profile_base = sha256_bytes(live_profile_material.data(),
                                              live_profile_material.size(), cancel);
    if (!attested_profile_base)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            attested_profile_base.error());
    auto profile_hash_result = bind_profile_identity(
        attested_profile_base.value(), attestation.value().format,
        attestation.value().architecture, attestation.value().abi,
        endian_t::little, image_base, &canonical_live_request, cancel);
    if (!profile_hash_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            profile_hash_result.error());
    workspace_identity_input_t identity_input;
    identity_input.bin_name = request.bin_name.empty() ? metadata.module.normalized_name
                                                       : request.bin_name;
    identity_input.source_path = metadata.process.normalized_process_path;
    identity_input.member_path = metadata.module.normalized_name;
    identity_input.content_hash = metadata.capture_hash;
    identity_input.load_profile_hash = profile_hash_result.take_value();
    identity_input.target_kind = target_kind_t::live_snapshot;
    identity_input.format = attestation.value().format;
    identity_input.architecture = attestation.value().architecture;
    identity_input.abi = attestation.value().abi;
    identity_input.endian = endian_t::little;
    identity_input.image_base = image_base;
    identity_input.process = metadata.process;
    auto attested_module = metadata.module;
    attested_module.content_hash = attestation.value().header_hash;
    identity_input.module = std::move(attested_module);
    auto identity_result = make_workspace_identity(std::move(identity_input));
    if (!identity_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            identity_result.error());
    const auto provider_hash = metadata.capture_hash;
    auto provider = provider_result.take_value();
    workspace_provider_binding_t binding{provider_hash,
        provider->identity().normalized_source, provider->size()};
    auto workspace_result = analysis_workspace_t::create(
        identity_result.take_value(),
        std::static_pointer_cast<const byte_provider_t>(provider), {}, std::move(binding));
    if (!workspace_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            workspace_result.error());
    return insert_or_get(workspace_result.take_value());
}

workspace_result_t<std::shared_ptr<analysis_workspace_t>> workspace_registry_t::open_live_function(
    const open_live_function_request_t& request,
    const cancellation_token_t& cancel) {
    if (request.bin_name.size() > 32768)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live function workspace name is too long", "workspace_open"));
    if (request.snapshot.pid == 0)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live function snapshot PID must be positive", "workspace_open"));
    if (request.snapshot.function_va == 0 || request.snapshot.function_size == 0)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live function snapshot VA and size must be positive",
                                 "workspace_open"));
    auto provider_result = live_snapshot_provider_t::capture_function(request.snapshot, cancel);
    if (!provider_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            provider_result.error());
    const auto& metadata = provider_result.value()->metadata();

    live_snapshot_request_t snapshot_for_profile;
    snapshot_for_profile.pid = request.snapshot.pid;
    snapshot_for_profile.module_base = metadata.module.base;
    snapshot_for_profile.module_size = metadata.module.size;
    snapshot_for_profile.module_name = request.snapshot.module_name;
    snapshot_for_profile.module_path = request.snapshot.module_path;
    snapshot_for_profile.capture_address = address_t{address_space_id_t::live_virtual,
                                                      request.snapshot.function_va,
                                                      architecture_id_t::x86_64,
                                                      architecture_mode_t::x86_64};
    snapshot_for_profile.capture_size = metadata.capture_size;
    snapshot_for_profile.maximum_capture_size = request.snapshot.maximum_capture_size;

    auto base_profile_hash = profile_hash({}, true, cancel);
    if (!base_profile_hash)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            base_profile_hash.error());
    auto profile_hash_result = bind_profile_identity(
        base_profile_hash.value(), format_id_t::pe32_plus,
        architecture_id_t::x86_64, abi_id_t::windows_x64,
        endian_t::little, metadata.module.base,
        &snapshot_for_profile, cancel);
    if (!profile_hash_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            profile_hash_result.error());

    workspace_identity_input_t identity_input;
    identity_input.bin_name = request.bin_name.empty() ? metadata.module.normalized_name
                                                       : request.bin_name;
    identity_input.source_path = metadata.process.normalized_process_path;
    identity_input.member_path = metadata.module.normalized_name;
    identity_input.content_hash = metadata.capture_hash;
    identity_input.load_profile_hash = profile_hash_result.take_value();
    identity_input.target_kind = target_kind_t::live_snapshot;
    identity_input.format = format_id_t::pe32_plus;
    identity_input.architecture = architecture_id_t::x86_64;
    identity_input.abi = abi_id_t::windows_x64;
    identity_input.endian = endian_t::little;
    identity_input.image_base = metadata.module.base;
    identity_input.process = metadata.process;
    identity_input.module = metadata.module;
    auto identity_result = make_workspace_identity(std::move(identity_input));
    if (!identity_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            identity_result.error());

    const auto provider_hash = metadata.capture_hash;
    auto provider = provider_result.take_value();
    workspace_provider_binding_t binding{provider_hash,
        provider->identity().normalized_source, provider->size()};
    auto workspace_result = analysis_workspace_t::create(
        identity_result.take_value(),
        std::static_pointer_cast<const byte_provider_t>(provider), {}, std::move(binding));
    if (!workspace_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            workspace_result.error());
    auto workspace = workspace_result.take_value();

    workspace_database_versions_t versions;
    versions.engine_version = "aida-pe-workspace-engine-1";
    versions.specification_version = "pe-x86-zydis-4.1.1-ghidra-native-1";
    versions.analysis_settings_hash = workspace->identity().load_profile_hash().to_hex();

    workspace_database_options_t db_options;
    db_options.identity = workspace->identity_handle();
    db_options.versions = versions;
    auto db_result = workspace_database_t::open(db_options);
    if (!db_result)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            db_result.error());
    auto db_registered = workspace->register_lifecycle_participant(db_result.value());
    if (!db_registered) {
        auto existing_db = workspace->database();
        if (!existing_db)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                db_registered.error());
    } else {
        auto db_installed = workspace->install_database(db_result.value());
        if (!db_installed) {
            auto existing_db = workspace->database();
            if (!existing_db)
                return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                    db_installed.error());
        }
    }
    auto database = workspace->database();
    if (!database)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::service_conflict,
                                 "workspace database installation did not publish a service",
                                 "workspace_open.live_function"));

    auto db_queue = database->queue();
    if (db_queue) {
        auto queue_registered = workspace->register_lifecycle_participant(db_queue);
        if (queue_registered) {
            auto queue_installed = workspace->install_persistence_queue(db_queue);
            if (!queue_installed && !workspace->persistence_queue()) {
                return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                    queue_installed.error());
            }
        }
    }

    if (!workspace->overlay()) {
        auto overlay_result = overlay_journal_t::open(workspace, database);
        if (!overlay_result && !workspace->overlay())
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                overlay_result.error());
    }

    if (!workspace->decompiler()) {
        auto decompiler_result = decompiler_service_t::create(workspace, database, versions);
        if (!decompiler_result && !workspace->decompiler())
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                decompiler_result.error());
    }

    if (!workspace->background_decompile()) {
        (void)decompile_batch_orchestrator_t::create(workspace, workspace->background_metrics());
    }

    return insert_or_get(workspace);
}

workspace_result_t<workspace_admission_handle_t> workspace_registry_t::open_static_async(
    open_static_workspace_request_t request,
    std::function<void(workspace_result_t<std::shared_ptr<analysis_workspace_t>>)> completion,
    std::optional<std::chrono::steady_clock::time_point> deadline) {
    if (!completion)
        return workspace_result_t<workspace_admission_handle_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace admission completion is required",
                                 "workspace_open.async"));
    struct admission_state_t {
        std::shared_ptr<cancellation_source_t> cancellation;
        std::function<void(workspace_result_t<std::shared_ptr<analysis_workspace_t>>)> completion;
        std::atomic<bool> completed{false};

        void finish(workspace_result_t<std::shared_ptr<analysis_workspace_t>> result) {
            if (!completed.exchange(true, std::memory_order_acq_rel))
                completion(std::move(result));
        }
    };
    auto state = std::make_shared<admission_state_t>();
    state->cancellation = std::make_shared<cancellation_source_t>(deadline);
    state->completion = std::move(completion);
    auto request_state = std::make_shared<open_static_workspace_request_t>(std::move(request));
    aida::infra::taskflow_runtime::task_descriptor_t task;
    task.domain = aida::infra::taskflow_runtime::executor_domain_t::long_running;
    task.owner_subsystem = "analysis_workspace";
    task.label = "analysis.workspace.admission";
    task.thread_class = "bounded_file_admission";
    task.ui_access_policy = "none";
    task.failure_policy = "structured_completion";
    task.shutdown_policy = "cancel_and_drain";
    task.priority = request_state->analysis_settings.task_priority;
    if (deadline) {
        task.deadline_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline->time_since_epoch()).count());
    }
    task.cancel_hook = [state]() {
        state->cancellation->request_cancel();
        auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                          "workspace admission was cancelled",
                                          "workspace_open.async");
        error.cancellation = true;
        state->finish(workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            std::move(error)));
    };
    task.cancellable_body = [this, state, request_state](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
        if (runtime_cancel.requested.load(std::memory_order_acquire))
            state->cancellation->request_cancel();
        state->finish(open_static(*request_state, state->cancellation->token()));
    };
    auto submitted = aida::infra::taskflow_runtime::submit(std::move(task));
    if (!submitted.submitted)
        return workspace_result_t<workspace_admission_handle_t>::failure(
            make_workspace_error(workspace_error_code_t::service_conflict,
                "workspace admission task was rejected: " + submitted.reject_reason,
                "workspace_open.async"));
    return workspace_result_t<workspace_admission_handle_t>::success(
        workspace_admission_handle_t{submitted.handle, state->cancellation});
}

workspace_result_t<workspace_admission_handle_t>
workspace_registry_t::admit_verified_provider_async(
    open_provider_workspace_request_t request,
    std::function<void(workspace_result_t<std::shared_ptr<analysis_workspace_t>>)> completion,
    std::optional<std::chrono::steady_clock::time_point> deadline) {
    if (!completion)
        return workspace_result_t<workspace_admission_handle_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace admission completion is required",
                                 "workspace_open.provider_async"));
    struct admission_state_t {
        std::shared_ptr<cancellation_source_t> cancellation;
        std::function<void(workspace_result_t<std::shared_ptr<analysis_workspace_t>>)> completion;
        std::atomic<bool> completed{false};

        void finish(workspace_result_t<std::shared_ptr<analysis_workspace_t>> result) {
            if (!completed.exchange(true, std::memory_order_acq_rel))
                completion(std::move(result));
        }
    };
    auto state = std::make_shared<admission_state_t>();
    state->cancellation = std::make_shared<cancellation_source_t>(deadline);
    state->completion = std::move(completion);
    auto request_state = std::make_shared<open_provider_workspace_request_t>(std::move(request));
    aida::infra::taskflow_runtime::task_descriptor_t task;
    task.domain = aida::infra::taskflow_runtime::executor_domain_t::long_running;
    task.owner_subsystem = "analysis_workspace";
    task.label = "analysis.workspace.provider_admission";
    task.thread_class = "bounded_provider_admission";
    task.ui_access_policy = "none";
    task.failure_policy = "structured_completion";
    task.shutdown_policy = "cancel_and_drain";
    task.priority = request_state->analysis_settings.task_priority;
    if (deadline) {
        task.deadline_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline->time_since_epoch()).count());
    }
    task.cancel_hook = [state]() {
        state->cancellation->request_cancel();
        auto error = make_workspace_error(workspace_error_code_t::cancelled,
                                          "workspace provider admission was cancelled",
                                          "workspace_open.provider_async");
        error.cancellation = true;
        state->finish(workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            std::move(error)));
    };
    task.cancellable_body = [this, state, request_state](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
        if (runtime_cancel.requested.load(std::memory_order_acquire))
            state->cancellation->request_cancel();
        state->finish(admit_verified_provider(*request_state, state->cancellation->token()));
    };
    auto submitted = aida::infra::taskflow_runtime::submit(std::move(task));
    if (!submitted.submitted)
        return workspace_result_t<workspace_admission_handle_t>::failure(
            make_workspace_error(workspace_error_code_t::service_conflict,
                "workspace provider admission task was rejected: " + submitted.reject_reason,
                "workspace_open.provider_async"));
    return workspace_result_t<workspace_admission_handle_t>::success(
        workspace_admission_handle_t{submitted.handle, state->cancellation});
}

bool workspace_registry_t::cancel_admission(workspace_admission_handle_t& handle) noexcept {
    if (!handle.valid())
        return false;
    handle.cancellation->request_cancel();
    const bool cancelled = aida::infra::taskflow_runtime::cancel(handle.job);
    handle.job = {};
    return cancelled;
}

workspace_result_t<std::shared_ptr<analysis_workspace_t>> workspace_registry_t::insert_or_get(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::shared_ptr<const pe_coff_metadata_result_t> pe_coff_metadata) {
    if (!workspace)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace insertion received null", "workspace_open"));
    std::unique_lock lock(mutex_);
    const auto exact = workspaces_.find(workspace->identity().binary_id());
    if (exact != workspaces_.end() && !exact->second->closed()) {
        if (exact->second->closing())
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                make_workspace_error(workspace_error_code_t::workspace_closing,
                                     "matching workspace is closing", "workspace_open"));
        auto binding_check = exact->second->verify_provider_binding();
        if (!binding_check)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                binding_check.error());
        if (pe_coff_metadata && pe_coff_metadata_.find(workspace->identity().binary_id()) ==
                                    pe_coff_metadata_.end())
            pe_coff_metadata_.emplace(workspace->identity().binary_id(), std::move(pe_coff_metadata));
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::success(exact->second);
    }
    if (workspace->identity().process() && workspace->identity().module()) {
        for (const auto& pair : workspaces_) {
            const auto& identity = pair.second->identity();
            if (!pair.second->closing() && !pair.second->closed() &&
                identity.process() && identity.module() &&
                *identity.process() == *workspace->identity().process() &&
                identity.module()->base == workspace->identity().module()->base) {
                if (*identity.module() == *workspace->identity().module() &&
                    identity.load_profile_hash() == workspace->identity().load_profile_hash() &&
                    identity.content_hash() == workspace->identity().content_hash())
                    return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::success(pair.second);
                auto error = make_workspace_error(workspace_error_code_t::target_stale,
                    "live module generation changed at an existing module base",
                    "workspace_open");
                error.details.emplace_back("existing_binary_id",
                    identity.binary_id().to_hex());
                return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                    std::move(error));
            }
        }
    }
    constexpr std::size_t maximum_open_workspaces = 4096;
    if (workspaces_.size() >= maximum_open_workspaces)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "open workspace limit is reached", "workspace_open"));
    pe_coff_metadata_.erase(workspace->identity().binary_id());
    workspaces_[workspace->identity().binary_id()] = workspace;
    if (pe_coff_metadata)
        pe_coff_metadata_.emplace(workspace->identity().binary_id(), std::move(pe_coff_metadata));
    if (!ui_selection_)
        ui_selection_ = workspace->identity().binary_id();
    return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::success(std::move(workspace));
}

workspace_result_t<void> workspace_registry_t::close(
    const binary_id_t& id, std::chrono::steady_clock::time_point deadline) {
    std::shared_ptr<analysis_workspace_t> workspace;
    {
        std::shared_lock lock(mutex_);
        const auto iterator = workspaces_.find(id);
        if (iterator == workspaces_.end())
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::target_not_found,
                                     "workspace was not found", "workspace_close"));
        workspace = iterator->second;
    }
    auto close_result = workspace->close(deadline);
    if (!close_result)
        return close_result;
    std::unique_lock lock(mutex_);
    const auto iterator = workspaces_.find(id);
    if (iterator != workspaces_.end() && iterator->second == workspace) {
        workspaces_.erase(iterator);
        pe_coff_metadata_.erase(id);
    }
    if (ui_selection_ && *ui_selection_ == id)
        ui_selection_.reset();
    return workspace_result_t<void>::success();
}

std::shared_ptr<analysis_workspace_t> workspace_registry_t::find_by_binary_id(
    const binary_id_t& id) const {
    std::shared_lock lock(mutex_);
    const auto iterator = workspaces_.find(id);
    return iterator == workspaces_.end() ? std::shared_ptr<analysis_workspace_t>{}
                                         : iterator->second;
}

std::shared_ptr<const pe_coff_metadata_result_t>
workspace_registry_t::find_pe_coff_metadata(const binary_id_t& id) const {
    std::shared_lock lock(mutex_);
    const auto iterator = pe_coff_metadata_.find(id);
    return iterator == pe_coff_metadata_.end()
        ? std::shared_ptr<const pe_coff_metadata_result_t>{} : iterator->second;
}

std::vector<std::shared_ptr<analysis_workspace_t>>
workspace_registry_t::find_by_exact_name_or_path(const std::string& name_or_path) const {
    const std::string normalized_name = normalize_target_name(name_or_path);
    auto path_result = normalize_utf8_path(name_or_path, false);
    const std::optional<std::string> normalized_path = path_result
        ? std::optional<std::string>(normalize_target_name(path_result.value()))
        : std::nullopt;
    std::vector<std::shared_ptr<analysis_workspace_t>> matches;
    std::shared_lock lock(mutex_);
    for (const auto& pair : workspaces_) {
        if (pair.second->closing() || pair.second->closed())
            continue;
        const auto& identity = pair.second->identity();
        if (normalize_target_name(identity.bin_name()) == normalized_name ||
            (normalized_path &&
             normalize_target_name(identity.normalized_source_path()) ==
                 *normalized_path))
            matches.push_back(pair.second);
    }
    std::sort(matches.begin(), matches.end(), [](const auto& lhs, const auto& rhs) {
        return lhs->identity().binary_id() < rhs->identity().binary_id();
    });
    return matches;
}

std::shared_ptr<analysis_workspace_t> workspace_registry_t::find_by_pid(
    std::uint32_t pid, std::optional<std::uint64_t> creation_time_100ns) const {
    std::shared_ptr<analysis_workspace_t> match;
    std::shared_lock lock(mutex_);
    for (const auto& pair : workspaces_) {
        const auto& process = pair.second->identity().process();
        if (pair.second->closing() || pair.second->closed() || !process || process->pid != pid ||
            (creation_time_100ns && process->creation_time_100ns != *creation_time_100ns))
            continue;
        if (match)
            return {};
        match = pair.second;
    }
    return match;
}

workspace_result_t<std::shared_ptr<analysis_workspace_t>> workspace_registry_t::resolve(
    const target_selector_t& selector,
    const target_resolution_options_t& options) const {
    const std::uint32_t selector_count = static_cast<std::uint32_t>(selector.binary_id.has_value()) +
                                         static_cast<std::uint32_t>(selector.bin_name.has_value()) +
                                         static_cast<std::uint32_t>(selector.pid.has_value());
    if (selector_count > 1)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                                 "only one target selector may be supplied", "workspace_resolve"));
    if (selector.process_creation_time_100ns && !selector.pid)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                                 "process creation identity requires a PID selector",
                                 "workspace_resolve"));
    if (selector.binary_id && selector.binary_id->empty())
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "binary id selector cannot be zero", "workspace_resolve"));
    if (selector.bin_name &&
        (selector.bin_name->empty() || selector.bin_name->size() > 32768))
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "binary name selector is invalid", "workspace_resolve"));
    if (selector.pid && *selector.pid == 0)
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "live target PID must be positive", "workspace_resolve"));
    if (selector.binary_id)
        return validate_live_handle(find_by_binary_id(*selector.binary_id));
    if (selector.bin_name) {
        auto exact = find_by_exact_name_or_path(*selector.bin_name);
        if (exact.size() == 1)
            return validate_live_handle(exact.front());
        if (exact.size() > 1)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                ambiguous_error(exact));
        if (options.allow_unique_substring) {
            const std::string needle = normalize_target_name(*selector.bin_name);
            auto workspaces = list();
            std::vector<std::shared_ptr<analysis_workspace_t>> matches;
            for (const auto& workspace : workspaces) {
                const std::string name = normalize_target_name(workspace->identity().bin_name());
                if (name.find(needle) != std::string::npos)
                    matches.push_back(workspace);
            }
            if (matches.size() == 1)
                return validate_live_handle(matches.front());
            if (matches.size() > 1)
                return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                    ambiguous_error(matches));
        }
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "target name was not found", "workspace_resolve"));
    }
    if (selector.pid) {
        std::vector<std::shared_ptr<analysis_workspace_t>> matches;
        bool pid_exists_with_other_creation = false;
        for (const auto& workspace : list()) {
            const auto& process = workspace->identity().process();
            if (!process || process->pid != *selector.pid)
                continue;
            if (selector.process_creation_time_100ns &&
                process->creation_time_100ns != *selector.process_creation_time_100ns) {
                pid_exists_with_other_creation = true;
                continue;
            }
            matches.push_back(workspace);
        }
        if (matches.size() == 1)
            return validate_live_handle(matches.front());
        if (matches.size() > 1)
            return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
                ambiguous_error(matches));
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(pid_exists_with_other_creation
                                     ? workspace_error_code_t::target_stale
                                     : workspace_error_code_t::target_not_found,
                                 pid_exists_with_other_creation
                                     ? "PID was reused by a different process identity"
                                     : "live target PID was not found",
                                 "workspace_resolve"));
    }
    auto workspaces = list();
    if (workspaces.empty())
        return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "no target workspace is open", "workspace_resolve"));
    if (workspaces.size() == 1)
        return validate_live_handle(workspaces.front());
    return workspace_result_t<std::shared_ptr<analysis_workspace_t>>::failure(
        make_workspace_error(options.require_selector_when_multiple
                                 ? workspace_error_code_t::target_required
                                 : workspace_error_code_t::target_ambiguous,
                             "multiple workspaces are open; select a target explicitly",
                             "workspace_resolve"));
}

std::vector<std::shared_ptr<analysis_workspace_t>> workspace_registry_t::list() const {
    std::vector<std::shared_ptr<analysis_workspace_t>> result;
    std::shared_lock lock(mutex_);
    result.reserve(workspaces_.size());
    for (const auto& pair : workspaces_) {
        if (!pair.second->closing() && !pair.second->closed())
            result.push_back(pair.second);
    }
    std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
        return lhs->identity().binary_id() < rhs->identity().binary_id();
    });
    return result;
}

workspace_result_t<void> workspace_registry_t::select_for_ui(const binary_id_t& id) {
    std::unique_lock lock(mutex_);
    const auto iterator = workspaces_.find(id);
    if (iterator == workspaces_.end() || iterator->second->closing() || iterator->second->closed())
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                                 "UI workspace selection was not found", "workspace_ui_select"));
    ui_selection_ = id;
    return workspace_result_t<void>::success();
}

std::shared_ptr<analysis_workspace_t> workspace_registry_t::selected_for_ui() const {
    std::shared_lock lock(mutex_);
    if (!ui_selection_)
        return {};
    const auto iterator = workspaces_.find(*ui_selection_);
    if (iterator == workspaces_.end() || iterator->second->closing() || iterator->second->closed())
        return {};
    return iterator->second;
}

std::optional<binary_id_t> workspace_registry_t::selected_binary_id() const {
    std::shared_lock lock(mutex_);
    return ui_selection_;
}

workspace_registry_t& workspace_registry() {
    static workspace_registry_t registry;
    return registry;
}

}

#endif
