#include "workspace_preview_fixture.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../core/analysis/workspace/overlay_journal.hpp"
#include "../core/analysis/workspace/paged_fact_staging.hpp"
#include "../core/analysis/workspace/paged_snapshot_view.hpp"
#include "../core/analysis/workspace/workspace_database.hpp"
#include "../core/workbench/workbench_shell_integration.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <optional>
#include <iterator>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace aida::analysis {

bool binary_id_t::empty() const noexcept {
    std::uint8_t aggregate = 0;
    for (const auto value : bytes)
        aggregate |= value;
    return aggregate == 0;
}

std::string binary_id_t::to_hex() const {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        result[index * 2] = alphabet[bytes[index] >> 4];
        result[index * 2 + 1] = alphabet[bytes[index] & 0x0F];
    }
    return result;
}

std::optional<binary_id_t> binary_id_t::from_hex(
    const std::string& text) noexcept {
    if (text.size() != 64)
        return std::nullopt;
    const auto nibble = [](char value) {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };
    binary_id_t result;
    for (std::size_t index = 0; index < result.bytes.size(); ++index) {
        const auto high = nibble(text[index * 2]);
        const auto low = nibble(text[index * 2 + 1]);
        if (high < 0 || low < 0)
            return std::nullopt;
        result.bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return result;
}

bool binary_id_t::constant_time_equal(const binary_id_t& other) const noexcept {
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index)
        difference |= static_cast<std::uint8_t>(bytes[index] ^ other.bytes[index]);
    return difference == 0;
}

std::size_t binary_id_hash_t::operator()(const binary_id_t& id) const noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const auto value : id.bytes) {
        hash ^= value;
        hash *= 1099511628211ULL;
    }
    return static_cast<std::size_t>(hash ^ (hash >> 32));
}

const char* workspace_error_code_name(workspace_error_code_t code) noexcept {
    switch (code) {
    case workspace_error_code_t::none: return "NONE";
    case workspace_error_code_t::range_overflow: return "RANGE_OVERFLOW";
    case workspace_error_code_t::out_of_range: return "OUT_OF_RANGE";
    case workspace_error_code_t::file_changed: return "FILE_CHANGED";
    case workspace_error_code_t::malformed_pe: return "MALFORMED_PE";
    case workspace_error_code_t::unsupported_pe_arch: return "UNSUPPORTED_PE_ARCH";
    case workspace_error_code_t::cancelled: return "CANCELLED";
    case workspace_error_code_t::deadline_exceeded: return "DEADLINE_EXCEEDED";
    case workspace_error_code_t::stale_generation: return "STALE_GENERATION";
    case workspace_error_code_t::target_required: return "TARGET_REQUIRED";
    case workspace_error_code_t::target_conflict: return "TARGET_CONFLICT";
    case workspace_error_code_t::target_ambiguous: return "TARGET_AMBIGUOUS";
    case workspace_error_code_t::target_not_found: return "TARGET_NOT_FOUND";
    case workspace_error_code_t::target_stale: return "TARGET_STALE";
    case workspace_error_code_t::self_target_refused: return "SELF_TARGET_REFUSED";
    case workspace_error_code_t::live_target_bulk_analysis_unsupported: return "LIVE_TARGET_BULK_ANALYSIS_UNSUPPORTED";
    case workspace_error_code_t::revision_conflict: return "REVISION_CONFLICT";
    case workspace_error_code_t::persistence_failure: return "PERSISTENCE_FAILURE";
    case workspace_error_code_t::invalid_argument: return "INVALID_ARGUMENT";
    case workspace_error_code_t::io_failure: return "IO_FAILURE";
    case workspace_error_code_t::hash_failure: return "HASH_FAILURE";
    case workspace_error_code_t::provider_unavailable: return "PROVIDER_UNAVAILABLE";
    case workspace_error_code_t::duplicate_target: return "DUPLICATE_TARGET";
    case workspace_error_code_t::workspace_closing: return "WORKSPACE_CLOSING";
    case workspace_error_code_t::unsupported_address_space: return "UNSUPPORTED_ADDRESS_SPACE";
    case workspace_error_code_t::limit_exceeded: return "LIMIT_EXCEEDED";
    case workspace_error_code_t::decode_failure: return "DECODE_FAILURE";
    case workspace_error_code_t::integrity_failure: return "INTEGRITY_FAILURE";
    case workspace_error_code_t::analysis_in_progress: return "ANALYSIS_IN_PROGRESS";
    case workspace_error_code_t::service_conflict: return "SERVICE_CONFLICT";
    case workspace_error_code_t::substitution_rejected: return "SUBSTITUTION_REJECTED";
    case workspace_error_code_t::malformed_image: return "MALFORMED_IMAGE";
    case workspace_error_code_t::unsupported_format: return "UNSUPPORTED_FORMAT";
    case workspace_error_code_t::provider_binding_mismatch: return "PROVIDER_BINDING_MISMATCH";
    }
    return "UNKNOWN";
}

std::string workspace_error_t::stable_code() const {
    return workspace_error_code_name(code);
}

workspace_error_t make_workspace_error(workspace_error_code_t code,
                                       std::string message,
                                       std::string phase) {
    workspace_error_t result;
    result.code = code;
    result.message = std::move(message);
    result.phase = std::move(phase);
    return result;
}

bool cancellation_token_t::cancellation_requested() const noexcept {
    return state_ && state_->requested.load(std::memory_order_acquire);
}

bool cancellation_token_t::deadline_exceeded() const noexcept {
    if (!state_)
        return false;
    const auto ticks = state_->deadline_ticks.load(std::memory_order_acquire);
    const auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return ticks != 0 && now >= ticks;
}

bool cancellation_token_t::stop_requested() const noexcept {
    return cancellation_requested() || deadline_exceeded();
}

std::optional<std::chrono::steady_clock::time_point>
cancellation_token_t::deadline() const noexcept {
    if (!state_)
        return std::nullopt;
    const auto ticks = state_->deadline_ticks.load(std::memory_order_acquire);
    return ticks == 0 ? std::nullopt
                      : std::optional<std::chrono::steady_clock::time_point>(
                            std::chrono::steady_clock::time_point(
                                std::chrono::nanoseconds(ticks)));
}

cancellation_source_t::cancellation_source_t()
    : state_(std::make_shared<cancellation_token_t::state_t>()) {}

cancellation_source_t::cancellation_source_t(
    std::optional<std::chrono::steady_clock::time_point> deadline_value)
    : cancellation_source_t() {
    set_deadline(deadline_value);
}

cancellation_token_t cancellation_source_t::token() const noexcept {
    return cancellation_token_t(state_);
}

void cancellation_source_t::request_cancel() noexcept {
    state_->requested.store(true, std::memory_order_release);
}

void cancellation_source_t::set_deadline(
    std::optional<std::chrono::steady_clock::time_point> deadline_value) noexcept {
    const auto ticks = deadline_value
        ? std::chrono::duration_cast<std::chrono::nanoseconds>(
              deadline_value->time_since_epoch()).count()
        : 0;
    state_->deadline_ticks.store(ticks, std::memory_order_release);
}

workspace_result_t<void> byte_provider_t::read_exact(
    std::uint64_t offset, void* destination, std::uint64_t requested,
    const cancellation_token_t& cancel) const {
    if (requested != 0 && !destination)
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "preview provider destination is null", "preview_provider"));
    auto view = lease(offset, requested, cancel);
    if (!view)
        return workspace_result_t<void>::failure(view.error());
    if (requested != 0)
        std::memcpy(destination, view.value().data(),
                    static_cast<std::size_t>(requested));
    return workspace_result_t<void>::success();
}

workspace_result_t<std::size_t> byte_provider_t::read_some(
    std::uint64_t offset, void* destination, std::size_t capacity,
    const cancellation_token_t& cancel) const {
    if (offset > size())
        return workspace_result_t<std::size_t>::failure(make_workspace_error(
            workspace_error_code_t::out_of_range,
            "preview provider offset is out of range", "preview_provider"));
    const auto count = static_cast<std::size_t>((std::min<std::uint64_t>)(
        capacity, size() - offset));
    auto result = read_exact(offset, destination, count, cancel);
    return result ? workspace_result_t<std::size_t>::success(count)
                  : workspace_result_t<std::size_t>::failure(result.error());
}

workspace_result_t<std::vector<std::uint8_t>> byte_provider_t::read_vector(
    std::uint64_t offset, std::uint64_t requested, std::uint64_t hard_limit,
    const cancellation_token_t& cancel) const {
    if (requested > hard_limit || requested >
        static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "preview provider read exceeds its limit",
                                 "preview_provider"));
    std::vector<std::uint8_t> result(static_cast<std::size_t>(requested));
    auto read = read_exact(offset, result.data(), requested, cancel);
    return read
        ? workspace_result_t<std::vector<std::uint8_t>>::success(std::move(result))
        : workspace_result_t<std::vector<std::uint8_t>>::failure(read.error());
}

workspace_result_t<sha256_digest_t> byte_provider_t::compute_content_sha256(
    const cancellation_token_t& cancel, std::uint64_t chunk_limit) const {
    static_cast<void>(chunk_limit);
    if (cancel.stop_requested())
        return workspace_result_t<sha256_digest_t>::failure(make_workspace_error(
            workspace_error_code_t::cancelled,
            "preview provider hash was cancelled", "preview_provider"));
    return identity().content_sha256
        ? workspace_result_t<sha256_digest_t>::success(*identity().content_sha256)
        : workspace_result_t<sha256_digest_t>::failure(make_workspace_error(
              workspace_error_code_t::hash_failure,
              "preview provider has no content identity", "preview_provider"));
}

std::shared_ptr<memory_provider_t> memory_provider_t::create(
    std::string normalized_source, std::vector<std::uint8_t> bytes,
    sha256_digest_t content_hash) {
    auto storage = std::make_shared<const std::vector<std::uint8_t>>(
        std::move(bytes));
    byte_provider_identity_t identity;
    identity.normalized_source = std::move(normalized_source);
    identity.size = storage->size();
    identity.content_sha256 = content_hash;
    identity.immutable_snapshot = true;
    return std::shared_ptr<memory_provider_t>(new memory_provider_t(
        std::move(storage), std::move(identity)));
}

memory_provider_t::memory_provider_t(
    std::shared_ptr<const std::vector<std::uint8_t>> bytes,
    byte_provider_identity_t identity)
    : bytes_(std::move(bytes)), identity_(std::move(identity)) {}

const byte_provider_identity_t& memory_provider_t::identity() const noexcept {
    return identity_;
}

std::uint64_t memory_provider_t::size() const noexcept {
    return bytes_->size();
}

workspace_result_t<byte_view_t> memory_provider_t::lease(
    std::uint64_t offset, std::uint64_t requested,
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested())
        return workspace_result_t<byte_view_t>::failure(make_workspace_error(
            cancel.deadline_exceeded()
                ? workspace_error_code_t::deadline_exceeded
                : workspace_error_code_t::cancelled,
            "preview provider lease was cancelled", "preview_provider"));
    if (offset > bytes_->size() || requested > bytes_->size() - offset)
        return workspace_result_t<byte_view_t>::failure(make_workspace_error(
            workspace_error_code_t::out_of_range,
            "preview provider lease exceeds the fixture", "preview_provider"));
    const auto* data = requested == 0 ? nullptr : bytes_->data() + offset;
    return workspace_result_t<byte_view_t>::success(byte_view_t(
        std::static_pointer_cast<const void>(bytes_), data,
        static_cast<std::size_t>(requested)));
}

std::shared_ptr<const workspace_identity_t> workspace_identity_t::create_preview(
    binary_id_t binary_id, workspace_identity_input_t input) {
    return std::shared_ptr<const workspace_identity_t>(new workspace_identity_t(
        std::move(binary_id), input, input.source_path, input.member_path,
        input.bin_name));
}

workspace_identity_t::workspace_identity_t(
    binary_id_t binary_id, workspace_identity_input_t input,
    std::string normalized_source_path,
    std::optional<std::string> normalized_member_path,
    std::string safe_bin_name)
    : binary_id_(std::move(binary_id)),
      bin_name_(std::move(safe_bin_name)),
      normalized_source_path_(std::move(normalized_source_path)),
      normalized_member_path_(std::move(normalized_member_path)),
      content_hash_(input.content_hash),
      load_profile_hash_(input.load_profile_hash),
      target_kind_(input.target_kind),
      format_(input.format),
      architecture_(input.architecture),
      architecture_mode_(input.architecture_mode),
      abi_(input.abi),
      endian_(input.endian),
      image_base_(input.image_base),
      process_(std::move(input.process)),
      module_(std::move(input.module)) {}

std::shared_ptr<const pe_image_t> pe_image_t::create_preview() {
    auto image = std::shared_ptr<pe_image_t>(new pe_image_t());
    image->format_ = format_id_t::pe32_plus;
    image->architecture_ = architecture_id_t::x86_64;
    image->mode_ = architecture_mode_t::x86_64;
    image->abi_ = abi_id_t::windows_x64;
    image->artifact_kind_ = pe_artifact_kind_t::executable;
    image->image_base_ = 0x0000000140000000ULL;
    image->image_size_ = 0x6000;
    image->headers_size_ = 0x400;
    image->entry_rva_ = 0x1000;
    image->machine_ = 0x8664;
    image->subsystem_ = 3;
    image->characteristics_ = 0x22;
    image->dll_characteristics_ = 0x4160;
    image->timestamp_ = 0x65A1D4C0;
    image->sections_.push_back({0, ".text", 0x1000, 0x2000, 0x400, 0x2000,
                                0x60000020, true, false, true, false});
    image->sections_.push_back({1, ".rdata", 0x3000, 0x1000, 0x2400, 0x1000,
                                0x40000040, true, false, false, false});
    image->sections_.push_back({2, ".data", 0x4000, 0x1000, 0x3400, 0x1000,
                                0xC0000040, true, true, false, false});
    image->entry_points_.push_back({0x1000, "image_entry"});
    image->imports_.push_back({"KERNEL32.dll", std::string("CreateFileW"),
                               std::nullopt, std::nullopt, 0x3080, 0x4080,
                               false});
    image->imports_.push_back({"KERNEL32.dll", std::string("ReadFile"),
                               std::nullopt, std::nullopt, 0x3090, 0x4090,
                               false});
    image->imports_.push_back({"KERNEL32.dll", std::string("VirtualAlloc"),
                               std::nullopt, std::nullopt, 0x30A0, 0x40A0,
                               false});
    image->imports_.push_back({"KERNEL32.dll", std::string("VirtualProtect"),
                               std::nullopt, std::nullopt, 0x30B0, 0x40B0,
                               false});
    image->imports_.push_back({"KERNEL32.dll", std::string("CreateProcessW"),
                               std::nullopt, std::nullopt, 0x30C0, 0x40C0,
                               false});
    image->imports_.push_back({"WINHTTP.dll", std::string("WinHttpSendRequest"),
                               std::nullopt, std::nullopt, 0x30D0, 0x40D0,
                               false});
    image->imports_.push_back({"BCRYPT.dll", std::string("BCryptDecrypt"),
                               std::nullopt, std::nullopt, 0x30E0, 0x40E0,
                               false});
    image->imports_.push_back({"ADVAPI32.dll", std::string("RegSetValueExW"),
                               std::nullopt, std::nullopt, 0x30F0, 0x40F0,
                               false});
    image->exports_.push_back({std::string("AnalyzeTarget"), 1, 0x1000,
                               std::nullopt});
    image->exports_.push_back({std::string("ExportEvidence"), 2, 0x22D0,
                               std::nullopt});
    pe_codeview_t codeview;
    codeview.guid = {0xA1, 0xDA, 0x7B, 0x42, 0x94, 0x11, 0x4C, 0x2D,
                     0xA8, 0x70, 0x45, 0x59, 0x72, 0xE3, 0x01, 0x8D};
    codeview.age = 1;
    codeview.pdb_path = "AiDA_Target.pdb";
    codeview.timestamp = image->timestamp_;
    image->codeview_records_.push_back(std::move(codeview));
    return image;
}

workspace_result_t<std::shared_ptr<overlay_journal_t>>
overlay_journal_t::open_preview(std::shared_ptr<analysis_workspace_t> workspace) {
    if (!workspace)
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "preview overlay requires a workspace",
                                 "preview_overlay"));
    overlay_target_identity_v9_t target;
    target.image_hash = workspace->identity().content_hash().bytes;
    target.provenance_hash = workspace->identity().load_profile_hash().bytes;
    target.image_base = workspace->identity().image_base();
    target.image_size = workspace->normalized_image()->image_size;
    target.generation = workspace->generation();
    target.kind = overlay_target_kind_v9_t::static_image;
    target.architecture = overlay_architecture_v9_t::x86_64;
    target.address_width = 64;
    auto journal = std::shared_ptr<overlay_journal_t>(new overlay_journal_t(
        workspace, nullptr, {}, target));
    auto installed = workspace->install_overlay(journal);
    if (!installed)
        return workspace_result_t<std::shared_ptr<overlay_journal_t>>::failure(
            installed.error());
    return workspace_result_t<std::shared_ptr<overlay_journal_t>>::success(
        std::move(journal));
}

overlay_journal_t::overlay_journal_t(
    std::shared_ptr<analysis_workspace_t> workspace,
    std::shared_ptr<workspace_database_t> database,
    overlay_limits_t limits, overlay_target_identity_v9_t fixed_target)
    : workspace_(std::move(workspace)), database_(std::move(database)),
      limits_(limits), fixed_target_(fixed_target) {}

overlay_journal_t::~overlay_journal_t() {
    request_cancel();
}

namespace {

template <typename Range>
std::string preview_overlay_hex(const Range& values) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.resize(values.size() * 2U);
    std::size_t index = 0;
    for (const auto value : values) {
        const auto byte = static_cast<std::uint8_t>(value);
        result[index++] = alphabet[byte >> 4U];
        result[index++] = alphabet[byte & 0x0fU];
    }
    return result;
}

std::string preview_overlay_address_key(const address_t& address) {
    return std::to_string(static_cast<unsigned>(address.space)) + ":" +
        std::to_string(address.value) + ":" +
        std::to_string(static_cast<unsigned>(address.architecture)) + ":" +
        std::to_string(static_cast<unsigned>(address.mode));
}

std::string preview_overlay_entity_key(const overlay_operation_t& operation) {
    if (operation.target_discriminator ==
            overlay_target_discriminator_v9_t::managed_entity &&
        operation.managed_locator) {
        std::string domain;
        switch (operation.kind) {
        case overlay_operation_kind_t::comment:
        case overlay_operation_kind_t::comment_update:
            domain = "comment";
            break;
        case overlay_operation_kind_t::name:
            domain = "name";
            break;
        case overlay_operation_kind_t::type_application:
        case overlay_operation_kind_t::type_update:
            domain = "type_application";
            break;
        default:
            domain = "invalid";
            break;
        }
        const auto& locator = *operation.managed_locator;
        const std::string qualifier =
            operation.kind == overlay_operation_kind_t::type_application ||
                    operation.kind == overlay_operation_kind_t::type_update
                ? (operation.variable.empty() ? operation.name
                                              : operation.variable)
                : std::string{};
        return "managed:" + domain + ":" +
            preview_overlay_hex(locator.workspace_id) + ":" +
            preview_overlay_hex(locator.provider_hash) + ":" +
            std::to_string(locator.provider_size) + ":" +
            preview_overlay_hex(locator.artifact_hash) + ":" +
            preview_overlay_hex(locator.entity_hash) + ":" +
            preview_overlay_hex(locator.serialized_entity) + ":" + qualifier;
    }
    std::string prefix;
    switch (operation.kind) {
    case overlay_operation_kind_t::comment:
    case overlay_operation_kind_t::comment_update:
        prefix = "comment";
        break;
    case overlay_operation_kind_t::name: prefix = "name"; break;
    case overlay_operation_kind_t::bookmark: prefix = "bookmark"; break;
    case overlay_operation_kind_t::type_declaration:
        return "type_declaration:" + operation.name;
    case overlay_operation_kind_t::enum_definition:
        return "enum_definition:" + operation.name;
    case overlay_operation_kind_t::define_function: prefix = "define_function"; break;
    case overlay_operation_kind_t::define_code: prefix = "define_code"; break;
    case overlay_operation_kind_t::define_data: prefix = "define_data"; break;
    case overlay_operation_kind_t::undefine: prefix = "undefine"; break;
    case overlay_operation_kind_t::stack_variable:
    case overlay_operation_kind_t::delete_stack_variable:
        return "stack_variable:" + preview_overlay_address_key(operation.address) +
            ":" + std::to_string(operation.stack_offset) + ":" + operation.name;
    case overlay_operation_kind_t::type_application:
    case overlay_operation_kind_t::type_update:
        return "type_application:" + preview_overlay_address_key(operation.address) +
            ":" + operation.variable + ":" + operation.name;
    case overlay_operation_kind_t::byte_patch:
    case overlay_operation_kind_t::assembly_patch:
    case overlay_operation_kind_t::integer_patch:
        prefix = "patch";
        break;
    case overlay_operation_kind_t::reanalysis:
        prefix = "reanalysis";
        break;
    }
    return prefix + ":" + preview_overlay_address_key(operation.address);
}

bool preview_overlay_removes_value(const overlay_operation_t& operation) {
    if (operation.remove)
        return true;
    if (operation.kind == overlay_operation_kind_t::comment ||
        operation.kind == overlay_operation_kind_t::comment_update)
        return operation.text.empty();
    if (operation.kind == overlay_operation_kind_t::name ||
        operation.kind == overlay_operation_kind_t::bookmark)
        return operation.name.empty();
    return false;
}

overlay_operation_t preview_materialized_operation(overlay_operation_t operation) {
    if (operation.kind == overlay_operation_kind_t::comment_update)
        operation.kind = overlay_operation_kind_t::comment;
    else if (operation.kind == overlay_operation_kind_t::delete_stack_variable)
        operation.kind = overlay_operation_kind_t::stack_variable;
    else if (operation.kind == overlay_operation_kind_t::type_update)
        operation.kind = overlay_operation_kind_t::type_application;
    operation.remove = false;
    return operation;
}

workspace_result_t<std::shared_ptr<const workspace_overlay_presentation_t>>
preview_overlay_presentation(
    const std::unordered_map<std::string, overlay_operation_t>& items,
    std::uint64_t revision) {
    try {
        auto presentation = std::make_shared<workspace_overlay_presentation_t>();
        presentation->overlay_revision = revision;
        presentation->comments.reserve(items.size());
        presentation->renames.reserve(items.size());
        presentation->bookmarks.reserve(items.size());
        presentation->workspace_bookmarks.reserve(items.size());
        for (const auto& item : items) {
            const auto& operation = item.second;
            if (operation.target_discriminator !=
                overlay_target_discriminator_v9_t::native_address)
                continue;
            if (operation.kind == overlay_operation_kind_t::comment) {
                presentation->comments.push_back(
                    {operation.address, operation.text});
            } else if (operation.kind == overlay_operation_kind_t::name) {
                presentation->renames.push_back(
                    {operation.address, operation.name});
            } else if (operation.kind == overlay_operation_kind_t::bookmark) {
                presentation->bookmarks.push_back(
                    {operation.address, operation.name});
                presentation->workspace_bookmarks.push_back(operation.address);
            }
        }
        const auto address_less = [](const auto& left, const auto& right) {
            return left.address < right.address;
        };
        std::sort(presentation->comments.begin(), presentation->comments.end(),
                  address_less);
        std::sort(presentation->renames.begin(), presentation->renames.end(),
                  address_less);
        std::sort(presentation->bookmarks.begin(), presentation->bookmarks.end(),
                  address_less);
        std::sort(presentation->workspace_bookmarks.begin(),
                  presentation->workspace_bookmarks.end());
        return workspace_result_t<
            std::shared_ptr<const workspace_overlay_presentation_t>>::success(
                std::static_pointer_cast<const workspace_overlay_presentation_t>(
                    std::move(presentation)));
    } catch (...) {
        return workspace_result_t<
            std::shared_ptr<const workspace_overlay_presentation_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "preview overlay presentation allocation failed",
                                     "preview_overlay"));
    }
}

void preview_restore_overlay_item(
    std::unordered_map<std::string, overlay_operation_t>& items,
    const std::string& key,
    const std::optional<overlay_operation_t>& value) {
    if (value)
        items.insert_or_assign(key, *value);
    else
        items.erase(key);
}

bool preview_overlay_target_equal(
    const overlay_target_identity_v9_t& left,
    const overlay_target_identity_v9_t& right) noexcept {
    return left.image_hash == right.image_hash &&
        left.provenance_hash == right.provenance_hash &&
        left.image_base == right.image_base &&
        left.image_size == right.image_size &&
        left.generation == right.generation && left.kind == right.kind &&
        left.architecture == right.architecture &&
        left.address_width == right.address_width &&
        left.reserved == right.reserved;
}

}

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::transact(
    const overlay_transaction_request_t& request,
    const cancellation_token_t& cancel) {
    auto workspace = workspace_.lock();
    if (!workspace || workspace->closing())
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "preview overlay workspace is unavailable",
                                 "preview_overlay"));
    if (cancel.stop_requested() || cancellation_.token().stop_requested())
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::cancelled,
                                 "preview overlay transaction was cancelled",
                                 "preview_overlay"));
    if (request.operations.empty() ||
        request.operations.size() > limits_.max_operations)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "preview overlay transaction is invalid",
                                 "preview_overlay"));
    std::unique_lock publication_lock(publication_mutex_);
    overlay_transaction_result_t result;
    result.dry_run = request.dry_run;
    std::shared_ptr<std::unordered_map<std::string, overlay_operation_t>> next_items;
    std::shared_ptr<std::vector<preview_history_transaction_t>> next_history;
    std::uint64_t local_revision = 0;
    std::uint64_t local_cursor = 0;
    std::uint64_t local_next_transaction = 0;
    std::uint64_t local_epoch = 0;
    std::uint64_t next_epoch = 0;
    overlay_target_identity_v9_t local_target;
    try {
        std::shared_lock state_lock(state_mutex_);
        local_revision = revision_;
        local_cursor = history_cursor_;
        local_next_transaction = next_transaction_id_;
        local_epoch = history_epoch_;
        next_epoch = local_epoch;
        local_target = fixed_target_;
        if (request.expected_revision && *request.expected_revision != local_revision)
            return workspace_result_t<overlay_transaction_result_t>::failure(
                make_workspace_error(workspace_error_code_t::revision_conflict,
                                     "preview overlay revision changed",
                                     "preview_overlay"));
        if (local_revision == (std::numeric_limits<std::uint64_t>::max)() ||
            local_next_transaction == (std::numeric_limits<std::uint64_t>::max)())
            return workspace_result_t<overlay_transaction_result_t>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "preview overlay revision or transaction identifier is exhausted",
                                     "preview_overlay"));
        next_items = std::make_shared<
            std::unordered_map<std::string, overlay_operation_t>>(items_);
        next_history = std::make_shared<
            std::vector<preview_history_transaction_t>>(preview_history_);
        const auto retained_end = std::remove_if(next_history->begin(),
            next_history->end(), [local_cursor](const auto& transaction) {
                return transaction.transaction_id > local_cursor;
            });
        if (retained_end != next_history->end()) {
            if (next_epoch == (std::numeric_limits<std::uint64_t>::max)())
                return workspace_result_t<overlay_transaction_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                                         "preview overlay history epoch is exhausted",
                                         "preview_overlay"));
            next_history->erase(retained_end, next_history->end());
            ++next_epoch;
        }
        preview_history_transaction_t transaction;
        transaction.transaction_id = local_next_transaction;
        transaction.operations.reserve(request.operations.size());
        std::vector<std::string> keys;
        keys.reserve(request.operations.size());
        result.operations.reserve(request.operations.size());
        for (std::size_t index = 0; index < request.operations.size(); ++index) {
            const auto& operation = request.operations[index];
            const auto key = preview_overlay_entity_key(operation);
            if (std::find(keys.begin(), keys.end(), key) != keys.end())
                return workspace_result_t<overlay_transaction_result_t>::failure(
                    make_workspace_error(workspace_error_code_t::revision_conflict,
                                         "preview overlay transaction contains duplicate entity operations",
                                         "preview_overlay"));
            keys.push_back(key);
            const bool remove = preview_overlay_removes_value(operation);
            result.operations.push_back({index, key, remove});
            preview_history_operation_t historical;
            historical.index = index;
            historical.entity_key = key;
            const auto before = items_.find(key);
            if (before != items_.end())
                historical.before = before->second;
            if (!remove)
                historical.after = preview_materialized_operation(operation);
            preview_restore_overlay_item(*next_items, key, historical.after);
            transaction.operations.push_back(std::move(historical));
        }
        if (!request.dry_run)
            next_history->push_back(std::move(transaction));
    } catch (...) {
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "preview overlay publication state allocation failed",
                                 "preview_overlay"));
    }

    result.revision = local_revision;
    if (request.dry_run)
        return workspace_result_t<overlay_transaction_result_t>::success(
            std::move(result));
    const auto publication = workspace->analysis_publication();
    if (!publication || !publication->provider ||
        publication->generation != local_target.generation ||
        publication->overlay_revision != local_revision)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "preview workspace and overlay journal publications differ",
                                 "preview_overlay"));
    if (publication->generation == (std::numeric_limits<std::uint64_t>::max)())
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "preview workspace generation is exhausted",
                                 "preview_overlay"));
    const std::uint64_t target_generation = publication->generation + 1;
    const std::uint64_t target_revision = local_revision + 1;
    auto presentation = preview_overlay_presentation(*next_items, target_revision);
    if (!presentation)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            presentation.error());
    if (cancel.stop_requested() || cancellation_.token().stop_requested())
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::cancelled,
                                 "preview overlay transaction was cancelled",
                                 "preview_overlay"));
    auto published = workspace->publish_preview_overlay_generation(
        publication->generation, publication->analysis_revision,
        publication->overlay_revision, target_generation, target_revision,
        presentation.take_value(),
        [this, next_items, next_history, local_revision, local_cursor,
         local_next_transaction, local_epoch, next_epoch, local_target,
         target_generation, target_revision, cancel]() -> workspace_result_t<void> {
            if (cancel.stop_requested() || cancellation_.token().stop_requested())
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::cancelled,
                                         "preview overlay transaction was cancelled",
                                         "preview_overlay"));
            std::unique_lock state_lock(state_mutex_);
            if (revision_ != local_revision || history_cursor_ != local_cursor ||
                next_transaction_id_ != local_next_transaction ||
                history_epoch_ != local_epoch ||
                !preview_overlay_target_equal(fixed_target_, local_target))
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::revision_conflict,
                                         "preview overlay changed before atomic publication",
                                         "preview_overlay"));
            items_.swap(*next_items);
            preview_history_.swap(*next_history);
            revision_ = target_revision;
            history_cursor_ = local_next_transaction;
            next_transaction_id_ = local_next_transaction + 1;
            history_epoch_ = next_epoch;
            fixed_target_.generation = target_generation;
            publication_epoch_.fetch_add(1, std::memory_order_release);
            return workspace_result_t<void>::success();
        });
    if (!published)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            published.error());
    result.transaction_id = local_next_transaction;
    result.revision = target_revision;
    result.committed = true;
    return workspace_result_t<overlay_transaction_result_t>::success(
        std::move(result));
}

overlay_snapshot_t overlay_journal_t::snapshot() const {
    overlay_snapshot_t result;
    std::shared_lock lock(state_mutex_);
    result.revision = revision_;
    result.history_cursor = history_cursor_;
    result.history_epoch = history_epoch_;
    result.items.reserve(items_.size());
    for (const auto& item : items_)
        result.items.push_back(item);
    std::sort(result.items.begin(), result.items.end(),
        [](const auto& left, const auto& right) {
            return left.first < right.first;
        });
    return result;
}

overlay_history_snapshot_t overlay_journal_t::history_snapshot() const noexcept {
    overlay_history_snapshot_t result;
    std::shared_lock lock(state_mutex_);
    result.revision = revision_;
    result.history_cursor = history_cursor_;
    result.next_transaction_id = next_transaction_id_;
    result.history_epoch = history_epoch_;
    return result;
}

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::history_action(
    bool redo_action, std::optional<std::uint64_t> expected_revision,
    const cancellation_token_t& cancel) {
    auto workspace = workspace_.lock();
    if (!workspace || workspace->closing())
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "preview overlay workspace is unavailable",
                                 "preview_overlay_history"));
    if (cancel.stop_requested() || cancellation_.token().stop_requested())
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::cancelled,
                                 "preview overlay history action was cancelled",
                                 "preview_overlay_history"));
    std::unique_lock publication_lock(publication_mutex_);
    std::shared_ptr<std::unordered_map<std::string, overlay_operation_t>> next_items;
    std::uint64_t local_revision = 0;
    std::uint64_t local_cursor = 0;
    std::uint64_t local_next_transaction = 0;
    std::uint64_t local_epoch = 0;
    std::uint64_t next_cursor = 0;
    std::uint64_t selected_transaction = 0;
    overlay_target_identity_v9_t local_target;
    overlay_transaction_result_t result;
    try {
        std::shared_lock state_lock(state_mutex_);
        local_revision = revision_;
        local_cursor = history_cursor_;
        local_next_transaction = next_transaction_id_;
        local_epoch = history_epoch_;
        local_target = fixed_target_;
        if (expected_revision && *expected_revision != local_revision)
            return workspace_result_t<overlay_transaction_result_t>::failure(
                make_workspace_error(workspace_error_code_t::revision_conflict,
                                     "preview overlay history revision changed",
                                     "preview_overlay_history"));
        if (local_revision == (std::numeric_limits<std::uint64_t>::max)())
            return workspace_result_t<overlay_transaction_result_t>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "preview overlay revision is exhausted",
                                     "preview_overlay_history"));
        auto selected = preview_history_.end();
        if (redo_action) {
            selected = std::find_if(preview_history_.begin(), preview_history_.end(),
                [local_cursor](const auto& transaction) {
                    return transaction.transaction_id > local_cursor;
                });
        } else {
            selected = std::find_if(preview_history_.begin(), preview_history_.end(),
                [local_cursor](const auto& transaction) {
                    return transaction.transaction_id == local_cursor;
                });
        }
        if (selected == preview_history_.end())
            return workspace_result_t<overlay_transaction_result_t>::failure(
                make_workspace_error(workspace_error_code_t::target_not_found,
                    redo_action ? "no preview overlay transaction is available to redo"
                                : "no preview overlay transaction is available to undo",
                    "preview_overlay_history"));
        selected_transaction = selected->transaction_id;
        next_items = std::make_shared<
            std::unordered_map<std::string, overlay_operation_t>>(items_);
        if (redo_action) {
            for (const auto& operation : selected->operations) {
                preview_restore_overlay_item(*next_items, operation.entity_key,
                                             operation.after);
                result.operations.push_back({operation.index, operation.entity_key,
                                             !operation.after.has_value()});
            }
            next_cursor = selected_transaction;
        } else {
            for (auto operation = selected->operations.rbegin();
                 operation != selected->operations.rend(); ++operation) {
                preview_restore_overlay_item(*next_items, operation->entity_key,
                                             operation->before);
                result.operations.push_back({operation->index, operation->entity_key,
                                             !operation->before.has_value()});
            }
            if (selected != preview_history_.begin())
                next_cursor = std::prev(selected)->transaction_id;
        }
    } catch (...) {
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "preview overlay history allocation failed",
                                 "preview_overlay_history"));
    }
    const auto publication = workspace->analysis_publication();
    if (!publication || !publication->provider ||
        publication->generation != local_target.generation ||
        publication->overlay_revision != local_revision)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "preview workspace and overlay history publications differ",
                                 "preview_overlay_history"));
    if (publication->generation == (std::numeric_limits<std::uint64_t>::max)())
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::range_overflow,
                                 "preview workspace generation is exhausted",
                                 "preview_overlay_history"));
    const std::uint64_t target_generation = publication->generation + 1;
    const std::uint64_t target_revision = local_revision + 1;
    auto presentation = preview_overlay_presentation(*next_items, target_revision);
    if (!presentation)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            presentation.error());
    if (cancel.stop_requested() || cancellation_.token().stop_requested())
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::cancelled,
                                 "preview overlay history action was cancelled",
                                 "preview_overlay_history"));
    auto published = workspace->publish_preview_overlay_generation(
        publication->generation, publication->analysis_revision,
        publication->overlay_revision, target_generation, target_revision,
        presentation.take_value(),
        [this, next_items, local_revision, local_cursor,
         local_next_transaction, local_epoch, local_target, next_cursor,
         target_generation, target_revision, cancel]() -> workspace_result_t<void> {
            if (cancel.stop_requested() || cancellation_.token().stop_requested())
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::cancelled,
                                         "preview overlay history action was cancelled",
                                         "preview_overlay_history"));
            std::unique_lock state_lock(state_mutex_);
            if (revision_ != local_revision || history_cursor_ != local_cursor ||
                next_transaction_id_ != local_next_transaction ||
                history_epoch_ != local_epoch ||
                !preview_overlay_target_equal(fixed_target_, local_target))
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::revision_conflict,
                                         "preview overlay history changed before atomic publication",
                                         "preview_overlay_history"));
            items_.swap(*next_items);
            revision_ = target_revision;
            history_cursor_ = next_cursor;
            fixed_target_.generation = target_generation;
            publication_epoch_.fetch_add(1, std::memory_order_release);
            return workspace_result_t<void>::success();
        });
    if (!published)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            published.error());
    result.transaction_id = selected_transaction;
    result.revision = target_revision;
    result.committed = true;
    return workspace_result_t<overlay_transaction_result_t>::success(
        std::move(result));
}

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::undo(
    std::optional<std::uint64_t> expected_revision,
    const cancellation_token_t& cancel) {
    return history_action(false, expected_revision, cancel);
}

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::redo(
    std::optional<std::uint64_t> expected_revision,
    const cancellation_token_t& cancel) {
    return history_action(true, expected_revision, cancel);
}

overlay_target_identity_v9_t overlay_journal_t::fixed_target() const {
    std::shared_lock lock(state_mutex_);
    return fixed_target_;
}

std::optional<overlay_operation_t> overlay_journal_t::find(
    const std::string& entity_key) const {
    std::shared_lock lock(state_mutex_);
    const auto found = items_.find(entity_key);
    return found == items_.end() ? std::nullopt
                                 : std::optional<overlay_operation_t>(found->second);
}

std::vector<overlay_operation_t> overlay_journal_t::patch_operations() const {
    std::vector<overlay_operation_t> result;
    std::shared_lock lock(state_mutex_);
    for (const auto& item : items_)
        if (item.second.kind == overlay_operation_kind_t::byte_patch ||
            item.second.kind == overlay_operation_kind_t::assembly_patch ||
            item.second.kind == overlay_operation_kind_t::integer_patch)
            result.push_back(item.second);
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.address < right.address;
    });
    return result;
}

void overlay_journal_t::request_cancel() noexcept {
    cancellation_.request_cancel();
}

workspace_result_t<void> overlay_journal_t::drain(
    std::chrono::steady_clock::time_point deadline) {
    static_cast<void>(deadline);
    return workspace_result_t<void>::success();
}

}

namespace aida::preview {
namespace {

analysis::binary_id_t digest(std::uint8_t seed) {
    analysis::binary_id_t value;
    for (std::size_t index = 0; index < value.bytes.size(); ++index)
        value.bytes[index] = static_cast<std::uint8_t>(seed + index * 13U);
    return value;
}

analysis::address_t rva(std::uint64_t value) {
    return {analysis::address_space_id_t::relative_virtual, value,
            analysis::architecture_id_t::x86_64,
            analysis::architecture_mode_t::x86_64};
}

struct preview_corpus_t final {
    std::vector<std::uint8_t> bytes;
    std::vector<analysis::instruction_record_t> instructions;
    std::vector<analysis::operand_fact_t> operand_facts;
    std::vector<analysis::target_fact_t> target_facts;
    std::vector<analysis::basic_block_record_t> blocks;
    std::vector<analysis::function_record_t> functions;
    std::vector<analysis::edge_record_t> edges;
    std::vector<analysis::xref_record_t> xrefs;
    std::vector<analysis::string_record_t> strings;
    std::vector<analysis::symbol_record_t> symbols;
    std::vector<analysis::coverage_span_t> coverage;
};

struct pending_relative_t final {
    std::size_t file_offset = 0;
    std::uint8_t width = 0;
    std::uint64_t instruction_end = 0;
    std::uint64_t target = 0;
};

preview_corpus_t build_preview_corpus() {
    static constexpr std::array<const char*, 64> function_names{{
        "image_entry", "initialize_runtime", "validate_dos_header",
        "validate_nt_headers", "enumerate_sections", "resolve_import_table",
        "resolve_delay_imports", "inspect_tls_callbacks",
        "recover_exception_directory", "detect_packer_stub",
        "score_entropy_regions", "locate_embedded_config",
        "decrypt_stage_buffer", "decompress_payload", "map_payload_image",
        "relocate_image", "bind_imports", "protect_mapped_sections",
        "register_unwind_metadata", "recover_control_flow",
        "enumerate_functions", "discover_basic_blocks", "build_call_graph",
        "index_cross_references", "scan_suspicious_strings",
        "identify_crypto_primitives", "recover_runtime_types",
        "propagate_signatures", "analyze_indirect_calls",
        "classify_network_behavior", "inspect_persistence_paths",
        "inspect_process_injection", "inspect_anti_debug", "inspect_anti_vm",
        "trace_registry_activity", "trace_filesystem_activity",
        "trace_socket_activity", "decode_command_channel",
        "parse_beacon_config", "verify_signature_chain", "calculate_file_hash",
        "compare_known_indicators", "build_evidence_timeline",
        "export_analysis_report", "submit_analysis_jobs",
        "wait_analysis_workers", "merge_analysis_results",
        "resolve_symbol_names", "reconstruct_pseudocode",
        "normalize_stack_frames", "recover_class_layouts", "infer_vtables",
        "infer_protocol_messages", "inspect_http_handlers",
        "inspect_websocket_frames", "inspect_driver_interface",
        "inspect_syscall_usage", "inspect_privilege_changes",
        "inspect_token_operations", "inspect_memory_permissions",
        "finalize_findings", "publish_workspace", "flush_analysis_cache",
        "shutdown_runtime"
    }};
    static constexpr std::array<const char*, 12> data_names{{
        "aAnalysisStarted", "aSuspiciousPayl", "aEncryptedStage",
        "aCommandChannel", "__imp_CreateFileW", "__imp_ReadFile",
        "__imp_VirtualAlloc", "__imp_VirtualProtect", "__imp_CreateProcessW",
        "__imp_WinHttpSendRequest", "__imp_BCryptDecrypt",
        "__imp_RegSetValueExW"
    }};
    static constexpr std::array<std::uint64_t, 4> string_addresses{{
        0x3000, 0x3040, 0x3100, 0x3140
    }};
    preview_corpus_t corpus;
    corpus.bytes.assign(0x6000, 0);
    std::fill(corpus.bytes.begin() + 0x400, corpus.bytes.begin() + 0x2400, 0xCC);
    corpus.instructions.reserve(1600);
    corpus.operand_facts.reserve(6400);
    corpus.target_facts.reserve(640);
    corpus.blocks.reserve(384);
    corpus.functions.reserve(64);
    corpus.edges.reserve(448);
    corpus.xrefs.reserve(640);
    corpus.symbols.reserve(80);
    std::vector<pending_relative_t> relatives;
    relatives.reserve(640);
    std::uint64_t instruction_serial = 1;
    std::uint64_t block_serial = 1;
    std::uint64_t edge_serial = 1;
    std::uint64_t xref_serial = 1;
    const auto function_address = [](std::size_t index) {
        return 0x1000ULL + static_cast<std::uint64_t>(index) * 0x70ULL;
    };
    const auto file_offset = [](std::uint64_t address) {
        return static_cast<std::size_t>(0x400ULL + address - 0x1000ULL);
    };
    for (std::size_t function_index = 0; function_index < function_names.size();
         ++function_index) {
        const std::uint64_t function_start = function_address(function_index);
        std::uint64_t cursor = function_start;
        const std::size_t first_block = corpus.blocks.size();
        std::array<std::size_t, 6> block_indices{};
        const auto emit = [&](std::initializer_list<std::uint8_t> encoded,
                              std::uint32_t flow_flags,
                              std::optional<std::uint64_t> target = {},
                              analysis::target_kind_record_t target_kind =
                                  analysis::target_kind_record_t::branch,
                                  analysis::xref_kind_t xref_kind =
                                  analysis::xref_kind_t::code) {
            analysis::instruction_record_t instruction;
            instruction.id = (1ULL << 56) | instruction_serial++;
            instruction.address = rva(cursor);
            instruction.length = static_cast<std::uint8_t>(encoded.size());
            instruction.mnemonic_id = static_cast<std::uint16_t>(
                1 + corpus.instructions.size() % 61);
            instruction.opcode_id = static_cast<std::uint32_t>(
                0x100 + corpus.instructions.size() % 251);
            instruction.flow_flags = flow_flags;
            instruction.target_fact_begin =
                static_cast<std::uint32_t>(corpus.target_facts.size());
            instruction.provenance = analysis::fact_provenance_t::recursive_decode;
            instruction.confidence = static_cast<std::uint8_t>(
                96 + (corpus.instructions.size() % 4));
            instruction.stable_source_id = 0xA1DA00000000ULL +
                corpus.instructions.size();
            const auto destination = file_offset(cursor);
            std::copy(encoded.begin(), encoded.end(),
                      corpus.bytes.begin() + static_cast<std::ptrdiff_t>(destination));
            if (target) {
                instruction.target_fact_count = 1;
                analysis::target_fact_t fact;
                fact.instruction_id = instruction.id;
                fact.target = rva(*target);
                fact.kind = target_kind;
                fact.resolution = analysis::target_resolution_t::image_relative;
                fact.direct = true;
                corpus.target_facts.push_back(fact);
                corpus.xrefs.push_back({(5ULL << 56) | xref_serial++,
                    instruction.address, rva(*target), xref_kind,
                    analysis::fact_provenance_t::recursive_decode, 97});
            }
            corpus.instructions.push_back(std::move(instruction));
            cursor += encoded.size();
            return corpus.instructions.size() - 1;
        };
        const auto emit_rel8 = [&](std::uint8_t opcode, std::uint64_t target,
                                   std::uint32_t flow_flags) {
            const auto index = emit({opcode, 0}, flow_flags, target,
                analysis::target_kind_record_t::branch,
                analysis::xref_kind_t::code);
            relatives.push_back({file_offset(corpus.instructions[index].address.value) + 1,
                                 1, corpus.instructions[index].address.value + 2, target});
            return index;
        };
        const auto emit_rel32 = [&](std::uint64_t target) {
            const auto index = emit({0xE8, 0, 0, 0, 0},
                analysis::flow_fallthrough | analysis::flow_direct |
                    analysis::flow_call,
                target, analysis::target_kind_record_t::call,
                analysis::xref_kind_t::call);
            relatives.push_back({file_offset(corpus.instructions[index].address.value) + 1,
                                 4, corpus.instructions[index].address.value + 5, target});
            return index;
        };
        const auto emit_lea_data = [&](std::uint64_t target) {
            const auto index = emit({0x48, 0x8D, 0x15, 0, 0, 0, 0},
                analysis::flow_fallthrough, target,
                analysis::target_kind_record_t::data,
                analysis::xref_kind_t::read);
            relatives.push_back({file_offset(corpus.instructions[index].address.value) + 3,
                                 4, corpus.instructions[index].address.value + 7, target});
            return index;
        };
        const auto begin_block = [&](std::size_t ordinal) {
            block_indices[ordinal] = corpus.blocks.size();
            analysis::basic_block_record_t block;
            block.id = (2ULL << 56) | block_serial++;
            block.function_id = (4ULL << 56) | (function_index + 1);
            block.start = rva(cursor);
            block.first_instruction =
                static_cast<std::uint32_t>(corpus.instructions.size());
            block.provenance = analysis::fact_provenance_t::recursive_decode;
            block.confidence = 98;
            corpus.blocks.push_back(block);
        };
        const auto end_block = [&](std::size_t ordinal) {
            auto& block = corpus.blocks[block_indices[ordinal]];
            block.end = rva(cursor);
            block.instruction_count = static_cast<std::uint32_t>(
                corpus.instructions.size() - block.first_instruction);
        };
        const std::uint64_t block3_target = function_start + 0x2F;
        const std::uint64_t block4_target = function_start + 0x3C;
        const std::uint64_t block5_target = function_start + 0x4A;
        begin_block(0);
        emit({0x55}, analysis::flow_fallthrough);
        emit({0x48, 0x89, 0xE5}, analysis::flow_fallthrough);
        emit({0x48, 0x83, 0xEC, 0x30}, analysis::flow_fallthrough);
        emit({0x48, 0x8B, 0x41, 0x08}, analysis::flow_fallthrough);
        emit({0x48, 0x85, 0xC0}, analysis::flow_fallthrough);
        emit_rel8(0x74, block4_target,
            analysis::flow_fallthrough | analysis::flow_direct |
                analysis::flow_branch | analysis::flow_conditional);
        end_block(0);
        begin_block(1);
        emit({0xB9, static_cast<std::uint8_t>(function_index), 0, 0, 0},
             analysis::flow_fallthrough);
        emit_rel32(function_address((function_index + 7) % function_names.size()));
        emit({0x85, 0xC0}, analysis::flow_fallthrough);
        emit_rel8(0x75, block3_target,
            analysis::flow_fallthrough | analysis::flow_direct |
                analysis::flow_branch | analysis::flow_conditional);
        end_block(1);
        begin_block(2);
        emit_lea_data(string_addresses[function_index % string_addresses.size()]);
        emit_rel32(function_address((function_index + 13) % function_names.size()));
        emit({0x33, 0xDB}, analysis::flow_fallthrough);
        emit_rel8(0xEB, block5_target,
            analysis::flow_direct | analysis::flow_branch);
        end_block(2);
        begin_block(3);
        emit({0x89, 0xC3}, analysis::flow_fallthrough);
        emit({0x48, 0x8B, 0x4D, 0x10}, analysis::flow_fallthrough);
        emit_rel32(function_address((function_index + 23) % function_names.size()));
        emit_rel8(0xEB, block5_target,
            analysis::flow_direct | analysis::flow_branch);
        end_block(3);
        begin_block(4);
        emit({0x33, 0xDB}, analysis::flow_fallthrough);
        emit_lea_data(0x3080 + (function_index % 8) * 0x10);
        emit_rel32(function_address((function_index + 31) % function_names.size()));
        end_block(4);
        begin_block(5);
        emit({0x89, 0xD8}, analysis::flow_fallthrough);
        emit({0x48, 0x83, 0xC4, 0x30}, analysis::flow_fallthrough);
        emit({0x5D}, analysis::flow_fallthrough);
        emit({0xC3}, analysis::flow_return | analysis::flow_terminal);
        end_block(5);
        analysis::function_record_t function;
        function.id = (4ULL << 56) | (function_index + 1);
        function.start = rva(function_start);
        function.end = rva(cursor);
        function.first_block = static_cast<std::uint32_t>(first_block);
        function.block_count = 6;
        function.symbol_id = (7ULL << 56) | (function_index + 1);
        function.provenance = function_index < 16
            ? analysis::fact_provenance_t::debug_symbol
            : analysis::fact_provenance_t::recursive_decode;
        function.confidence = static_cast<std::uint8_t>(99 - function_index % 3);
        corpus.functions.push_back(function);
        corpus.symbols.push_back({*function.symbol_id, rva(function_start),
            function_names[function_index], analysis::symbol_kind_t::function,
            function.provenance, function.confidence});
        const auto add_edge = [&](std::size_t source_block, std::size_t target_block,
                                  analysis::edge_kind_t kind) {
            const auto& source = corpus.blocks[block_indices[source_block]];
            const auto& target = corpus.blocks[block_indices[target_block]];
            corpus.edges.push_back({(3ULL << 56) | edge_serial++, source.id,
                target.id, source.end, target.start, kind,
                analysis::fact_provenance_t::recursive_decode, 97});
        };
        add_edge(0, 4, analysis::edge_kind_t::conditional_taken);
        add_edge(0, 1, analysis::edge_kind_t::fallthrough);
        add_edge(1, 3, analysis::edge_kind_t::conditional_taken);
        add_edge(1, 2, analysis::edge_kind_t::fallthrough);
        add_edge(2, 5, analysis::edge_kind_t::unconditional);
        add_edge(3, 5, analysis::edge_kind_t::unconditional);
        add_edge(4, 5, analysis::edge_kind_t::fallthrough);
    }
    for (const auto& relative : relatives) {
        const std::int64_t displacement = static_cast<std::int64_t>(relative.target) -
            static_cast<std::int64_t>(relative.instruction_end);
        if (relative.width == 1) {
            corpus.bytes[relative.file_offset] = static_cast<std::uint8_t>(
                static_cast<std::int8_t>(displacement));
        } else {
            const auto value = static_cast<std::int32_t>(displacement);
            for (std::size_t byte = 0; byte < 4; ++byte)
                corpus.bytes[relative.file_offset + byte] =
                    static_cast<std::uint8_t>(
                        static_cast<std::uint32_t>(value) >> (byte * 8));
        }
    }
    ZydisDecoder decoder{};
    if (ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                                      ZYDIS_STACK_WIDTH_64))) {
        std::uint64_t operand_serial = 1;
        for (auto& instruction : corpus.instructions) {
            ZydisDecodedInstruction decoded{};
            std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
            const auto offset = file_offset(instruction.address.value);
            const auto status = ZydisDecoderDecodeFull(&decoder,
                corpus.bytes.data() + static_cast<std::ptrdiff_t>(offset),
                instruction.length, &decoded, operands.data());
            if (!ZYAN_SUCCESS(status) || decoded.length != instruction.length)
                continue;
            instruction.mnemonic_id = static_cast<std::uint16_t>(decoded.mnemonic);
            instruction.opcode_id =
                (static_cast<std::uint32_t>(decoded.encoding) << 16) |
                (static_cast<std::uint32_t>(decoded.opcode_map) << 8) |
                decoded.opcode;
            instruction.operand_fact_begin =
                static_cast<std::uint32_t>(corpus.operand_facts.size());
            instruction.operand_fact_count = decoded.operand_count;
            for (std::uint8_t index = 0; index < decoded.operand_count; ++index) {
                const auto& decoded_operand = operands[index];
                analysis::operand_fact_t operand;
                operand.id = (8ULL << 56) | operand_serial++;
                operand.instruction_id = instruction.id;
                operand.operand_index = index;
                operand.access = static_cast<std::uint8_t>(decoded_operand.actions);
                operand.bit_width = decoded_operand.size;
                operand.access_width_bits = decoded_operand.size;
                switch (decoded_operand.type) {
                case ZYDIS_OPERAND_TYPE_REGISTER:
                    operand.kind = analysis::operand_kind_t::reg;
                    operand.reg = static_cast<std::uint16_t>(
                        decoded_operand.reg.value);
                    break;
                case ZYDIS_OPERAND_TYPE_MEMORY:
                    operand.kind = analysis::operand_kind_t::memory;
                    operand.segment_reg = static_cast<std::uint16_t>(
                        decoded_operand.mem.segment);
                    operand.base_reg = static_cast<std::uint16_t>(
                        decoded_operand.mem.base);
                    operand.index_reg = static_cast<std::uint16_t>(
                        decoded_operand.mem.index);
                    operand.scale = decoded_operand.mem.scale;
                    operand.displacement = decoded_operand.mem.disp.value;
                    operand.access_width = static_cast<std::uint8_t>(
                        decoded_operand.size);
                    if (decoded_operand.mem.segment != ZYDIS_REGISTER_NONE)
                        operand.address_components |= analysis::address_component_segment;
                    if (decoded_operand.mem.base != ZYDIS_REGISTER_NONE)
                        operand.address_components |= analysis::address_component_base;
                    if (decoded_operand.mem.index != ZYDIS_REGISTER_NONE) {
                        operand.address_components |= analysis::address_component_index;
                        if (decoded_operand.mem.scale != 0)
                            operand.address_components |= analysis::address_component_scale;
                    }
                    if (decoded_operand.mem.disp.has_displacement != ZYAN_FALSE) {
                        operand.has_displacement = true;
                        operand.address_components |= analysis::address_component_displacement;
                    }
                    if (decoded_operand.mem.segment == ZYDIS_REGISTER_FS ||
                        decoded_operand.mem.segment == ZYDIS_REGISTER_GS) {
                        operand.address_expression =
                            analysis::address_expression_kind_t::segment_relative;
                        operand.address_resolution =
                            analysis::target_resolution_t::segment_relative;
                    }
                    break;
                case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                    operand.kind = analysis::operand_kind_t::immediate;
                    operand.relative = decoded_operand.imm.is_relative != ZYAN_FALSE;
                    operand.signed_value = decoded_operand.imm.is_signed != ZYAN_FALSE;
                    operand.immediate = decoded_operand.imm.value.u;
                    break;
                case ZYDIS_OPERAND_TYPE_POINTER:
                    operand.kind = analysis::operand_kind_t::pointer;
                    operand.immediate =
                        (static_cast<std::uint64_t>(decoded_operand.ptr.segment) << 32) |
                        decoded_operand.ptr.offset;
                    break;
                default:
                    operand.kind = analysis::operand_kind_t::none;
                    break;
                }
                corpus.operand_facts.push_back(std::move(operand));
            }
        }
    }
    const std::array<std::string, 4> strings{{
        "Analysis pipeline initialized",
        "suspicious_payload.exe",
        "Encrypted stage recovered",
        "Command channel configuration"
    }};
    for (std::size_t index = 0; index < strings.size(); ++index) {
        const std::uint64_t address = string_addresses[index];
        const auto offset = static_cast<std::size_t>(0x2400 + address - 0x3000);
        std::copy(strings[index].begin(), strings[index].end(),
                  corpus.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
        corpus.strings.push_back({(6ULL << 56) | (index + 1), rva(address),
            strings[index].size(), analysis::string_encoding_t::ascii,
            strings[index], analysis::fact_provenance_t::linear_validation, 99});
        corpus.symbols.push_back({(7ULL << 56) | (65 + index), rva(address),
            data_names[index], analysis::symbol_kind_t::data,
            analysis::fact_provenance_t::linear_validation, 99});
    }
    for (std::size_t index = 4; index < data_names.size(); ++index) {
        corpus.symbols.push_back({(7ULL << 56) | (65 + index),
            rva(0x3080 + (index - 4) * 0x10), data_names[index],
            analysis::symbol_kind_t::import_symbol,
            analysis::fact_provenance_t::relocation, 100});
    }
    std::sort(corpus.symbols.begin(), corpus.symbols.end(),
        [](const auto& left, const auto& right) {
            return left.address < right.address;
        });
    std::sort(corpus.edges.begin(), corpus.edges.end(),
        [](const auto& left, const auto& right) {
            return std::tie(left.source, left.target, left.kind, left.id) <
                   std::tie(right.source, right.target, right.kind, right.id);
        });
    corpus.coverage = {
        {rva(0x1000), 0x1C00, analysis::coverage_reason_t::decoded,
         analysis::fact_provenance_t::recursive_decode, 98, 0},
        {rva(0x3000), 0x180, analysis::coverage_reason_t::proven_data,
         analysis::fact_provenance_t::linear_validation, 99, 0}
    };
    return corpus;
}

std::shared_ptr<const analysis::workspace_image_t> normalized_image(
    const analysis::binary_id_t& binary_id,
    const analysis::binary_id_t& content_hash,
    const std::string& source,
    const preview_corpus_t& corpus) {
    auto image = std::make_shared<analysis::workspace_image_t>();
    image->format = analysis::format_id_t::pe32_plus;
    image->architecture = analysis::architecture_id_t::x86_64;
    image->architecture_mode = analysis::architecture_mode_t::x86_64;
    image->abi = analysis::abi_id_t::windows_x64;
    image->address_width_bits = 64;
    image->image_base = 0x0000000140000000ULL;
    image->image_size = 0x6000;
    image->header_size = 0x400;
    image->format_name = "Portable Executable 64-bit";
    image->address_mappings = {
        {analysis::address_space_id_t::file_offset,
         analysis::address_space_id_t::relative_virtual, 0, 0, 0x400,
         analysis::image_permission_read},
        {analysis::address_space_id_t::file_offset,
         analysis::address_space_id_t::relative_virtual, 0x400, 0x1000, 0x2000,
         analysis::image_permission_read | analysis::image_permission_execute},
        {analysis::address_space_id_t::file_offset,
         analysis::address_space_id_t::relative_virtual, 0x2400, 0x3000, 0x1000,
         analysis::image_permission_read},
        {analysis::address_space_id_t::file_offset,
         analysis::address_space_id_t::relative_virtual, 0x3400, 0x4000, 0x1000,
         analysis::image_permission_read | analysis::image_permission_write}};
    image->entry_points.push_back({rva(0x1000), "image_entry"});
    image->segments = {
        {0, ".text", 0x1000, 0x2000, 0x400, 0x2000, 0x1000, 0,
         analysis::image_permission_read | analysis::image_permission_execute},
        {1, ".rdata", 0x3000, 0x1000, 0x2400, 0x1000, 0x1000, 0,
         analysis::image_permission_read},
        {2, ".data", 0x4000, 0x1000, 0x3400, 0x1000, 0x1000, 0,
         analysis::image_permission_read | analysis::image_permission_write}};
    image->sections = {
        {0, ".text", 0x1000, 0x2000, 0x400, 0x2000, 0x60000020,
         analysis::image_permission_read | analysis::image_permission_execute},
        {1, ".rdata", 0x3000, 0x1000, 0x2400, 0x1000, 0x40000040,
         analysis::image_permission_read},
        {2, ".data", 0x4000, 0x1000, 0x3400, 0x1000, 0xC0000040,
         analysis::image_permission_read | analysis::image_permission_write}};
    for (std::size_t index = 0; index < corpus.functions.size(); ++index) {
        const auto& function = corpus.functions[index];
        const auto symbol = std::find_if(corpus.symbols.begin(), corpus.symbols.end(),
            [&](const auto& candidate) {
                return candidate.id == function.symbol_id.value_or(0);
            });
        if (symbol == corpus.symbols.end())
            continue;
        image->symbols.push_back({static_cast<std::uint64_t>(index + 1),
            symbol->name, function.start,
            function.end.value - function.start.value,
            analysis::image_symbol_kind_t::function,
            index < 16 ? analysis::image_symbol_binding_t::global
                       : analysis::image_symbol_binding_t::local,
            true, false});
    }
    image->imports = {
        {"KERNEL32.dll", std::string("CreateFileW"), std::nullopt,
         rva(0x3080), rva(0x4080), false},
        {"KERNEL32.dll", std::string("ReadFile"), std::nullopt,
         rva(0x3090), rva(0x4090), false},
        {"KERNEL32.dll", std::string("VirtualAlloc"), std::nullopt,
         rva(0x30A0), rva(0x40A0), false},
        {"KERNEL32.dll", std::string("VirtualProtect"), std::nullopt,
         rva(0x30B0), rva(0x40B0), false},
        {"KERNEL32.dll", std::string("CreateProcessW"), std::nullopt,
         rva(0x30C0), rva(0x40C0), false},
        {"WINHTTP.dll", std::string("WinHttpSendRequest"), std::nullopt,
         rva(0x30D0), rva(0x40D0), false},
        {"BCRYPT.dll", std::string("BCryptDecrypt"), std::nullopt,
         rva(0x30E0), rva(0x40E0), false},
        {"ADVAPI32.dll", std::string("RegSetValueExW"), std::nullopt,
         rva(0x30F0), rva(0x40F0), false}};
    image->exports = {
        {std::string("AnalyzeTarget"), 1, rva(0x1000), std::nullopt},
        {std::string("ExportEvidence"), 2, rva(0x22D0), std::nullopt}
    };
    image->workspace_binary_id = binary_id;
    image->provider_content_hash = content_hash;
    image->provider_source = source;
    image->provider_size = 0x6000;
    image->provider_binding_verified = true;
    return image;
}

std::shared_ptr<const analysis::analysis_snapshot_t> analysis_snapshot(
    const analysis::binary_id_t& binary_id,
    const analysis::binary_id_t& profile_hash,
    const std::shared_ptr<const analysis::workspace_image_t>& normalized,
    const std::shared_ptr<const analysis::pe_image_t>& pe,
    const preview_corpus_t& corpus) {
    auto snapshot = std::make_shared<analysis::analysis_snapshot_t>();
    snapshot->binary_id = binary_id;
    snapshot->load_profile_hash = profile_hash;
    snapshot->generation = 1;
    snapshot->analysis_revision = 7;
    snapshot->overlay_revision = 0;
    snapshot->normalized_image = normalized;
    snapshot->image = pe;
    snapshot->instructions = corpus.instructions;
    snapshot->delay_slot_counts.assign(corpus.instructions.size(), 0);
    snapshot->operand_facts.hot.reserve(corpus.operand_facts.size());
    for (const auto& instruction : snapshot->instructions) {
        const auto operand_begin = instruction.operand_fact_begin;
        const auto operand_end = static_cast<std::uint64_t>(operand_begin) +
            instruction.operand_fact_count;
        for (std::uint64_t fact = operand_begin; fact < operand_end &&
             fact < corpus.operand_facts.size(); ++fact) {
            auto parts = analysis::operand_fact_split(
                corpus.operand_facts[static_cast<std::size_t>(fact)],
                static_cast<std::uint32_t>(&instruction - snapshot->instructions.data()));
            if (parts.has_cold) {
                snapshot->operand_facts.cold.push_back(parts.cold);
                parts.hot.cold_index = static_cast<std::uint32_t>(
                    snapshot->operand_facts.cold.size());
            }
            snapshot->operand_facts.hot.push_back(parts.hot);
        }
    }
    snapshot->target_facts = corpus.target_facts;
    snapshot->blocks = corpus.blocks;
    snapshot->functions = corpus.functions;
    snapshot->edges = corpus.edges;
    snapshot->xrefs = corpus.xrefs;
    snapshot->strings = corpus.strings;
    snapshot->symbols = corpus.symbols;
    snapshot->coverage = corpus.coverage;
    return snapshot;
}

void verify_paged_residency_parity(
    const std::shared_ptr<const analysis::analysis_snapshot_t>& resident) {
    namespace analysis = aida::analysis;
    auto staging_created = analysis::paged_fact_staging_t::create(
        1ULL << 30, 0);
    preview_fixture_require(static_cast<bool>(staging_created),
        "preview paged staging create");
    auto staging = staging_created.take_value();
    const std::uint64_t content_capacity = staging->content_page_bytes();
    const auto header = analysis::encode_packed_domain_stream_header(
        analysis::packed_page_type_t::operands, resident->operand_facts.size());
    std::vector<std::uint8_t> stream;
    stream.insert(stream.end(), header.begin(), header.end());
    for (std::uint64_t ordinal = 0; ordinal < resident->operand_facts.size();
         ++ordinal) {
        auto record = analysis::operand_fact_materialize(
            resident->operand_facts, ordinal, resident->instructions);
        auto bytes = analysis::encode_packed_operand_record(record);
        stream.insert(stream.end(), bytes.begin(), bytes.end());
    }
    std::uint64_t ordinal_begin = 0;
    std::uint64_t records_started = 0;
    for (std::size_t offset = 0; offset < stream.size();) {
        const std::size_t count = (std::min)(
            static_cast<std::size_t>(content_capacity), stream.size() - offset);
        const std::uint64_t stream_base = offset;
        std::uint32_t page_records = 0;
        while (records_started + page_records < resident->operand_facts.size() &&
               analysis::packed_domain_stream_header_bytes +
                   (records_started + page_records) *
                       analysis::packed_operand_stream_record_bytes <
                   stream_base + count) {
            ++page_records;
        }
        analysis::packed_record_page_prefix_t prefix;
        prefix.ordinal_begin = static_cast<std::uint32_t>(ordinal_begin);
        prefix.record_count = page_records;
        const auto encoded_prefix = prefix.encode();
        std::vector<std::uint8_t> payload;
        payload.insert(payload.end(), encoded_prefix.begin(), encoded_prefix.end());
        payload.insert(payload.end(), stream.begin() + offset,
                       stream.begin() + offset + count);
        analysis::paged_fact_page_meta_t meta;
        meta.ordinal_begin = prefix.ordinal_begin;
        meta.record_count = prefix.record_count;
        auto staged = staging->stage_page(
            analysis::fact_domain_t::operand_facts, std::move(payload), meta, {});
        if (!staged)
            preview_fixture_failure("preview paged staging stage_page",
                                    staged.error());
        ordinal_begin += page_records;
        records_started += page_records;
        offset += count;
    }
    auto contiguous = staging->validate_contiguous(
        analysis::fact_domain_t::operand_facts);
    preview_fixture_require(static_cast<bool>(contiguous),
        "preview paged staging contiguity");
    auto paged = std::make_shared<analysis::analysis_snapshot_t>(*resident);
    paged->operand_facts.clear();
    paged->paged_staging = staging;
    paged->residency_plan.domains[static_cast<std::size_t>(
        analysis::fact_domain_t::operand_facts)].mode =
        analysis::fact_residency_mode_t::paged;
    paged->paged_domain_counts[static_cast<std::size_t>(
        analysis::fact_domain_t::operand_facts)] = resident->operand_facts.size();
    auto resident_view = analysis::operand_facts_view(*resident);
    auto paged_view = analysis::operand_facts_view(*paged);
    preview_fixture_require(paged_view.size() == resident_view.size() &&
        !paged_view.resident() && resident_view.resident(),
        "preview paged view shape");
    analysis::fact_page_pin_t resident_pin;
    analysis::fact_page_pin_t paged_pin;
    bool parity = true;
    for (std::uint64_t ordinal = 0; ordinal < resident_view.size(); ++ordinal) {
        auto expected = resident_view.at(ordinal, resident_pin, {});
        auto actual = paged_view.at(ordinal, paged_pin, {});
        if (!expected || !actual) {
            parity = false;
            break;
        }
        const auto& lhs = *expected.value();
        const auto& rhs = *actual.value();
        if (lhs.id != rhs.id || lhs.instruction_id != rhs.instruction_id ||
            lhs.displacement != rhs.displacement || lhs.immediate != rhs.immediate ||
            lhs.resolved_expression_value != rhs.resolved_expression_value ||
            lhs.bit_width != rhs.bit_width ||
            lhs.access_width_bits != rhs.access_width_bits ||
            lhs.reg != rhs.reg || lhs.segment_reg != rhs.segment_reg ||
            lhs.base_reg != rhs.base_reg || lhs.index_reg != rhs.index_reg ||
            lhs.address_components != rhs.address_components ||
            lhs.access_count != rhs.access_count ||
            lhs.element_count != rhs.element_count ||
            lhs.address_width_bits != rhs.address_width_bits ||
            lhs.operand_index != rhs.operand_index ||
            lhs.decoder_operand_id != rhs.decoder_operand_id ||
            lhs.kind != rhs.kind || lhs.access != rhs.access ||
            lhs.visibility != rhs.visibility || lhs.encoding != rhs.encoding ||
            lhs.memory_type != rhs.memory_type ||
            lhs.access_width != rhs.access_width || lhs.scale != rhs.scale ||
            lhs.relative != rhs.relative || lhs.signed_value != rhs.signed_value ||
            lhs.has_displacement != rhs.has_displacement ||
            lhs.has_resolved_expression_value != rhs.has_resolved_expression_value ||
            lhs.address_expression != rhs.address_expression ||
            lhs.address_resolution != rhs.address_resolution ||
            lhs.address_expression_id != rhs.address_expression_id ||
            lhs.element_width_bits != rhs.element_width_bits) {
            parity = false;
            break;
        }
    }
    preview_fixture_require(parity, "preview paged residency parity");
}

[[noreturn]] void preview_fixture_failure(
    const std::string& stage, const analysis::workspace_error_t& error) {
    throw std::runtime_error(stage + ": " + error.stable_code() + ": " +
                             error.message);
}

void preview_fixture_require(bool condition, const char* stage) {
    if (!condition)
        throw std::runtime_error(std::string(stage) +
                                 ": deterministic preview invariant failed");
}

void validate_preview_overlay_history(
    const std::shared_ptr<analysis::analysis_workspace_t>& workspace,
    const std::shared_ptr<analysis::overlay_journal_t>& overlay) {
    analysis::overlay_operation_t first_operation;
    first_operation.kind = analysis::overlay_operation_kind_t::comment;
    first_operation.address = rva(0x3F00);
    first_operation.text = "Preview history probe A";
    analysis::overlay_transaction_request_t first_request;
    first_request.expected_revision = overlay->snapshot().revision;
    first_request.operations.push_back(first_operation);
    auto first = overlay->transact(first_request, {});
    if (!first)
        preview_fixture_failure("preview overlay probe transact", first.error());
    preview_fixture_require(first.value().committed &&
        first.value().transaction_id == 1 && first.value().revision == 1,
        "preview overlay probe transact result");
    auto first_history = overlay->history_snapshot();
    auto first_presentation = workspace->overlay_presentation();
    preview_fixture_require(first_history.can_undo() && !first_history.can_redo() &&
        first_history.history_cursor == 1 && first_history.next_transaction_id == 2 &&
        workspace->overlay_revision() == 1 && first_presentation &&
        first_presentation->overlay_revision == 1 &&
        first_presentation->comments.size() == 1 &&
        first_presentation->comments.front().text == first_operation.text,
        "preview overlay probe publication");

    auto first_undo = overlay->undo(first.value().revision, {});
    if (!first_undo)
        preview_fixture_failure("preview overlay probe undo", first_undo.error());
    auto undone_history = overlay->history_snapshot();
    auto undone_presentation = workspace->overlay_presentation();
    preview_fixture_require(first_undo.value().transaction_id == 1 &&
        first_undo.value().revision == 2 && !undone_history.can_undo() &&
        undone_history.can_redo() && undone_history.history_cursor == 0 &&
        overlay->snapshot().items.empty() && workspace->overlay_revision() == 2 &&
        undone_presentation && undone_presentation->comments.empty(),
        "preview overlay probe undo publication");

    auto first_redo = overlay->redo(first_undo.value().revision, {});
    if (!first_redo)
        preview_fixture_failure("preview overlay probe redo", first_redo.error());
    auto redone_history = overlay->history_snapshot();
    preview_fixture_require(first_redo.value().transaction_id == 1 &&
        first_redo.value().revision == 3 && redone_history.can_undo() &&
        !redone_history.can_redo() && overlay->snapshot().items.size() == 1 &&
        workspace->overlay_revision() == 3,
        "preview overlay probe redo publication");

    auto branch_undo = overlay->undo(first_redo.value().revision, {});
    if (!branch_undo)
        preview_fixture_failure("preview overlay branch undo", branch_undo.error());
    analysis::overlay_operation_t branch_operation = first_operation;
    branch_operation.text = "Preview history probe B";
    analysis::overlay_transaction_request_t branch_request;
    branch_request.expected_revision = branch_undo.value().revision;
    branch_request.operations.push_back(branch_operation);
    auto branch = overlay->transact(branch_request, {});
    if (!branch)
        preview_fixture_failure("preview overlay branch transact", branch.error());
    const auto branch_history = overlay->history_snapshot();
    preview_fixture_require(branch.value().transaction_id == 2 &&
        branch.value().revision == 5 && branch_history.history_epoch == 2 &&
        branch_history.history_cursor == 2 &&
        branch_history.next_transaction_id == 3 && !branch_history.can_redo(),
        "preview overlay redo truncation");
    auto truncated_redo = overlay->redo(branch.value().revision, {});
    preview_fixture_require(!truncated_redo &&
        truncated_redo.error().code == analysis::workspace_error_code_t::target_not_found,
        "preview overlay truncated redo rejection");
    auto branch_restore = overlay->undo(branch.value().revision, {});
    if (!branch_restore)
        preview_fixture_failure("preview overlay branch restoration",
                                branch_restore.error());
    const auto restored = overlay->snapshot();
    const auto restored_history = overlay->history_snapshot();
    const auto restored_presentation = workspace->overlay_presentation();
    preview_fixture_require(restored.items.empty() && restored.revision == 6 &&
        restored_history.history_cursor == 0 && restored_history.can_redo() &&
        workspace->overlay_revision() == restored.revision &&
        restored_presentation && restored_presentation->comments.empty(),
        "preview overlay probe state restoration");
}

workspace_preview_fixture_t make_fixture(bool live_process) {
    workspace_preview_fixture_t fixture;
    fixture.session_id = "as_aida_preview_0001";
    fixture.source_path = "C:\\Samples\\suspicious_payload.exe";
    fixture.filename = "suspicious_payload.exe";
    fixture.display_name = "Suspicious Payload Analysis";
    const auto content_hash = digest(0x31);
    const auto profile_hash = digest(0xA4);
    const auto binary_id = digest(0x6D);
    auto corpus = build_preview_corpus();
    auto provider = analysis::memory_provider_t::create(
        fixture.source_path, std::move(corpus.bytes), content_hash);
    analysis::workspace_identity_input_t input;
    input.bin_name = fixture.filename;
    input.source_path = fixture.source_path;
    input.content_hash = content_hash;
    input.load_profile_hash = profile_hash;
    input.format = analysis::format_id_t::pe32_plus;
    input.architecture = analysis::architecture_id_t::x86_64;
    input.architecture_mode = analysis::architecture_mode_t::x86_64;
    input.abi = analysis::abi_id_t::windows_x64;
    input.image_base = 0x0000000140000000ULL;
    if (live_process) {
        input.target_kind = analysis::target_kind_t::live_snapshot;
        input.image_base = 0x00007FF7A4C00000ULL;
        input.process = analysis::process_identity_t{
            6420, 1, "c:\\samples\\suspicious_payload.exe"};
        input.module = analysis::module_identity_t{
            0x00007FF7A4C00000ULL, 0x001A0000ULL, "suspicious_payload.exe",
            "c:\\samples\\suspicious_payload.exe",
            std::optional<analysis::sha256_digest_t>{content_hash}};
    }
    auto identity = analysis::workspace_identity_t::create_preview(
        binary_id, std::move(input));
    auto pe = analysis::pe_image_t::create_preview();
    auto normalized = normalized_image(binary_id, content_hash,
                                       fixture.source_path, corpus);
    auto snapshot = analysis_snapshot(binary_id, profile_hash, normalized, pe,
                                      corpus);
    verify_paged_residency_parity(snapshot);
    auto created = analysis::analysis_workspace_t::create_preview(
        std::move(identity), std::move(provider), std::move(normalized),
        std::move(pe), std::move(snapshot));
    if (created) {
        fixture.workspace = created.take_value();
        auto overlay = analysis::overlay_journal_t::open_preview(fixture.workspace);
        if (overlay && !live_process) {
            validate_preview_overlay_history(fixture.workspace, overlay.value());
            static constexpr std::array<const char*, 12> analyst_notes{{
                "Program entry; initializes the staged analysis pipeline",
                "Validates image metadata before recursive traversal",
                "Walks section descriptors and records executable ranges",
                "Resolves import slots with module provenance",
                "Examines TLS callbacks before the nominal entry point",
                "High-entropy region promoted for unpacking review",
                "Recovered buffer is retained as immutable evidence",
                "Rebuilds control-flow edges from direct and indirect targets",
                "Indexes code and data references for synchronized navigation",
                "Potential command-channel behavior requires network review",
                "Reconstructs types from repeated field access patterns",
                "Publishes findings without mutating the original sample"
            }};
            analysis::overlay_transaction_request_t request;
            request.expected_revision = overlay.value()->snapshot().revision;
            request.operations.reserve(analyst_notes.size() + 3U);
            for (std::size_t index = 0; index < analyst_notes.size(); ++index) {
                analysis::overlay_operation_t operation;
                operation.kind = analysis::overlay_operation_kind_t::comment;
                operation.address = rva(0x1000 + index * 0x1C0);
                operation.text = analyst_notes[index];
                request.operations.push_back(std::move(operation));
            }
            for (const auto& bookmark : std::array{
                     std::pair{0x1460ULL, "Parser entry"},
                     std::pair{0x1C40ULL, "Unpacking review"},
                     std::pair{0x2420ULL, "Command channel"}}) {
                analysis::overlay_operation_t operation;
                operation.kind = analysis::overlay_operation_kind_t::bookmark;
                operation.address = rva(bookmark.first);
                operation.name = bookmark.second;
                request.operations.push_back(std::move(operation));
            }
            auto seeded = overlay.value()->transact(request, {});
            if (!seeded)
                preview_fixture_failure("preview overlay seed transaction",
                                        seeded.error());
            const auto seeded_snapshot = overlay.value()->snapshot();
            const auto seeded_history = overlay.value()->history_snapshot();
            const auto seeded_presentation = fixture.workspace->overlay_presentation();
            preview_fixture_require(seeded.value().committed &&
                seeded.value().transaction_id == 3 && seeded.value().revision == 7 &&
                seeded_snapshot.revision == seeded.value().revision &&
                seeded_snapshot.items.size() == analyst_notes.size() + 3U &&
                seeded_history.history_cursor == seeded.value().transaction_id &&
                seeded_history.next_transaction_id == 4 &&
                seeded_history.history_epoch == 3 && seeded_history.can_undo() &&
                !seeded_history.can_redo() && seeded_presentation &&
                seeded_presentation->overlay_revision == seeded.value().revision &&
                seeded_presentation->comments.size() == analyst_notes.size() &&
                seeded_presentation->bookmarks.size() == 3 &&
                seeded_presentation->workspace_bookmarks.size() == 3 &&
                fixture.workspace->overlay_revision() == seeded.value().revision,
                "preview overlay seeded publication");
        } else if (!overlay) {
            preview_fixture_failure("preview overlay open", overlay.error());
        }
        static_cast<void>(fixture.workspace->update_view_state([](auto& view) {
            view.selection = rva(0x1000);
            view.bookmarks = {rva(0x1460), rva(0x1C40), rva(0x2420)};
            view.revision = 3;
        }));
        workbench::workbench_shell_workspace_context_t workbench_context;
        static_cast<void>(workbench::workbench_shell_runtime_t::instance()
            .attach_analysis_workspace(fixture.workspace, workbench_context));
    }
    return fixture;
}

}

workspace_preview_target_t& configured_workspace_target() {
    static workspace_preview_target_t target = workspace_preview_target_t::static_file;
    return target;
}

void configure_workspace_preview_target(workspace_preview_target_t target) {
    configured_workspace_target() = target;
}

const workspace_preview_fixture_t& workspace_preview_fixture() {
    static const workspace_preview_fixture_t static_fixture = make_fixture(false);
    static const workspace_preview_fixture_t live_fixture = make_fixture(true);
    return configured_workspace_target() == workspace_preview_target_t::live_process
        ? live_fixture : static_fixture;
}

}

#endif
