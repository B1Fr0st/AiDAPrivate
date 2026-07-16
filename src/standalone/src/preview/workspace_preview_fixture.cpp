#include "workspace_preview_fixture.hpp"

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../core/analysis/workspace/overlay_journal.hpp"
#include "../core/workbench/workbench_shell_integration.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
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
    image->imports_.push_back({"USER32.dll", std::string("MessageBoxW"),
                               std::nullopt, std::nullopt, 0x3090, 0x4090,
                               false});
    image->exports_.push_back({std::string("AnalyzeTarget"), 1, 0x1180,
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

workspace_result_t<overlay_transaction_result_t> overlay_journal_t::transact(
    const overlay_transaction_request_t& request,
    const cancellation_token_t& cancel) {
    auto workspace = workspace_.lock();
    if (!workspace || workspace->closing())
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "preview overlay workspace is unavailable",
                                 "preview_overlay"));
    if (cancel.stop_requested())
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
    std::unique_lock state_lock(state_mutex_);
    if (request.expected_revision && *request.expected_revision != revision_)
        return workspace_result_t<overlay_transaction_result_t>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "preview overlay revision changed",
                                 "preview_overlay"));
    overlay_transaction_result_t result;
    result.transaction_id = history_cursor_ + 1;
    result.revision = request.dry_run ? revision_ : revision_ + 1;
    result.dry_run = request.dry_run;
    result.committed = !request.dry_run;
    for (std::size_t index = 0; index < request.operations.size(); ++index) {
        const auto& operation = request.operations[index];
        const auto key = std::to_string(static_cast<unsigned>(operation.kind)) +
            ":" + std::to_string(operation.address.value) + ":" +
            operation.name + ":" + operation.variable;
        result.operations.push_back({index, key, operation.remove});
        if (request.dry_run)
            continue;
        if (operation.remove)
            items_.erase(key);
        else
            items_[key] = operation;
    }
    if (!request.dry_run) {
        const auto expected = revision_;
        state_lock.unlock();
        auto advanced = workspace->advance_overlay_revision(expected);
        state_lock.lock();
        if (!advanced)
            return workspace_result_t<overlay_transaction_result_t>::failure(
                advanced.error());
        revision_ = advanced.value();
        history_cursor_ = result.transaction_id;
        result.revision = revision_;
    }
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

std::vector<std::uint8_t> fixture_bytes() {
    std::vector<std::uint8_t> bytes(0x6000, 0);
    const std::array<std::uint8_t, 128> code{{
        0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x20,0x48,0x8B,0xF9,0x48,0x85,0xC9,
        0x74,0x23,0x48,0x8B,0x01,0xFF,0x50,0x18,0x84,0xC0,0x74,0x18,0x48,0x8B,0xCF,0xE8,
        0x5B,0x00,0x00,0x00,0x48,0x8B,0x5C,0x24,0x30,0x48,0x83,0xC4,0x20,0x5F,0xC3,0x33,
        0xC0,0xEB,0xF0,0xCC,0xCC,0xCC,0xCC,0x48,0x83,0xEC,0x28,0x48,0x8D,0x0D,0x99,0x20,
        0x00,0x00,0xE8,0x3B,0x00,0x00,0x00,0x48,0x85,0xC0,0x74,0x0A,0x48,0x8B,0xC8,0xE8,
        0x21,0x00,0x00,0x00,0x48,0x83,0xC4,0x28,0xC3,0xCC,0xCC,0x40,0x53,0x48,0x83,0xEC,
        0x20,0x48,0x8B,0xD9,0x48,0x8B,0x49,0x10,0x48,0x85,0xC9,0x74,0x06,0xFF,0x15,0xCA,
        0x1F,0x00,0x00,0x48,0x8B,0xC3,0x48,0x83,0xC4,0x20,0x5B,0xC3,0xCC,0xCC,0xCC,0xCC
    }};
    std::copy(code.begin(), code.end(), bytes.begin() + 0x400);
    const std::string banner = "AiDA Reverse Engineering Workspace";
    std::copy(banner.begin(), banner.end(), bytes.begin() + 0x2400);
    const std::string target = "suspicious_payload.bin";
    std::copy(target.begin(), target.end(), bytes.begin() + 0x2440);
    return bytes;
}

std::shared_ptr<const analysis::workspace_image_t> normalized_image(
    const analysis::binary_id_t& binary_id,
    const analysis::binary_id_t& content_hash,
    const std::string& source) {
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
    image->symbols = {
        {1, "entry_point", rva(0x1000), 0x34,
         analysis::image_symbol_kind_t::function,
         analysis::image_symbol_binding_t::global, true, false},
        {2, "analyze_image", rva(0x1040), 0x30,
         analysis::image_symbol_kind_t::function,
         analysis::image_symbol_binding_t::global, true, false},
        {3, "validate_header", rva(0x1080), 0x28,
         analysis::image_symbol_kind_t::function,
         analysis::image_symbol_binding_t::local, true, false},
        {4, "dispatch_analysis", rva(0x10C0), 0x30,
         analysis::image_symbol_kind_t::function,
         analysis::image_symbol_binding_t::local, true, false}};
    image->imports = {
        {"KERNEL32.dll", std::string("CreateFileW"), std::nullopt,
         rva(0x3080), rva(0x4080), false},
        {"USER32.dll", std::string("MessageBoxW"), std::nullopt,
         rva(0x3090), rva(0x4090), false}};
    image->exports = {{std::string("AnalyzeTarget"), 1, rva(0x1040),
                       std::nullopt}};
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
    const std::shared_ptr<const analysis::pe_image_t>& pe) {
    auto snapshot = std::make_shared<analysis::analysis_snapshot_t>();
    snapshot->binary_id = binary_id;
    snapshot->load_profile_hash = profile_hash;
    snapshot->generation = 1;
    snapshot->analysis_revision = 7;
    snapshot->overlay_revision = 0;
    snapshot->normalized_image = normalized;
    snapshot->image = pe;
    const std::array<std::uint64_t, 16> starts{{
        0x1000,0x1005,0x1009,0x100D,0x1010,0x1012,0x1017,0x1019,
        0x1040,0x1044,0x104B,0x1050,0x1080,0x1084,0x108B,0x1091}};
    const std::array<std::uint8_t, 16> lengths{{5,4,4,3,2,5,2,5,4,7,5,8,4,7,6,7}};
    for (std::size_t index = 0; index < starts.size(); ++index) {
        analysis::instruction_record_t instruction;
        instruction.id = (1ULL << 56) | (index + 1);
        instruction.address = rva(starts[index]);
        instruction.length = lengths[index];
        instruction.mnemonic_id = static_cast<std::uint16_t>(index % 9 + 1);
        instruction.opcode_id = static_cast<std::uint32_t>(0x100 + index);
        instruction.flow_flags = index == 7 || index == 11 || index == 15
            ? analysis::flow_return | analysis::flow_terminal
            : analysis::flow_fallthrough;
        instruction.provenance = analysis::fact_provenance_t::recursive_decode;
        instruction.confidence = 98;
        instruction.stable_source_id = 0xA1DA0000ULL + index;
        snapshot->instructions.push_back(std::move(instruction));
    }
    const std::array<std::pair<std::size_t, std::size_t>, 3> block_ranges{{
        {0, 8}, {8, 12}, {12, 16}}};
    for (std::size_t index = 0; index < block_ranges.size(); ++index) {
        const auto first = block_ranges[index].first;
        const auto end = block_ranges[index].second;
        analysis::basic_block_record_t block;
        block.id = (2ULL << 56) | (index + 1);
        block.function_id = (4ULL << 56) | (index + 1);
        block.start = snapshot->instructions[first].address;
        block.end = rva(snapshot->instructions[end - 1].address.value +
                        snapshot->instructions[end - 1].length);
        block.first_instruction = static_cast<std::uint32_t>(first);
        block.instruction_count = static_cast<std::uint32_t>(end - first);
        block.provenance = analysis::fact_provenance_t::recursive_decode;
        block.confidence = 96;
        snapshot->blocks.push_back(block);
        analysis::function_record_t function;
        function.id = block.function_id;
        function.start = block.start;
        function.end = block.end;
        function.first_block = static_cast<std::uint32_t>(index);
        function.block_count = 1;
        function.symbol_id = (7ULL << 56) | (index + 1);
        function.provenance = analysis::fact_provenance_t::debug_symbol;
        function.confidence = 97;
        snapshot->functions.push_back(std::move(function));
    }
    const std::array<const char*, 3> names{{
        "entry_point", "analyze_image", "validate_header"}};
    for (std::size_t index = 0; index < names.size(); ++index) {
        analysis::symbol_record_t symbol;
        symbol.id = (7ULL << 56) | (index + 1);
        symbol.address = snapshot->functions[index].start;
        symbol.name = names[index];
        symbol.kind = analysis::symbol_kind_t::function;
        symbol.provenance = analysis::fact_provenance_t::debug_symbol;
        symbol.confidence = 100;
        snapshot->symbols.push_back(std::move(symbol));
    }
    snapshot->strings = {
        {(6ULL << 56) | 1, rva(0x3000), 35,
         analysis::string_encoding_t::ascii,
         "AiDA Reverse Engineering Workspace",
         analysis::fact_provenance_t::linear_validation, 99},
        {(6ULL << 56) | 2, rva(0x3040), 23,
         analysis::string_encoding_t::ascii, "suspicious_payload.bin",
         analysis::fact_provenance_t::linear_validation, 99}};
    snapshot->xrefs = {
        {(5ULL << 56) | 1, rva(0x1019), rva(0x1040),
         analysis::xref_kind_t::call,
         analysis::fact_provenance_t::recursive_decode, 96},
        {(5ULL << 56) | 2, rva(0x1044), rva(0x3000),
         analysis::xref_kind_t::read,
         analysis::fact_provenance_t::recursive_decode, 94}};
    snapshot->coverage = {
        {rva(0x1000), 0x1E, analysis::coverage_reason_t::decoded,
         analysis::fact_provenance_t::recursive_decode, 98, 0},
        {rva(0x1040), 0x18, analysis::coverage_reason_t::decoded,
         analysis::fact_provenance_t::recursive_decode, 98, 0},
        {rva(0x1080), 0x18, analysis::coverage_reason_t::decoded,
         analysis::fact_provenance_t::recursive_decode, 98, 0},
        {rva(0x3000), 0x57, analysis::coverage_reason_t::proven_data,
         analysis::fact_provenance_t::linear_validation, 99, 0}};
    return snapshot;
}

workspace_preview_fixture_t make_fixture() {
    workspace_preview_fixture_t fixture;
    fixture.session_id = "as_aida_preview_0001";
    fixture.source_path = "C:\\Samples\\suspicious_payload.exe";
    fixture.filename = "suspicious_payload.exe";
    fixture.display_name = "Suspicious Payload Analysis";
    const auto content_hash = digest(0x31);
    const auto profile_hash = digest(0xA4);
    const auto binary_id = digest(0x6D);
    auto provider = analysis::memory_provider_t::create(
        fixture.source_path, fixture_bytes(), content_hash);
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
    auto identity = analysis::workspace_identity_t::create_preview(
        binary_id, std::move(input));
    auto pe = analysis::pe_image_t::create_preview();
    auto normalized = normalized_image(binary_id, content_hash,
                                       fixture.source_path);
    auto snapshot = analysis_snapshot(binary_id, profile_hash, normalized, pe);
    auto created = analysis::analysis_workspace_t::create_preview(
        std::move(identity), std::move(provider), std::move(normalized),
        std::move(pe), std::move(snapshot));
    if (created) {
        fixture.workspace = created.take_value();
        static_cast<void>(analysis::overlay_journal_t::open_preview(
            fixture.workspace));
        static_cast<void>(fixture.workspace->update_view_state([](auto& view) {
            view.selection = rva(0x1000);
            view.bookmarks = {rva(0x1040), rva(0x1080)};
            view.revision = 3;
        }));
        workbench::workbench_shell_workspace_context_t workbench_context;
        static_cast<void>(workbench::workbench_shell_runtime_t::instance()
            .attach_analysis_workspace(fixture.workspace, workbench_context));
    }
    return fixture;
}

}

const workspace_preview_fixture_t& workspace_preview_fixture() {
    static const workspace_preview_fixture_t fixture = make_fixture();
    return fixture;
}

}

#endif
