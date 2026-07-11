#include "jar_container.hpp"

#include <algorithm>
#include <iterator>
#include <limits>
#include <string_view>
#include <utility>

namespace aida::analysis {
namespace {

workspace_error_t jar_error(std::string message, std::uint64_t offset = 0,
                            std::uint64_t size = 0) {
    auto error = make_workspace_error(workspace_error_code_t::malformed_pe,
                                      std::move(message), "jar_container");
    error.offset = offset;
    error.size = size;
    return error;
}

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    auto error = make_workspace_error(cancel.deadline_exceeded()
                                          ? workspace_error_code_t::deadline_exceeded
                                          : workspace_error_code_t::cancelled,
                                      cancel.deadline_exceeded()
                                          ? "JAR processing deadline exceeded"
                                          : "JAR processing cancelled",
                                      "jar_container");
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

bool stopped(const cancellation_token_t& cancel) noexcept {
    return cancel.cancellation_requested() || cancel.deadline_exceeded();
}

bool ascii_equal_folded(std::string_view left, std::string_view right) noexcept {
    if (left.size() != right.size())
        return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        const auto fold = [](unsigned char value) {
            return value >= 'A' && value <= 'Z' ? static_cast<unsigned char>(value + ('a' - 'A')) : value;
        };
        if (fold(static_cast<unsigned char>(left[index])) != fold(static_cast<unsigned char>(right[index])))
            return false;
    }
    return true;
}

bool ends_with(std::string_view value, std::string_view suffix) noexcept {
    return value.size() >= suffix.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool has_nested_container_extension(std::string_view path) noexcept {
    return ends_with(path, ".jar") || ends_with(path, ".zip") || ends_with(path, ".war") ||
           ends_with(path, ".ear") || ends_with(path, ".apk") || ends_with(path, ".jmod");
}

std::optional<std::uint32_t> multi_release_version(std::string_view path) {
    constexpr std::string_view prefix = "META-INF/versions/";
    if (path.substr(0, prefix.size()) != prefix)
        return std::nullopt;
    const auto separator = path.find('/', prefix.size());
    if (separator == std::string_view::npos || separator == prefix.size() || separator + 1 == path.size())
        return std::nullopt;
    std::uint64_t value = 0;
    for (std::size_t index = prefix.size(); index < separator; ++index) {
        const auto character = path[index];
        if (character < '0' || character > '9')
            return std::nullopt;
        value = value * 10 + static_cast<std::uint64_t>(character - '0');
        if (value > (std::numeric_limits<std::uint32_t>::max)())
            return std::nullopt;
    }
    if (value == 0)
        return std::nullopt;
    return static_cast<std::uint32_t>(value);
}

std::string effective_class_path(std::string_view member_path) {
    constexpr std::string_view prefix = "META-INF/versions/";
    if (const auto version = multi_release_version(member_path)) {
        const auto version_end = member_path.find('/', prefix.size());
        return std::string(member_path.substr(version_end + 1));
    }
    return std::string(member_path);
}

std::string class_name_from_path(std::string path) {
    path.resize(path.size() - 6);
    return path;
}

bool manifest_declares_multi_release(std::string_view manifest) {
    std::string current_name;
    std::string current_value;
    const auto consume = [&]() {
        const auto answer = ascii_equal_folded(current_name, "Multi-Release") &&
                            ascii_equal_folded(current_value, "true");
        current_name.clear();
        current_value.clear();
        return answer;
    };
    std::size_t offset = 0;
    while (offset < manifest.size()) {
        const auto line_end = manifest.find('\n', offset);
        auto line = manifest.substr(offset, (line_end == std::string_view::npos ? manifest.size() : line_end) - offset);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        offset = line_end == std::string_view::npos ? manifest.size() : line_end + 1;
        if (line.empty()) {
            if (consume())
                return true;
            continue;
        }
        if (line.front() == ' ') {
            if (!current_name.empty())
                current_value.append(line.substr(1));
            continue;
        }
        if (consume())
            return true;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || colon + 1 >= line.size() || line[colon + 1] != ' ')
            continue;
        current_name.assign(line.substr(0, colon));
        current_value.assign(line.substr(colon + 2));
    }
    return consume();
}

workspace_result_t<bool> read_multi_release_manifest(const zip_container_t& zip,
                                                      std::uint64_t max_manifest_bytes,
                                                      const cancellation_token_t& cancel) {
    const auto* member = zip.find_member("META-INF/MANIFEST.MF");
    if (member == nullptr)
        return workspace_result_t<bool>::success(false);
    if (member->kind != zip_member_kind_t::regular_file || member->uncompressed_size > max_manifest_bytes)
        return workspace_result_t<bool>::failure(jar_error(
            "manifest member exceeds JAR manifest budget", member->data_offset, member->uncompressed_size));
    auto provider = zip.open_member_provider("META-INF/MANIFEST.MF", cancel);
    if (!provider)
        return workspace_result_t<bool>::failure(std::move(provider.error()));
    auto bytes = provider.value()->read_vector(0, member->uncompressed_size, max_manifest_bytes, cancel);
    if (!bytes)
        return workspace_result_t<bool>::failure(std::move(bytes.error()));
    return workspace_result_t<bool>::success(manifest_declares_multi_release(
        std::string_view(reinterpret_cast<const char*>(bytes.value().data()), bytes.value().size())));
}

container_member_t make_member(const zip_member_t& member, bool multi_release) {
    container_member_t result;
    result.name = member.normalized_path;
    result.token.ordinal = member.ordinal;
    result.token.local_header_offset = member.local_header_offset;
    result.token.data_offset = member.data_offset;
    result.token.uncompressed_size = member.uncompressed_size;
    result.token.crc32 = member.crc32;
    result.provenance = member.provenance;
    result.compressed_size = member.compressed_size;
    result.uncompressed_size = member.uncompressed_size;
    result.compression_method = member.compression_method;
    result.crc32 = member.crc32;
    result.external_attributes = member.external_attributes;
    result.is_directory = member.kind == zip_member_kind_t::directory;
    if (result.is_directory)
        return result;
    result.is_class = ends_with(result.name, ".class");
    result.is_nested_class = result.is_class && result.name.find('$') != std::string::npos;
    result.is_nested_container = has_nested_container_extension(result.name);
    result.is_code = result.is_class || result.is_nested_container;
    result.format_hint = result.is_class ? format_id_t::classfile :
                         result.is_nested_container ? format_id_t::jar : format_id_t::unknown;
    result.architecture_hint = result.is_class ? architecture_id_t::jvm_bytecode : architecture_id_t::unknown;
    if (const auto version = multi_release_version(result.name)) {
        result.multi_release_version = *version;
        result.is_multi_release_layout = true;
        result.is_active_multi_release_entry = multi_release;
    }
    return result;
}

std::shared_ptr<const byte_provider_t> borrowed_provider(const byte_provider_t& provider) {
    return std::shared_ptr<const byte_provider_t>(&provider, [](const byte_provider_t*) {});
}

bool same_token(const jar_member_token_t& left, const jar_member_token_t& right) noexcept {
    return left == right;
}

} 

jar_container_t::jar_container_t(std::shared_ptr<const byte_provider_t> provider,
                                 std::shared_ptr<zip_container_t> zip,
                                 jar_parse_limits_t limits,
                                 std::vector<container_member_t> members,
                                 bool multi_release)
    : provider_(std::move(provider)), zip_(std::move(zip)), limits_(std::move(limits)),
      members_(std::move(members)), multi_release_(multi_release) {}

workspace_result_t<std::shared_ptr<jar_container_t>> jar_container_t::open(
    std::shared_ptr<const byte_provider_t> provider, jar_parse_limits_t limits,
    const cancellation_token_t& cancel) {
    if (provider == nullptr)
        return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "JAR source provider is required", "jar_container"));
    if (stopped(cancel))
        return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(stop_error(cancel));
    if (limits.max_class_members == 0 || limits.max_nested_code_members == 0 || limits.max_manifest_bytes == 0)
        return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument, "JAR parse limits must be nonzero", "jar_container"));
    auto zip = zip_container_t::open(provider, limits.zip, cancel);
    if (!zip)
        return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(std::move(zip.error()));
    auto multi_release = read_multi_release_manifest(*zip.value(), limits.max_manifest_bytes, cancel);
    if (!multi_release)
        return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(std::move(multi_release.error()));
    std::vector<container_member_t> members;
    members.reserve(zip.value()->members().size());
    std::uint64_t class_count = 0;
    std::uint64_t nested_code_count = 0;
    for (const auto& member : zip.value()->members()) {
        if (stopped(cancel))
            return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(stop_error(cancel));
        auto record = make_member(member, multi_release.value());
        if (record.is_class && ++class_count > limits.max_class_members)
            return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded, "JAR class-member count exceeds limit", "jar_container"));
        if ((record.is_nested_class || record.is_nested_container) && ++nested_code_count > limits.max_nested_code_members)
            return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded, "JAR nested code-member count exceeds limit", "jar_container"));
        members.push_back(std::move(record));
    }
    std::sort(members.begin(), members.end(), [](const container_member_t& left, const container_member_t& right) {
        return left.name != right.name ? left.name < right.name : left.token.ordinal < right.token.ordinal;
    });
    return workspace_result_t<std::shared_ptr<jar_container_t>>::success(std::shared_ptr<jar_container_t>(
        new jar_container_t(std::move(provider), zip.take_value(), std::move(limits),
                            std::move(members), multi_release.take_value())));
}

const byte_provider_identity_t& jar_container_t::source_identity() const noexcept {
    return provider_->identity();
}

const std::shared_ptr<const byte_provider_t>& jar_container_t::source_provider() const noexcept {
    return provider_;
}

const std::shared_ptr<zip_container_t>& jar_container_t::zip() const noexcept {
    return zip_;
}

const jar_parse_limits_t& jar_container_t::limits() const noexcept {
    return limits_;
}

const std::vector<container_member_t>& jar_container_t::members() const noexcept {
    return members_;
}

const container_member_t* jar_container_t::find_member(const jar_member_token_t& token) const noexcept {
    const auto found = std::find_if(members_.begin(), members_.end(), [&](const container_member_t& member) {
        return same_token(member.token, token);
    });
    return found == members_.end() ? nullptr : &*found;
}

const container_member_t* jar_container_t::find_member(const std::string& normalized_path) const noexcept {
    const auto found = std::lower_bound(members_.begin(), members_.end(), normalized_path,
        [](const container_member_t& member, const std::string& path) { return member.name < path; });
    return found == members_.end() || found->name != normalized_path ? nullptr : &*found;
}

bool jar_container_t::is_multi_release() const noexcept {
    return multi_release_;
}

workspace_result_t<std::shared_ptr<byte_provider_t>> jar_container_t::open_member_provider(
    const jar_member_token_t& token, const cancellation_token_t& cancel) const {
    if (stopped(cancel))
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(stop_error(cancel));
    const auto* record = find_member(token);
    if (record == nullptr)
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(jar_error("JAR member token was not found"));
    const auto& zip_members = zip_->members();
    const auto found = std::find_if(zip_members.begin(), zip_members.end(), [&](const zip_member_t& member) {
        return member.ordinal == token.ordinal && member.local_header_offset == token.local_header_offset &&
               member.data_offset == token.data_offset && member.uncompressed_size == token.uncompressed_size &&
               member.crc32 == token.crc32;
    });
    if (found == zip_members.end())
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(jar_error("JAR member token no longer matches ZIP metadata"));
    return zip_->open_member_provider(static_cast<std::size_t>(std::distance(zip_members.begin(), found)), cancel);
}

workspace_result_t<std::shared_ptr<byte_provider_t>> jar_container_t::open_member_provider(
    const std::string& normalized_path, const cancellation_token_t& cancel) const {
    const auto* record = find_member(normalized_path);
    if (record == nullptr)
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(jar_error("JAR member path was not found"));
    return open_member_provider(record->token, cancel);
}

workspace_result_t<std::shared_ptr<jar_container_t>> jar_container_t::open_nested_container(
    const jar_member_token_t& token, const cancellation_token_t& cancel) const {
    if (stopped(cancel))
        return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(stop_error(cancel));
    const auto* member = find_member(token);
    if (member == nullptr || !member->is_nested_container)
        return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(jar_error(
            "requested JAR member is not a nested container"));
    auto provider = open_member_provider(token, cancel);
    if (!provider)
        return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(std::move(provider.error()));
    return jar_container_t::open(std::move(provider.value()), limits_, cancel);
}

workspace_result_t<std::shared_ptr<jar_container_t>> jar_container_t::open_nested_container(
    const std::string& normalized_path, const cancellation_token_t& cancel) const {
    const auto* member = find_member(normalized_path);
    if (member == nullptr)
        return workspace_result_t<std::shared_ptr<jar_container_t>>::failure(jar_error(
            "JAR member path was not found"));
    return open_nested_container(member->token, cancel);
}

workspace_result_t<managed_class_record_t> jar_container_t::parse_class_member(
    const jar_member_token_t& token, const cancellation_token_t& cancel) const {
    if (stopped(cancel))
        return workspace_result_t<managed_class_record_t>::failure(stop_error(cancel));
    const auto* member = find_member(token);
    if (member == nullptr || !member->is_class)
        return workspace_result_t<managed_class_record_t>::failure(jar_error("requested JAR member is not a classfile"));
    auto provider = open_member_provider(token, cancel);
    if (!provider)
        return workspace_result_t<managed_class_record_t>::failure(std::move(provider.error()));
    auto classfile = parse_classfile_image(*provider.value(), limits_.classfile, cancel);
    if (!classfile)
        return workspace_result_t<managed_class_record_t>::failure(std::move(classfile.error()));
    const auto expected_name = class_name_from_path(effective_class_path(member->name));
    managed_class_record_t record;
    record.member = *member;
    record.identity.internal_name = classfile.value().this_class_name;
    record.identity.binary_name = record.identity.internal_name;
    std::replace(record.identity.binary_name.begin(), record.identity.binary_name.end(), '/', '.');
    record.identity.major_version = classfile.value().major_version;
    record.identity.minor_version = classfile.value().minor_version;
    record.identity.token = member->token;
    record.identity.provenance = member->provenance;
    record.identity.entry_name_matches_internal_name = record.identity.internal_name == expected_name;
    record.classfile = classfile.take_value();
    record.provider = provider.take_value();
    return workspace_result_t<managed_class_record_t>::success(std::move(record));
}

workspace_result_t<managed_class_record_t> jar_container_t::parse_class_member(
    const std::string& normalized_path, const cancellation_token_t& cancel) const {
    const auto* member = find_member(normalized_path);
    if (member == nullptr)
        return workspace_result_t<managed_class_record_t>::failure(jar_error("JAR member path was not found"));
    return parse_class_member(member->token, cancel);
}

workspace_result_t<std::vector<container_member_t>> enumerate_jar_members(
    const byte_provider_t& provider, const jar_parse_limits_t& limits,
    const cancellation_token_t& cancel) {
    auto jar = jar_container_t::open(borrowed_provider(provider), limits, cancel);
    if (!jar)
        return workspace_result_t<std::vector<container_member_t>>::failure(std::move(jar.error()));
    return workspace_result_t<std::vector<container_member_t>>::success(jar.value()->members());
}

workspace_result_t<std::vector<container_member_t>> enumerate_jar_members(
    const byte_provider_t& provider, const cancellation_token_t& cancel) {
    return enumerate_jar_members(provider, jar_parse_limits_t{}, cancel);
}

workspace_result_t<std::shared_ptr<byte_provider_t>> extract_jar_member(
    const byte_provider_t& provider, const container_member_t& member,
    const cancellation_token_t& cancel) {
    auto jar = jar_container_t::open(borrowed_provider(provider), jar_parse_limits_t{}, cancel);
    if (!jar)
        return workspace_result_t<std::shared_ptr<byte_provider_t>>::failure(std::move(jar.error()));
    return jar.value()->open_member_provider(member.token, cancel);
}

bool jar_is_multi_release(const byte_provider_t& provider, const cancellation_token_t& cancel) {
    auto jar = jar_container_t::open(borrowed_provider(provider), jar_parse_limits_t{}, cancel);
    return jar && jar.value()->is_multi_release();
}

}
