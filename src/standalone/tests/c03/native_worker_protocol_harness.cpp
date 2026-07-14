#include "native_worker_protocol_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/native_worker_host.hpp"
#include "../../workers/native_decompiler/native_worker_runtime.hpp"

#include <windows.h>
#include <userenv.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "userenv.lib")

namespace aida::analysis::c03_test {
namespace {

using namespace native_worker;

class handle_t final {
public:
    handle_t() = default;
    explicit handle_t(HANDLE value) noexcept : value_(value) {}
    ~handle_t() { reset(); }

    handle_t(const handle_t&) = delete;
    handle_t& operator=(const handle_t&) = delete;

    HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }

    void reset(HANDLE value = nullptr) noexcept
    {
        if (*this)
            CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_ = nullptr;
};

class pipe_pair_t final {
public:
    pipe_pair_t()
    {
        HANDLE read = nullptr;
        HANDLE write = nullptr;
        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof(attributes);
        if (!CreatePipe(&read, &write, &attributes, 0))
            throw std::runtime_error("pipe creation failed");
        read_.reset(read);
        write_.reset(write);
    }

    HANDLE read() const noexcept { return read_.get(); }
    HANDLE write() const noexcept { return write_.get(); }

private:
    handle_t read_;
    handle_t write_;
};

class session_guard_t final {
public:
    explicit session_guard_t(wire::session_material_t& session) noexcept : session_(session) {}
    ~session_guard_t()
    {
        SecureZeroMemory(session_.key.data(), session_.key.size());
        SecureZeroMemory(session_.nonce.data(), session_.nonce.size());
    }

private:
    wire::session_material_t& session_;
};

class fixture_workspace_t final {
public:
    fixture_workspace_t(const std::filesystem::path& scratch_root, const std::filesystem::path& fake_worker)
    {
        std::error_code error;
        const auto scratch = std::filesystem::absolute(scratch_root, error).lexically_normal();
        if (error || !std::filesystem::is_directory(scratch, error) || error)
            throw std::runtime_error("native worker scratch root is not an existing directory");
        const DWORD scratch_attributes = GetFileAttributesW(scratch.c_str());
        if (scratch_attributes == INVALID_FILE_ATTRIBUTES || (scratch_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw std::runtime_error("native worker scratch root is a reparse point");
        const auto source = std::filesystem::absolute(fake_worker, error).lexically_normal();
        if (error || !std::filesystem::is_regular_file(source, error) || error)
            throw std::runtime_error("fake native worker is not a regular file");
        const DWORD source_attributes = GetFileAttributesW(source.c_str());
        if (source_attributes == INVALID_FILE_ATTRIBUTES ||
            (source_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            throw std::runtime_error("fake native worker is not a regular non-reparse file");
        const std::wstring prefix = L"aida-c03-native-worker-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()) + L"-";
        for (std::uint32_t attempt = 0; attempt < 64; ++attempt) {
            root_ = scratch / (prefix + std::to_wstring(attempt));
            if (std::filesystem::create_directory(root_, error))
                break;
            if (error && error != std::errc::file_exists)
                throw std::runtime_error("native worker scratch workspace could not be created");
            error.clear();
            root_.clear();
        }
        if (root_.empty())
            throw std::runtime_error("native worker scratch workspace name could not be reserved");
        try {
            worker_path_ = root_ / L"AiDA_FakeNativeDecompilerWorker.exe";
            if (!std::filesystem::copy_file(source, worker_path_, std::filesystem::copy_options::none, error) || error)
                throw std::runtime_error("fake native worker could not be staged");
        } catch (...) {
            cleanup();
            root_.clear();
            throw;
        }
    }

    ~fixture_workspace_t()
    {
        cleanup();
    }

    fixture_workspace_t(const fixture_workspace_t&) = delete;
    fixture_workspace_t& operator=(const fixture_workspace_t&) = delete;

    const std::filesystem::path& root() const noexcept { return root_; }
    const std::filesystem::path& worker_path() const noexcept { return worker_path_; }

private:
    void cleanup() noexcept
    {
        if (root_.empty())
            return;
        const DWORD root_attributes = GetFileAttributesW(root_.c_str());
        if (root_attributes == INVALID_FILE_ATTRIBUTES ||
            (root_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != FILE_ATTRIBUTE_DIRECTORY)
            return;
        if (!worker_path_.empty()) {
            const DWORD worker_attributes = GetFileAttributesW(worker_path_.c_str());
            if (worker_attributes != INVALID_FILE_ATTRIBUTES &&
                (worker_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0) {
                SetFileAttributesW(worker_path_.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(worker_path_.c_str());
            }
        }
        RemoveDirectoryW(root_.c_str());
    }

    std::filesystem::path root_;
    std::filesystem::path worker_path_;
};

void require(bool condition, std::string_view message)
{
    assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

sha256_digest_t digest(std::string_view value)
{
    sha256_digest_t result;
    require(wire::sha256(value.data(), value.size(), result), "SHA-256 calculation failed");
    return result;
}

sha256_digest_t locked_digest(std::string_view value)
{
    const auto parsed = sha256_digest_t::from_hex(std::string(value));
    require(parsed.has_value(), "locked SHA-256 value is malformed");
    return *parsed;
}

sha256_digest_t file_digest(const std::filesystem::path& path)
{
    handle_t file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    require(static_cast<bool>(file), "worker file could not be opened for hashing");
    LARGE_INTEGER size{};
    require(GetFileSizeEx(file.get(), &size) != FALSE && size.QuadPart > 0 &&
        static_cast<std::uint64_t>(size.QuadPart) <= 2ULL * 1024ULL * 1024ULL * 1024ULL,
        "worker file size violates the harness contract");
    std::vector<std::uint8_t> bytes;
    try {
        bytes.resize(static_cast<std::size_t>(size.QuadPart));
    } catch (...) {
        throw std::runtime_error("worker hash buffer allocation failed");
    }
    DWORD error = ERROR_SUCCESS;
    require(wire::read_all(file.get(), bytes.data(), bytes.size(), error), "worker file could not be read for hashing");
    sha256_digest_t result;
    require(wire::sha256(bytes.data(), bytes.size(), result), "worker file hash calculation failed");
    return result;
}

void write_binary_file(const std::filesystem::path& path, std::string_view bytes)
{
    require(!bytes.empty(), "manifest bytes are empty");
    handle_t file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    require(static_cast<bool>(file), "manifest file could not be created");
    DWORD error = ERROR_SUCCESS;
    require(wire::write_all(file.get(), bytes.data(), bytes.size(), error) && FlushFileBuffers(file.get()) != FALSE,
        "manifest file could not be committed");
}

native_worker_manifest_t manifest_fixture(const sha256_digest_t& worker_hash, std::string fixture)
{
    native_worker_manifest_t result;
    result.worker_relative_path = "AiDA_FakeNativeDecompilerWorker.exe";
    result.worker_binary_hash = worker_hash;
    result.provider.provider = decompiler_provider_id_t::ghidra_native;
    result.provider.provider_name = runtime::k_provider_name;
    result.provider.provider_version = runtime::k_provider_version;
    result.provider.provider_binary_hash = result.worker_binary_hash;
    result.provider.worker_build_id = runtime::k_worker_build_id;
    result.provider.worker_build_hash = stable_serialization_hash(runtime::k_worker_build_hash_material);
    result.worker_protocol_hash = native_worker_protocol_hash();
    if (!fixture.empty())
        result.startup_arguments.push_back("--fixture=" + std::move(fixture));
    return result;
}

native_worker_manifest_t manifest_fixture()
{
    return manifest_fixture(digest("worker-binary"), "replay");
}

native_worker_manifest_t managed_manifest_fixture()
{
    native_worker_manifest_t result;
    result.schema_version = k_managed_worker_manifest_schema_version;
    result.worker_relative_path = std::string(k_managed_worker_binary_artifact_relative_path);
    result.worker_binary_hash = digest("managed-worker-binary");
    result.provider.provider = decompiler_provider_id_t::ilspy_cli;
    result.provider.provider_name = "ICSharpCode.Decompiler";
    result.provider.provider_version = "10.1.0.8386";
    result.provider.provider_binary_hash = locked_digest(
        "bebc24d573164da41b6f43f521d96362516d0f4b5b2715a9e7d877f4b2730345");
    result.provider.worker_build_id = "aida-managed-decompiler-worker-v3";
    result.provider.worker_build_hash = locked_digest(
        "4dd8c0d095629437387a4b631fd9ac3c3cb8e840f6b7af277ccc2ad49d4bc3b7");
    result.worker_protocol_hash = native_worker_protocol_hash();
    result.managed_runtime_manifest_hash = digest("managed-runtime-manifest");
    return result;
}

decompiler_worker_message_t heartbeat(const wire::session_material_t& session, std::uint64_t sequence)
{
    decompiler_worker_heartbeat_t value;
    value.envelope.kind = decompiler_worker_message_kind_t::heartbeat;
    value.envelope.session_nonce_hash = session.nonce_hash;
    value.envelope.sequence = sequence;
    value.active_job_id = 1;
    return value;
}

std::array<std::uint8_t, wire::k_frame_header_bytes> rejected_header(
    const wire::session_material_t& session, std::uint64_t sequence, std::uint32_t payload_size,
    bool malformed, bool nonce_mismatch)
{
    std::array<std::uint8_t, wire::k_frame_header_bytes> header{};
    wire::write_u32(header.data(), malformed ? wire::k_frame_magic ^ 0x80000000U : wire::k_frame_magic);
    wire::write_u16(header.data() + 4, wire::k_frame_version);
    wire::write_u16(header.data() + 6, static_cast<std::uint16_t>(wire::frame_kind_t::decompiler_contract));
    wire::write_u64(header.data() + 8, sequence);
    wire::write_u32(header.data() + 16, payload_size);
    std::memcpy(header.data() + 20, session.nonce_hash.bytes.data(), session.nonce_hash.bytes.size());
    if (nonce_mismatch)
        header[20] ^= 0x80U;
    return header;
}

void frame_round_trip_and_replay()
{
    pipe_pair_t pipe;
    wire::session_material_t session;
    session_guard_t session_guard(session);
    require(wire::make_session(session), "session creation failed");
    const auto message = heartbeat(session, 1);
    const auto payload = serialize_decompiler_worker_message(message);
    DWORD error = ERROR_SUCCESS;
    require(wire::send_frame(pipe.write(), session, wire::frame_kind_t::decompiler_contract, 1,
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), 1024 * 1024, error), "frame send failed");
    wire::frame_reader_t reader;
    wire::frame_t frame;
    require(reader.poll(pipe.read(), session, 1, 1024 * 1024, frame, error) == wire::read_state_t::complete,
        "valid frame was not accepted");
    require(frame.sequence == 1 && frame.payload.size() == payload.size(), "valid frame changed during receipt");
    require(wire::send_frame(pipe.write(), session, wire::frame_kind_t::decompiler_contract, 1,
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), 1024 * 1024, error), "replay frame send failed");
    require(reader.poll(pipe.read(), session, 2, 1024 * 1024, frame, error) == wire::read_state_t::failure &&
        reader.failure() == wire::frame_failure_t::replay, "replayed sequence did not produce a replay failure");
}

void rejected_header_diagnostics()
{
    wire::session_material_t session;
    session_guard_t session_guard(session);
    require(wire::make_session(session), "header diagnostic session creation failed");
    const auto verify = [&](const auto& header, wire::frame_failure_t expected, std::size_t maximum, std::string_view message) {
        pipe_pair_t pipe;
        DWORD error = ERROR_SUCCESS;
        require(wire::write_all(pipe.write(), header.data(), header.size(), error), "rejected header write failed");
        wire::frame_reader_t reader;
        wire::frame_t frame;
        require(reader.poll(pipe.read(), session, 1, maximum, frame, error) == wire::read_state_t::failure &&
            reader.failure() == expected, message);
    };
    verify(rejected_header(session, 1, 0, true, false), wire::frame_failure_t::malformed_header,
        1024 * 1024, "malformed header did not produce a distinct failure");
    verify(rejected_header(session, 1, 0, false, true), wire::frame_failure_t::nonce_mismatch,
        1024 * 1024, "nonce mismatch did not produce a distinct failure");
    verify(rejected_header(session, 1, 2U * 1024U * 1024U, false, false), wire::frame_failure_t::oversize,
        1024 * 1024, "oversize frame did not produce a distinct failure");
    auto authentication = rejected_header(session, 1, 0, false, false);
    std::array<std::uint8_t, wire::k_digest_bytes> tag{};
    require(wire::hmac_sha256(session.key.data(), session.key.size(), authentication.data(),
        wire::k_frame_header_without_tag_bytes, tag), "authentication fixture tag calculation failed");
    std::memcpy(authentication.data() + wire::k_frame_header_without_tag_bytes, tag.data(), tag.size());
    authentication.back() ^= 0x80U;
    SecureZeroMemory(tag.data(), tag.size());
    verify(authentication, wire::frame_failure_t::authentication_failed,
        1024 * 1024, "invalid frame tag did not produce an authentication failure");
}

void truncation_contract()
{
    pipe_pair_t pipe;
    wire::session_material_t session;
    session_guard_t session_guard(session);
    require(wire::make_session(session), "truncation session creation failed");
    std::array<std::uint8_t, 9> fragment{};
    wire::write_u32(fragment.data(), wire::k_frame_magic);
    DWORD error = ERROR_SUCCESS;
    require(wire::write_all(pipe.write(), fragment.data(), fragment.size(), error), "truncated frame write failed");
    wire::frame_reader_t reader;
    wire::frame_t frame;
    require(reader.poll(pipe.read(), session, 1, 1024 * 1024, frame, error) == wire::read_state_t::incomplete &&
        reader.has_partial_frame(), "truncated frame was not retained as an incomplete frame");
}

void manifest_and_snapshot_contracts()
{
    require(k_decompiler_worker_protocol_version == 3 &&
        native_worker_protocol_hash() == stable_serialization_hash(wire::k_protocol_hash_material) &&
        std::string_view(wire::k_protocol_hash_material).find(
            "bounded-native-printc-evidence|control-frame-8m|result-frame-80m|provider-artifacts-48m|printc-8m") !=
            std::string_view::npos,
        "native worker protocol identity does not bind the PrintC evidence extension");
    require(k_native_worker_binary_artifact_relative_path == "deps/AiDA_NativeDecompilerWorker.exe" &&
        k_native_worker_manifest_artifact_relative_path == "deps/AiDA_NativeDecompilerWorker.manifest.bin" &&
        k_native_worker_manifest_digest_relative_path == "deps/AiDA_NativeDecompilerWorker.manifest.sha256" &&
        k_managed_worker_binary_artifact_relative_path == "deps/AiDA_ManagedDecompilerWorker.exe" &&
        k_managed_worker_manifest_artifact_relative_path == "deps/AiDA_ManagedDecompilerWorker.manifest.bin" &&
        k_managed_worker_manifest_digest_relative_path == "deps/AiDA_ManagedDecompilerWorker.manifest.sha256" &&
        k_managed_runtime_manifest_artifact_relative_path == "deps/AiDA_ManagedRuntime.manifest.json" &&
        k_managed_runtime_manifest_digest_relative_path == "deps/AiDA_ManagedRuntime.manifest.sha256" &&
        k_managed_dotnet_root_relative_path == "deps/dotnet",
        "worker production artifact paths drifted from the packaging contract");
    const auto manifest = manifest_fixture();
    const std::string serialized = serialize_native_worker_manifest(manifest);
    require(!serialized.empty(), "manifest did not serialize");
    require(wire::read_u32(reinterpret_cast<const std::uint8_t*>(serialized.data())) == k_native_worker_manifest_magic,
        "manifest magic does not match the packaging contract");
    const auto decoded = deserialize_native_worker_manifest(serialized);
    require(decoded.valid() && decoded.value.has_value(), "manifest did not deserialize");
    require(decoded.value->worker_binary_hash == manifest.worker_binary_hash &&
        decoded.value->worker_protocol_hash == native_worker_protocol_hash(), "manifest identity changed during round trip");
    sha256_digest_t before;
    sha256_digest_t after;
    require(wire::sha256(serialized.data(), serialized.size(), before), "manifest hash failed");
    std::string tampered = serialized;
    tampered.back() ^= 0x01;
    require(wire::sha256(tampered.data(), tampered.size(), after) && before != after,
        "manifest hash mismatch fixture is ineffective");
    tampered.pop_back();
    require(!deserialize_native_worker_manifest(tampered).valid(), "truncated manifest was accepted");
    const auto managed_manifest = managed_manifest_fixture();
    const auto managed_serialized = serialize_native_worker_manifest(managed_manifest);
    require(!managed_serialized.empty(), "managed manifest v3 did not serialize");
    const auto managed_decoded = deserialize_native_worker_manifest(managed_serialized);
    require(managed_decoded.valid() && managed_decoded.value &&
        managed_decoded.value->schema_version == k_managed_worker_manifest_schema_version &&
        managed_decoded.value->provider.provider == decompiler_provider_id_t::ilspy_cli &&
        managed_decoded.value->managed_runtime_manifest_hash ==
            managed_manifest.managed_runtime_manifest_hash &&
        managed_serialized.size() >= managed_manifest.managed_runtime_manifest_hash.bytes.size() &&
        std::equal(managed_manifest.managed_runtime_manifest_hash.bytes.begin(),
            managed_manifest.managed_runtime_manifest_hash.bytes.end(),
            reinterpret_cast<const std::uint8_t*>(managed_serialized.data()) +
                managed_serialized.size() -
                managed_manifest.managed_runtime_manifest_hash.bytes.size()),
        "managed manifest v3 runtime identity did not round trip as the final digest field");
    auto truncated_managed = managed_serialized;
    truncated_managed.pop_back();
    require(!deserialize_native_worker_manifest(truncated_managed).valid(),
        "managed manifest v3 accepted a truncated runtime identity");
    auto snapshot = make_native_worker_snapshot({0x48, 0x31, 0xc0, 0xc3});
    require(snapshot.has_value() && snapshot->valid(), "read-only snapshot factory failed");
    sha256_digest_t verified;
    require(wire::sha256(snapshot->bytes->data(), snapshot->bytes->size(), verified) && verified == snapshot->hash,
        "snapshot hash is not bound to immutable bytes");
}

address_t fixture_address(std::uint64_t value)
{
    address_t result;
    result.space = address_space_id_t::relative_virtual;
    result.value = value;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_entity_key_t fixture_entity(const sha256_digest_t& snapshot_hash)
{
    native_decompiler_entity_identity_t identity;
    identity.function_id = 1;
    identity.entry = fixture_address(0x1000);
    identity.end = fixture_address(0x1004);
    identity.function_bytes_hash = snapshot_hash;
    identity.canonical_symbol = "c03::native_worker_fixture";
    decompiler_entity_key_t result;
    result.kind = decompiler_entity_kind_t::native_function;
    result.format = format_id_t::pe32_plus;
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    result.identity = std::move(identity);
    return result;
}

decompiler_language_identity_t fixture_language()
{
    decompiler_language_identity_t result;
    result.language_id = "x86:LE:64:default";
    result.language_version = "1";
    result.compiler_spec_id = "windows";
    result.language_spec_hash = digest("c03-native-worker-language");
    result.architecture = architecture_id_t::x86_64;
    result.mode = architecture_mode_t::x86_64;
    return result;
}

decompiler_profile_budget_t fixture_profile()
{
    decompiler_profile_budget_t result;
    result.profile = decompiler_profile_id_t::balanced;
    result.max_wall_clock_ms = 5000;
    result.max_cpu_ms = 4000;
    result.max_memory_bytes = 256ULL << 20;
    result.max_provider_ir_nodes = 100000;
    result.max_hir_nodes = 100000;
    result.max_ast_nodes = 100000;
    return result;
}

decompiler_pipeline_cache_key_t fixture_cache_key(const decompiler_entity_key_t& entity,
                                                   const decompiler_provider_identity_t& provider,
                                                   const sha256_digest_t& snapshot_hash,
                                                   const decompiler_profile_budget_t& profile)
{
    decompiler_pipeline_cache_key_t result;
    result.stage = decompiler_cache_stage_t::rendered_document;
    result.workspace_id = "c03-native-worker-host";
    result.workspace_generation = 1;
    result.analysis_revision = 1;
    result.entity = entity;
    result.provider = provider;
    result.worker_protocol_hash = native_worker_protocol_hash();
    result.language = fixture_language();
    result.loader_layout_hash = digest("c03-native-worker-layout");
    result.function_bytes_hash = snapshot_hash;
    result.chunk_fingerprints.push_back({fixture_address(0x1000), fixture_address(0x1004), snapshot_hash});
    result.metadata_revision = 1;
    result.type_graph_revision = 1;
    result.overlay_revision = 1;
    result.profile = profile;
    result.renderer.style_id = "aida.c03.native-worker";
    result.renderer.indentation_spaces = 4;
    result.dependencies.push_back({"native-worker", runtime::k_provider_version, provider.provider_binary_hash});
    return result;
}

enum class fixture_execution_t : std::uint8_t {
    normal,
    cancellation,
    deadline
};

native_worker_execution_result_t execute_fixture(const fixture_workspace_t& workspace,
                                                  const sha256_digest_t& worker_hash,
                                                  std::string fixture, std::uint64_t job_id,
                                                  fixture_execution_t execution = fixture_execution_t::normal)
{
    const native_worker_manifest_t manifest = manifest_fixture(worker_hash, fixture);
    const std::string manifest_bytes = serialize_native_worker_manifest(manifest);
    require(!manifest_bytes.empty(), "host fixture manifest did not serialize");
    sha256_digest_t manifest_hash;
    require(wire::sha256(manifest_bytes.data(), manifest_bytes.size(), manifest_hash),
        "host fixture manifest hash failed");
    const auto manifest_path = workspace.root() / (L"native-worker-" + std::wstring(fixture.begin(), fixture.end()) + L".manifest.bin");
    write_binary_file(manifest_path, manifest_bytes);
    native_worker_launch_contract_t contract;
    contract.approved_root = workspace.root();
    contract.manifest_path = manifest_path;
    contract.expected_manifest_hash = manifest_hash;
    native_worker_host_limits_t limits;
    limits.max_frame_bytes = 1024U * 1024U;
    limits.max_snapshot_bytes = 1024U * 1024U;
    limits.startup_timeout = std::chrono::seconds(10);
    limits.cancellation_grace = std::chrono::seconds(2);
    limits.poll_interval = std::chrono::milliseconds(2);
    native_worker_host_t host(std::move(contract), limits);
    native_worker_execution_request_t request;
    request.job_id = job_id;
    request.profile = fixture_profile();
    const auto snapshot = make_native_worker_snapshot({0x48, 0x31, 0xc0, 0xc3});
    require(snapshot.has_value(), "host fixture snapshot creation failed");
    request.snapshot = *snapshot;
    const auto entity = fixture_entity(request.snapshot.hash);
    request.cache_key = fixture_cache_key(entity, manifest.provider, request.snapshot.hash, request.profile);
    require(validate_decompiler_profile(request.profile).valid() &&
        validate_decompiler_pipeline_cache_key(request.cache_key).valid(), "host fixture request contract is invalid");
    if (execution == fixture_execution_t::cancellation)
        request.cancellation_requested = [] { return true; };
    if (execution == fixture_execution_t::deadline)
        request.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    auto result = host.execute(request);
    require(host.worker_generation() == 1 && result.worker_generation == 1,
        "host fixture did not allocate exactly one worker generation");
    const std::string profile_name_utf8 = std::string("AiDA.NativeWorker.") + manifest_hash.to_hex().substr(0, 32);
    const std::wstring profile_name(profile_name_utf8.begin(), profile_name_utf8.end());
    DeleteAppContainerProfile(profile_name.c_str());
    return result;
}

bool has_diagnostic(const native_worker_execution_result_t& result, native_worker_diagnostic_code_t code)
{
    return std::any_of(result.diagnostics.begin(), result.diagnostics.end(),
        [code](const native_worker_diagnostic_t& current) { return current.code == code; });
}

bool has_worker_key(const native_worker_execution_result_t& result, std::string_view key)
{
    return std::any_of(result.worker_diagnostics.begin(), result.worker_diagnostics.end(),
        [key](const decompiler_diagnostic_t& current) { return current.localization_key == key; });
}

void require_replaced_failure(const native_worker_execution_result_t& result,
                              native_worker_diagnostic_code_t code, std::string_view fixture)
{
    require(has_diagnostic(result, code), std::string(fixture) + " did not emit its required host diagnostic");
    require(result.worker_process_id != 0 && result.worker_terminated && result.worker_replaced &&
        has_diagnostic(result, native_worker_diagnostic_code_t::worker_replaced),
        std::string(fixture) + " did not terminate and invalidate the worker generation");
}

void host_protocol_fixtures(const fixture_workspace_t& workspace, const sha256_digest_t& worker_hash)
{
    std::uint64_t job_id = 1;
    require_replaced_failure(execute_fixture(workspace, worker_hash, "replay", job_id++),
        native_worker_diagnostic_code_t::protocol_replay, "replay fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "truncation", job_id++),
        native_worker_diagnostic_code_t::protocol_truncated, "truncation fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "oversize", job_id++),
        native_worker_diagnostic_code_t::protocol_oversize, "oversize fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "malformed_header", job_id++),
        native_worker_diagnostic_code_t::protocol_malformed, "malformed-header fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "nonce_mismatch", job_id++),
        native_worker_diagnostic_code_t::protocol_nonce_mismatch, "nonce-mismatch fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "hash_mismatch", job_id++),
        native_worker_diagnostic_code_t::worker_identity_mismatch, "hash-mismatch fixture");
    require_replaced_failure(execute_fixture(workspace, worker_hash, "crash", job_id++),
        native_worker_diagnostic_code_t::worker_crashed, "crash fixture");
    const auto hang = execute_fixture(workspace, worker_hash, "hang", job_id++, fixture_execution_t::deadline);
    require(hang.status == native_worker_execution_status_t::deadline_exceeded,
        "hang fixture did not end with deadline status");
    require_replaced_failure(hang, native_worker_diagnostic_code_t::deadline_exceeded, "hang fixture");
    const auto cancelled = execute_fixture(workspace, worker_hash, "cancel", job_id++, fixture_execution_t::cancellation);
    require(cancelled.status == native_worker_execution_status_t::cancelled &&
        has_worker_key(cancelled, "native_worker.fixture.cancelled"),
        "cancel fixture did not preserve the worker cancellation response");
    require_replaced_failure(cancelled, native_worker_diagnostic_code_t::cancelled, "cancel fixture");
    const auto replacement = execute_fixture(workspace, worker_hash, "replacement", job_id++);
    require(replacement.status == native_worker_execution_status_t::failed &&
        has_worker_key(replacement, "native_worker.fixture.replacement"),
        "replacement fixture did not preserve its typed retryable failure");
    require_replaced_failure(replacement, native_worker_diagnostic_code_t::worker_failed, "replacement fixture");
}

void host_containment_fixtures(const fixture_workspace_t& workspace, const sha256_digest_t& worker_hash)
{
    const auto network = execute_fixture(workspace, worker_hash, "no_network", 100);
    require(network.status == native_worker_execution_status_t::failed && network.worker_terminated &&
        !network.worker_replaced && has_worker_key(network, "native_worker.fixture.network_denied") &&
        !has_worker_key(network, "native_worker.fixture.network_violation"),
        "network fixture did not prove fail-closed AppContainer network isolation");
    const auto child = execute_fixture(workspace, worker_hash, "child", 101);
    require(child.status == native_worker_execution_status_t::failed && child.worker_terminated &&
        !child.worker_replaced && has_worker_key(child, "native_worker.fixture.child_denied") &&
        !has_worker_key(child, "native_worker.fixture.child_violation"),
        "child fixture did not prove child-process restriction");
    const auto handles = execute_fixture(workspace, worker_hash, "handles", 102);
    require(handles.status == native_worker_execution_status_t::failed && handles.worker_terminated &&
        !handles.worker_replaced && has_worker_key(handles, "native_worker.fixture.handle_capability_denied") &&
        !has_worker_key(handles, "native_worker.fixture.handle_capability_violation"),
        "handle fixture did not prove the inherited-handle and protected-DACL boundary");
}

void fixture_inventory()
{
    constexpr std::array<std::string_view, 13> fixtures{
        "replay", "truncation", "oversize", "malformed_header", "nonce_mismatch", "hash_mismatch", "crash",
        "hang", "cancel", "replacement", "no_network", "child", "handles"
    };
    require(fixtures.size() == 13, "fixture inventory is incomplete");
    for (const auto fixture : fixtures)
        require(!fixture.empty(), "fixture identifier is empty");
}

void result_frame_contracts()
{
    require(runtime::classify_document_payload_size(1) ==
        runtime::document_send_status_t::sent,
        "result-frame classifier rejected a bounded payload");
    require(runtime::classify_document_payload_size(
        k_decompiler_worker_result_frame_max_bytes) ==
        runtime::document_send_status_t::sent,
        "result-frame classifier rejected the exact frame boundary");
    require(runtime::classify_document_payload_size(
        k_decompiler_worker_result_frame_max_bytes + 1U) ==
        runtime::document_send_status_t::resource_limit,
        "result-frame classifier accepted a one-byte-over payload");
    runtime::startup_t unavailable_channel;
    require(!runtime::send_failure(unavailable_channel, 1,
        decompiler_diagnostic_code_t::resource_limit,
        "decompiler.isolated_worker.result_frame_limit"),
        "resource-limit fallback unexpectedly succeeded without an authenticated channel");
}

}

bool run_native_worker_protocol_harness(std::string& failure)
{
    try {
        require(!native_worker_protocol_hash().empty(), "protocol hash is empty");
        manifest_and_snapshot_contracts();
        frame_round_trip_and_replay();
        rejected_header_diagnostics();
        truncation_contract();
        result_frame_contracts();
        fixture_inventory();
        failure.clear();
        return true;
    } catch (const std::exception& error) {
        assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    } catch (...) {
        assertion_telemetry::record_exception(
            "native worker protocol harness failed with a non-standard exception");
        failure = "native worker protocol harness failed with a non-standard exception";
        return false;
    }
}

bool run_native_worker_host_harness(const native_worker_host_harness_paths_t& paths, std::string& failure)
{
    try {
        require(!paths.fake_worker_path.empty() && !paths.scratch_root.empty(),
            "native worker host harness paths are incomplete");
        fixture_workspace_t workspace(paths.scratch_root, paths.fake_worker_path);
        const auto worker_hash = file_digest(workspace.worker_path());
        require(!worker_hash.empty(), "staged fake native worker hash is empty");
        host_protocol_fixtures(workspace, worker_hash);
        host_containment_fixtures(workspace, worker_hash);
        failure.clear();
        return true;
    } catch (const std::exception& error) {
        assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    } catch (...) {
        assertion_telemetry::record_exception(
            "native worker host harness failed with a non-standard exception");
        failure = "native worker host harness failed with a non-standard exception";
        return false;
    }
}

}

int main(int argc, char** argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--protocol-only") {
        std::string failure;
        if (!aida::analysis::c03_test::run_native_worker_protocol_harness(failure)) {
            std::cerr << failure << '\n';
            return 1;
        }
        return 0;
    }
    if (argc != 3) {
        aida::analysis::c03_test::assertion_telemetry::record_assertion(false,
            "native worker protocol harness arguments are invalid", __FILE__, __LINE__);
        std::cerr << "usage: native_worker_protocol_harness --protocol-only | <fake-worker> <scratch-root>\n";
        return 2;
    }
    std::string failure;
    if (!aida::analysis::c03_test::run_native_worker_protocol_harness(failure)) {
        std::cerr << failure << '\n';
        return 1;
    }
    aida::analysis::c03_test::native_worker_host_harness_paths_t paths;
    paths.fake_worker_path = std::filesystem::u8path(argv[1]);
    paths.scratch_root = std::filesystem::u8path(argv[2]);
    if (!aida::analysis::c03_test::run_native_worker_host_harness(paths, failure)) {
        std::cerr << failure << '\n';
        return 1;
    }
    return 0;
}
