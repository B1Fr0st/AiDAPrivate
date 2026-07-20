#include "python_worker_harness.hpp"

#include "../../src/core/mcp/compat/python_worker_host.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <fstream>
#include <future>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace aida::standalone::tests::mcp_compat {

namespace {

using namespace aida::standalone::mcp::compat;
namespace worker_wire = aida::standalone::mcp::python_worker::wire;

constexpr std::uintmax_t k_source_contract_max_bytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::uintmax_t k_fixture_worker_max_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

std::vector<std::uint8_t> read_binary_file(const std::filesystem::path& path,
                                            std::uintmax_t maximum_bytes,
                                            std::string_view failure) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    require(!ec && size <= maximum_bytes &&
        size <= static_cast<std::uintmax_t>((std::numeric_limits<std::size_t>::max)()) &&
        size <= static_cast<std::uintmax_t>((std::numeric_limits<std::streamsize>::max)()), failure);
    std::ifstream input(path, std::ios::binary);
    require(static_cast<bool>(input), failure);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        require(input.gcount() == static_cast<std::streamsize>(bytes.size()) &&
            !input.fail() && !input.bad(), failure);
    }
    const auto trailing = input.get();
    require(trailing == std::char_traits<char>::eof() && input.eof() && !input.bad(), failure);
    return bytes;
}

void write_binary_file(const std::filesystem::path& path, std::string_view contents,
                       std::string_view failure) {
    require(contents.size() <= static_cast<std::size_t>(
        (std::numeric_limits<std::streamsize>::max)()), failure);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(static_cast<bool>(output), failure);
    if (!contents.empty())
        output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    output.close();
    require(static_cast<bool>(output), failure);
}

std::filesystem::path locate_root() {
    auto value = std::filesystem::current_path();
    for (std::size_t depth = 0; depth < 8; ++depth) {
        if (std::filesystem::exists(value / "AGENTS.md"))
            return value;
        if (!value.has_parent_path())
            break;
        value = value.parent_path();
    }
    throw std::runtime_error("repository root could not be located");
}

std::filesystem::path unique_temp_directory() {
    std::array<wchar_t, MAX_PATH> path{};
    const DWORD length = GetTempPathW(static_cast<DWORD>(path.size()), path.data());
    if (length == 0 || length >= path.size())
        throw std::runtime_error("temporary path cannot be resolved");
    const std::wstring name = L"aida-c03-b24-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
    const auto result = std::filesystem::path(path.data()) / name;
    std::filesystem::create_directories(result);
    return result;
}

void verify_source_contract() {
    const auto source = locate_root() / "src/standalone/workers/analysis_python/analysis_python_worker.py";
    const auto bytes = read_binary_file(source, k_source_contract_max_bytes,
        "analysis Python worker source is unavailable or changed while being read");
    require(!bytes.empty(), "analysis Python worker source is empty");
    const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    for (const std::string_view forbidden : {"camoufox", "socket", "subprocess", "Popen", "CreateProcess", "WriteProcessMemory", "py_eval"})
        require(text.find(forbidden) == std::string::npos, "analysis Python worker source exposes a forbidden capability");
    require(text.find("WorkspaceApi") != std::string::npos && text.find("read_bytes") != std::string::npos &&
        text.find("list_functions") != std::string::npos, "approved workspace API is incomplete");
}

void verify_manifest_contract() {
    python_worker_manifest_t manifest;
    manifest.schema_version = k_python_worker_manifest_schema_version;
    manifest.worker_relative_path = "deps/AiDA_AnalysisPythonWorker.exe";
    manifest.worker_binary_hash.bytes[0] = 1;
    manifest.protocol_hash = worker_wire::protocol_hash();
    manifest.capabilities = k_python_worker_capability_execute_file;
    require(k_python_worker_binary_artifact_relative_path == "deps/AiDA_AnalysisPythonWorker.exe" &&
        k_python_worker_manifest_artifact_relative_path == "deps/AiDA_AnalysisPythonWorker.manifest.bin" &&
        k_python_worker_manifest_digest_relative_path == "deps/AiDA_AnalysisPythonWorker.manifest.sha256",
        "analysis Python worker package paths changed");
    const std::string encoded = serialize_python_worker_manifest(manifest);
    const auto decoded = deserialize_python_worker_manifest(encoded);
    require(decoded.valid() && decoded.value && decoded.value->worker_relative_path == manifest.worker_relative_path &&
        decoded.value->worker_binary_hash == manifest.worker_binary_hash, "worker manifest round trip failed");
    std::string corrupt = encoded;
    corrupt.back() ^= 0x40;
    require(!deserialize_python_worker_manifest(corrupt).valid(), "corrupt worker manifest was accepted");
    require(!deserialize_python_worker_manifest(encoded.substr(0, encoded.size() - 1U)).valid(),
        "truncated worker manifest was accepted");
    require(!deserialize_python_worker_manifest(encoded + std::string(1, '\0')).valid(),
        "worker manifest with trailing material was accepted");
    auto invalid_manifest = manifest;
    invalid_manifest.worker_relative_path = "deps/../AiDA_AnalysisPythonWorker.exe";
    require(serialize_python_worker_manifest(invalid_manifest).empty(),
        "worker manifest path traversal was accepted");
    invalid_manifest = manifest;
    invalid_manifest.protocol_hash.bytes[0] ^= 1U;
    require(serialize_python_worker_manifest(invalid_manifest).empty(),
        "worker manifest protocol mismatch was accepted");
    invalid_manifest = manifest;
    invalid_manifest.capabilities |= 2U;
    require(serialize_python_worker_manifest(invalid_manifest).empty(),
        "worker manifest capability expansion was accepted");
    require(python_workspace_operation_allowed("metadata") && python_workspace_operation_allowed("read_bytes") &&
        python_workspace_operation_allowed("find") && python_workspace_operation_allowed("list_functions"),
        "approved workspace operation is rejected");
    for (const std::string_view rejected : {"write_bytes", "write_memory", "execute", "spawn", "network"})
        require(!python_workspace_operation_allowed(rejected), "unapproved workspace operation was accepted");
    require(python_worker_requires_replacement(python_worker_status_t::cancelled) &&
        python_worker_requires_replacement(python_worker_status_t::deadline_exceeded) &&
        python_worker_requires_replacement(python_worker_status_t::protocol_failure) &&
        !python_worker_requires_replacement(python_worker_status_t::completed),
        "worker replacement policy changed");
}

struct package_fixture_t final {
    std::filesystem::path root;
    std::filesystem::path scripts;
    python_worker_launch_contract_t contract;
    std::string manifest_bytes;

    explicit package_fixture_t(const std::filesystem::path& fake_worker) : root(unique_temp_directory()), scripts(root / "scripts") {
        std::filesystem::create_directories(root / "deps");
        std::filesystem::create_directories(scripts);
        const auto worker = root / "deps/AiDA_AnalysisPythonWorker.exe";
        std::filesystem::copy_file(fake_worker, worker, std::filesystem::copy_options::overwrite_existing);
        const auto bytes = read_binary_file(worker, k_fixture_worker_max_bytes,
            "fake worker fixture cannot be read completely");
        require(!bytes.empty(), "fake worker fixture is empty");
        python_worker_manifest_t manifest;
        manifest.schema_version = k_python_worker_manifest_schema_version;
        manifest.worker_relative_path = "deps/AiDA_AnalysisPythonWorker.exe";
        require(worker_wire::sha256(bytes.data(), bytes.size(), manifest.worker_binary_hash), "fake worker hash failed");
        manifest.protocol_hash = worker_wire::protocol_hash();
        manifest.capabilities = k_python_worker_capability_execute_file;
        manifest_bytes = serialize_python_worker_manifest(manifest);
        write_manifest(manifest_bytes);
        worker_wire::digest_t manifest_hash;
        require(worker_wire::sha256(manifest_bytes.data(), manifest_bytes.size(), manifest_hash),
            "fake manifest hash failed");
        write_digest(manifest_hash.to_hex() + "\n");
        const auto resolved_contract = resolve();
        require(resolved_contract.valid() && resolved_contract.value,
            "production worker launch contract cannot be resolved from the fixture package");
        contract = *resolved_contract.value;
    }

    ~package_fixture_t() {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }

    std::filesystem::path script(std::string_view name, std::string_view contents) const {
        const auto path = scripts / std::string(name);
        write_binary_file(path, contents, "fixture script cannot be written");
        return path;
    }

    std::filesystem::path manifest_path() const {
        return root / "deps/AiDA_AnalysisPythonWorker.manifest.bin";
    }

    std::filesystem::path digest_path() const {
        return root / "deps/AiDA_AnalysisPythonWorker.manifest.sha256";
    }

    void write_manifest(std::string_view contents) const {
        write_binary_file(manifest_path(), contents, "fake worker manifest cannot be written");
    }

    void write_digest(std::string_view contents) const {
        write_binary_file(digest_path(), contents, "fake worker manifest digest cannot be written");
    }

    python_worker_launch_contract_resolution_t resolve() const {
        return resolve_python_worker_launch_contract(root, scripts);
    }
};

python_worker_execution_request_t request_for(std::uint64_t job_id, const std::filesystem::path& script,
                                              const std::atomic<bool>* cancellation = nullptr) {
    python_worker_execution_request_t request;
    request.job_id = job_id;
    request.script_path = script;
    request.workspace_metadata = {{"name", "fixture"}, {"revision", 7}};
    request.unsafe_approved = true;
    request.cancellation = cancellation;
    return request;
}

bool has_diagnostic(const python_worker_execution_result_t& result,
                    python_worker_error_code_t code, std::uint32_t win32_error = ERROR_SUCCESS) {
    return std::any_of(result.diagnostics.begin(), result.diagnostics.end(),
        [code, win32_error](const auto& diagnostic) {
            return diagnostic.code == code &&
                (win32_error == ERROR_SUCCESS || diagnostic.win32_error == win32_error);
        });
}

void verify_package_contract_rejections(const std::filesystem::path& fake_worker) {
    package_fixture_t fixture(fake_worker);
    const std::string valid_digest = fixture.contract.expected_manifest_hash.to_hex() + "\n";

    fixture.write_digest(valid_digest.substr(0, 63));
    require(!fixture.resolve().valid(), "truncated worker manifest digest was accepted");
    fixture.write_digest(std::string(64, 'g'));
    require(!fixture.resolve().valid(), "non-hex worker manifest digest was accepted");
    fixture.write_digest(std::string(257, '0'));
    require(!fixture.resolve().valid(), "oversized worker manifest digest was accepted");
    std::error_code ec;
    require(std::filesystem::remove(fixture.digest_path(), ec) && !ec,
        "worker manifest digest cannot be removed for the unavailable-file case");
    require(!fixture.resolve().valid(), "missing worker manifest digest was accepted");
    fixture.write_digest(valid_digest);
    require(fixture.resolve().valid(), "valid worker manifest digest was not recoverable");

    const auto script = fixture.script("manifest_rejection.py", "fixture:success\n");
    std::uint64_t job_id = 1;
    const auto execute_material = [&](std::string_view material) {
        worker_wire::digest_t hash;
        require(worker_wire::sha256(material.data(), material.size(), hash),
            "fixture manifest material cannot be hashed");
        fixture.write_manifest(material);
        fixture.write_digest(hash.to_hex() + "\n");
        const auto resolved = fixture.resolve();
        require(resolved.valid() && resolved.value,
            "fixture manifest contract cannot be resolved through production code");
        python_worker_host_t host(*resolved.value);
        return host.execute(request_for(job_id++, script));
    };

    std::string truncated_manifest = fixture.manifest_bytes;
    truncated_manifest.pop_back();
    const auto truncated_result = execute_material(truncated_manifest);
    require(truncated_result.error_code == "PYTHON_WORKER_MANIFEST_REJECTED" &&
        has_diagnostic(truncated_result, python_worker_error_code_t::manifest_malformed),
        "truncated production worker manifest was accepted");

    std::string malformed_manifest = fixture.manifest_bytes;
    malformed_manifest.back() ^= 0x40;
    const auto malformed_result = execute_material(malformed_manifest);
    require(malformed_result.error_code == "PYTHON_WORKER_MANIFEST_REJECTED" &&
        has_diagnostic(malformed_result, python_worker_error_code_t::manifest_malformed),
        "malformed production worker manifest was accepted");

    const std::string oversized_manifest(64U * 1024U + 1U, '\0');
    const auto oversized_result = execute_material(oversized_manifest);
    require(oversized_result.error_code == "PYTHON_WORKER_MANIFEST_REJECTED" &&
        has_diagnostic(oversized_result, python_worker_error_code_t::manifest_unavailable,
            ERROR_FILE_TOO_LARGE),
        "oversized production worker manifest was accepted");

    fixture.write_manifest(fixture.manifest_bytes + std::string(1, '\0'));
    fixture.write_digest(valid_digest);
    const auto mismatched_contract = fixture.resolve();
    require(mismatched_contract.valid() && mismatched_contract.value,
        "hash-mismatch fixture contract cannot be resolved through production code");
    python_worker_host_t mismatch_host(*mismatched_contract.value);
    const auto mismatch_result = mismatch_host.execute(request_for(job_id, script));
    require(mismatch_result.error_code == "PYTHON_WORKER_MANIFEST_REJECTED" &&
        has_diagnostic(mismatch_result, python_worker_error_code_t::manifest_hash_mismatch),
        "production worker manifest hash mismatch was accepted");
}

void verify_runtime_contract(const std::filesystem::path& fake_worker) {
    package_fixture_t fixture(fake_worker);
    python_worker_host_t host(fixture.contract);
    auto unapproved = request_for(1, fixture.script("unapproved.py", "fixture:success\n"));
    unapproved.unsafe_approved = false;
    const auto denied = host.execute(unapproved);
    require(denied.status == python_worker_status_t::rejected &&
        denied.error_code == "PYTHON_WORKER_UNSAFE_APPROVAL_REQUIRED", "unsafe execution approval was not enforced");
    const auto success = host.execute(request_for(1, fixture.script("success.py", "fixture:success\n")));
    require(success.completed() && success.stdout_text == "fixture output\n" && success.worker_generation == 1,
        "frozen worker success fixture failed");
    const auto workspace = host.execute(request_for(2, fixture.script("workspace.py", "fixture:workspace\n")));
    require(workspace.completed() && workspace.worker_generation == 2,
        "approved workspace API fixture failed");
    const auto containment = host.execute(request_for(3, fixture.script("containment.py", "fixture:containment\n")));
    require(containment.completed(), "network, child, or handle containment fixture failed");
    const auto outside = fixture.root / "outside.py";
    {
        std::ofstream output(outside, std::ios::binary | std::ios::trunc);
        output << "fixture:success\n";
    }
    const auto path_rejected = host.execute(request_for(4, outside));
    require(path_rejected.status == python_worker_status_t::rejected &&
        path_rejected.error_code == "PYTHON_WORKER_SCRIPT_REJECTED", "script path escaped the approved root");
    python_worker_limits_t size_limits;
    size_limits.max_script_bytes = 4;
    python_worker_host_t size_host(fixture.contract, size_limits);
    const auto oversized = size_host.execute(request_for(5, fixture.script("oversized.py", "fixture:success\n")));
    require(oversized.status == python_worker_status_t::rejected && oversized.error_code == "PYTHON_WORKER_SCRIPT_REJECTED",
        "script size limit was not enforced");
    python_worker_limits_t output_limits;
    output_limits.max_output_bytes = 16;
    python_worker_host_t output_host(fixture.contract, output_limits);
    const auto output_rejected = output_host.execute(request_for(6, fixture.script("output.py", "fixture:output\n")));
    require(output_rejected.status == python_worker_status_t::protocol_failure &&
        output_rejected.error_code == "PYTHON_WORKER_OUTPUT_LIMIT_EXCEEDED", "worker output limit was not enforced");
    const auto replay = host.execute(request_for(4, fixture.script("replay.py", "fixture:replay\n")));
    require(replay.status == python_worker_status_t::protocol_failure && replay.worker_replaced,
        "replayed authenticated sequence was accepted");
    std::atomic<bool> cancelled{false};
    const auto cancellation_script = fixture.script("cancel.py", "fixture:cancel\n");
    auto pending = std::async(std::launch::async, [&] { return host.execute(request_for(5, cancellation_script, &cancelled)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    cancelled.store(true, std::memory_order_release);
    const auto cancelled_result = pending.get();
    require(cancelled_result.status == python_worker_status_t::cancelled && cancelled_result.worker_replaced,
        "cancellation did not replace the active worker");
    python_worker_limits_t deadline_limits;
    deadline_limits.max_wall_clock = std::chrono::milliseconds(100);
    deadline_limits.cancellation_grace = std::chrono::milliseconds(50);
    python_worker_host_t deadline_host(fixture.contract, deadline_limits);
    const auto deadline = deadline_host.execute(request_for(6, fixture.script("hang.py", "fixture:hang\n")));
    require(deadline.status == python_worker_status_t::deadline_exceeded && deadline.worker_replaced,
        "deadline did not replace the unresponsive worker");
}

}

bool run_python_worker_harness(std::string& failure, const std::filesystem::path& fake_worker_path) {
    try {
        if (fake_worker_path.empty()) {
            failure = "python worker harness requires a fake-worker path";
            return false;
        }
        std::error_code ec;
        if (!std::filesystem::is_regular_file(fake_worker_path, ec) || ec) {
            failure = "python worker harness fake-worker path is not a regular file";
            return false;
        }
        verify_source_contract();
        verify_manifest_contract();
        verify_package_contract_rejections(fake_worker_path);
        verify_runtime_contract(fake_worker_path);
    } catch (const std::exception& error) {
        failure.assign(error.what());
        return false;
    }
    failure.clear();
    return true;
}

}
