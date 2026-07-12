#include <winsock2.h>
#include <aclapi.h>

#include "native_worker_runtime.hpp"

#include <array>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

using namespace aida::analysis;
using namespace aida::analysis::native_worker;

std::wstring fixture_name(int argc, wchar_t** argv)
{
    constexpr std::wstring_view prefix = L"--fixture=";
    for (int index = 1; index < argc; ++index) {
        const std::wstring_view argument(argv[index] ? argv[index] : L"");
        if (argument.substr(0, prefix.size()) == prefix)
            return std::wstring(argument.substr(prefix.size()));
    }
    return L"failure";
}

bool send_heartbeat(runtime::startup_t& startup, std::uint64_t job_id)
{
    decompiler_worker_heartbeat_t heartbeat;
    heartbeat.envelope.kind = decompiler_worker_message_kind_t::heartbeat;
    heartbeat.envelope.session_nonce_hash = startup.session.nonce_hash;
    heartbeat.envelope.sequence = startup.next_worker_sequence;
    heartbeat.active_job_id = job_id;
    return runtime::send_message(startup, decompiler_worker_message_t{std::move(heartbeat)}, 8U * 1024U * 1024U);
}

bool write_raw_frame(HANDLE handle, const wire::session_material_t& session, std::uint64_t sequence,
                     std::uint32_t declared_payload_size, const std::uint8_t* authenticated_payload,
                     std::size_t authenticated_payload_size, std::size_t written_payload_size)
{
    std::array<std::uint8_t, wire::k_frame_header_bytes> header{};
    wire::write_u32(header.data(), wire::k_frame_magic);
    wire::write_u16(header.data() + 4, wire::k_frame_version);
    wire::write_u16(header.data() + 6, static_cast<std::uint16_t>(wire::frame_kind_t::decompiler_contract));
    wire::write_u64(header.data() + 8, sequence);
    wire::write_u32(header.data() + 16, declared_payload_size);
    std::memcpy(header.data() + 20, session.nonce_hash.bytes.data(), session.nonce_hash.bytes.size());
    std::vector<std::uint8_t> material;
    try {
        material.insert(material.end(), header.begin(), header.begin() + static_cast<std::ptrdiff_t>(wire::k_frame_header_without_tag_bytes));
        material.insert(material.end(), authenticated_payload, authenticated_payload + authenticated_payload_size);
    } catch (...) {
        return false;
    }
    std::array<std::uint8_t, wire::k_digest_bytes> tag{};
    if (!wire::hmac_sha256(session.key.data(), session.key.size(), material.data(), material.size(), tag))
        return false;
    std::memcpy(header.data() + wire::k_frame_header_without_tag_bytes, tag.data(), tag.size());
    DWORD error = ERROR_SUCCESS;
    const bool header_written = wire::write_all(handle, header.data(), header.size(), error);
    const bool payload_written = header_written && (written_payload_size == 0 ||
        wire::write_all(handle, authenticated_payload, written_payload_size, error));
    SecureZeroMemory(material.data(), material.size());
    SecureZeroMemory(tag.data(), tag.size());
    return payload_written;
}

bool write_rejected_header(HANDLE handle, const wire::session_material_t& session, std::uint64_t sequence,
                           bool malformed, bool nonce_mismatch)
{
    std::array<std::uint8_t, wire::k_frame_header_bytes> header{};
    wire::write_u32(header.data(), malformed ? wire::k_frame_magic ^ 0x80000000U : wire::k_frame_magic);
    wire::write_u16(header.data() + 4, wire::k_frame_version);
    wire::write_u16(header.data() + 6, static_cast<std::uint16_t>(wire::frame_kind_t::decompiler_contract));
    wire::write_u64(header.data() + 8, sequence);
    std::memcpy(header.data() + 20, session.nonce_hash.bytes.data(), session.nonce_hash.bytes.size());
    if (nonce_mismatch)
        header[20] ^= 0x80U;
    DWORD error = ERROR_SUCCESS;
    return wire::write_all(handle, header.data(), header.size(), error);
}

bool network_denied()
{
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        return true;
    SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET) {
        const int error = WSAGetLastError();
        WSACleanup();
        return error == WSAEACCES;
    }
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(9);
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const int connected = connect(socket_handle, reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    const int error = connected == 0 ? ERROR_SUCCESS : WSAGetLastError();
    closesocket(socket_handle);
    WSACleanup();
    return error == WSAEACCES;
}

bool child_creation_denied()
{
    std::array<wchar_t, 32768> path{};
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size())
        return true;
    std::wstring command = L"\"";
    command.append(path.data(), length);
    command.append(L"\" --fixture=child_probe");
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(path.data(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &process);
    if (!created)
        return GetLastError() == ERROR_ACCESS_DENIED;
    CloseHandle(process.hThread);
    TerminateProcess(process.hProcess, ERROR_CANCELLED);
    CloseHandle(process.hProcess);
    return false;
}

bool query_token_information(HANDLE token, TOKEN_INFORMATION_CLASS information_class, std::vector<std::uint8_t>& output)
{
    DWORD required = 0;
    if (GetTokenInformation(token, information_class, nullptr, 0, &required) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0)
        return false;
    try {
        output.resize(required);
    } catch (...) {
        return false;
    }
    return GetTokenInformation(token, information_class, output.data(), required, &required) != FALSE;
}

bool restricted_pipe_acl(HANDLE pipe)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    std::vector<std::uint8_t> user_bytes;
    std::vector<std::uint8_t> container_bytes;
    const bool queried = query_token_information(token, TokenUser, user_bytes) &&
        query_token_information(token, TokenAppContainerSid, container_bytes);
    CloseHandle(token);
    if (!queried)
        return false;
    const auto* user = reinterpret_cast<const TOKEN_USER*>(user_bytes.data());
    const auto* container = reinterpret_cast<const TOKEN_APPCONTAINER_INFORMATION*>(container_bytes.data());
    if (!user->User.Sid || !container->TokenAppContainer || !IsValidSid(user->User.Sid) ||
        !IsValidSid(container->TokenAppContainer))
        return false;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD status = GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor);
    if (status != ERROR_SUCCESS || !descriptor || !owner || !dacl) {
        if (descriptor)
            LocalFree(descriptor);
        return false;
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    ACL_SIZE_INFORMATION information{};
    constexpr DWORD expected_access = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | READ_CONTROL;
    bool user_ace = false;
    bool container_ace = false;
    bool valid = EqualSid(owner, user->User.Sid) &&
        GetSecurityDescriptorControl(descriptor, &control, &revision) != FALSE &&
        (control & SE_DACL_PROTECTED) != 0 &&
        GetAclInformation(dacl, &information, sizeof(information), AclSizeInformation) != FALSE &&
        information.AceCount == 2;
    for (DWORD index = 0; valid && index < information.AceCount; ++index) {
        void* raw_ace = nullptr;
        if (!GetAce(dacl, index, &raw_ace) || !raw_ace) {
            valid = false;
            break;
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != 0 || ace->Mask != expected_access) {
            valid = false;
            break;
        }
        PSID sid = const_cast<DWORD*>(&ace->SidStart);
        if (EqualSid(sid, user->User.Sid) && !user_ace)
            user_ace = true;
        else if (EqualSid(sid, container->TokenAppContainer) && !container_ace)
            container_ace = true;
        else
            valid = false;
    }
    LocalFree(descriptor);
    return valid && user_ace && container_ace;
}

bool only_declared_handles(const runtime::startup_t& startup)
{
    DWORD flags = 0;
    const bool read = GetHandleInformation(startup.read_handle, &flags) != FALSE;
    const bool write = GetHandleInformation(startup.write_handle, &flags) != FALSE;
    const bool snapshot = GetHandleInformation(startup.snapshot_handle, &flags) != FALSE;
    const bool identity = GetHandleInformation(startup.identity_handle, &flags) != FALSE;
    const HANDLE standard_input = GetStdHandle(STD_INPUT_HANDLE);
    const HANDLE standard_output = GetStdHandle(STD_OUTPUT_HANDLE);
    const HANDLE standard_error = GetStdHandle(STD_ERROR_HANDLE);
    const auto inaccessible = [](HANDLE value) {
        DWORD local_flags = 0;
        return !value || value == INVALID_HANDLE_VALUE || GetHandleInformation(value, &local_flags) == FALSE;
    };
    DWORD handle_count = 0;
    return read && write && snapshot && identity && restricted_pipe_acl(startup.read_handle) && restricted_pipe_acl(startup.write_handle) &&
        inaccessible(standard_input) && inaccessible(standard_output) && inaccessible(standard_error) &&
        GetProcessHandleCount(GetCurrentProcess(), &handle_count) != FALSE && handle_count == 4;
}

}

int wmain(int argc, wchar_t** argv)
{
    runtime::startup_t startup;
    if (!runtime::parse_startup(argc, argv, startup) || !runtime::receive_bootstrap(startup))
        return 2;
    const std::wstring fixture = fixture_name(argc, argv);
    const auto provider = runtime::provider_identity(startup);
    if (provider.provider_binary_hash.empty())
        return 3;
    sha256_digest_t manifest_hash = startup.manifest_hash;
    if (fixture == L"hash_mismatch")
        manifest_hash.bytes[0] ^= 0x80U;
    if (!runtime::send_hello(startup, provider, manifest_hash))
        return 4;
    if (fixture == L"hash_mismatch")
        return 0;
    const auto job = runtime::receive_job(startup, std::chrono::seconds(30));
    if (!job)
        return 6;
    if (fixture == L"crash") {
        TerminateProcess(GetCurrentProcess(), ERROR_UNHANDLED_EXCEPTION);
        return 5;
    }
    if (fixture == L"hang") {
        for (;;)
            Sleep(1000);
    }
    if (!runtime::verify_snapshot(startup, *job)) {
        runtime::send_failure(startup, job->job_id, decompiler_diagnostic_code_t::worker_integrity_failure,
            "native_worker.fixture.snapshot_integrity");
        return 7;
    }
    if (fixture == L"replay") {
        if (!send_heartbeat(startup, job->job_id))
            return 8;
        --startup.next_worker_sequence;
        send_heartbeat(startup, job->job_id);
        return 0;
    }
    if (fixture == L"truncation") {
        const std::array<std::uint8_t, 64> payload{};
        return write_raw_frame(startup.write_handle, startup.session, startup.next_worker_sequence,
            static_cast<std::uint32_t>(payload.size()), payload.data(), payload.size(), 3) ? 0 : 10;
    }
    if (fixture == L"oversize") {
        const std::array<std::uint8_t, 1> payload{};
        write_raw_frame(startup.write_handle, startup.session, startup.next_worker_sequence, 64U * 1024U * 1024U,
            payload.data(), payload.size(), 0);
        return 0;
    }
    if (fixture == L"malformed_header")
        return write_rejected_header(startup.write_handle, startup.session, startup.next_worker_sequence, true, false) ? 0 : 11;
    if (fixture == L"nonce_mismatch")
        return write_rejected_header(startup.write_handle, startup.session, startup.next_worker_sequence, false, true) ? 0 : 12;
    if (fixture == L"cancel") {
        const auto cancelled = runtime::receive_cancel(startup, std::chrono::seconds(30));
        if (!cancelled || cancelled->job_id != job->job_id)
            return 9;
        runtime::send_failure(startup, job->job_id, decompiler_diagnostic_code_t::cancelled, "native_worker.fixture.cancelled", true);
        return 0;
    }
    if (fixture == L"replacement") {
        runtime::send_failure(startup, job->job_id, decompiler_diagnostic_code_t::provider_failure,
            "native_worker.fixture.replacement", true);
        return 0;
    }
    if (fixture == L"no_network") {
        runtime::send_failure(startup, job->job_id, decompiler_diagnostic_code_t::provider_failure,
            network_denied() ? "native_worker.fixture.network_denied" : "native_worker.fixture.network_violation");
        return 0;
    }
    if (fixture == L"child") {
        runtime::send_failure(startup, job->job_id, decompiler_diagnostic_code_t::provider_failure,
            child_creation_denied() ? "native_worker.fixture.child_denied" : "native_worker.fixture.child_violation");
        return 0;
    }
    if (fixture == L"handles") {
        runtime::send_failure(startup, job->job_id, decompiler_diagnostic_code_t::provider_failure,
            only_declared_handles(startup) ? "native_worker.fixture.handle_capability_denied" : "native_worker.fixture.handle_capability_violation");
        return 0;
    }
    runtime::send_failure(startup, job->job_id, decompiler_diagnostic_code_t::provider_failure, "native_worker.fixture.failure");
    return 0;
}
