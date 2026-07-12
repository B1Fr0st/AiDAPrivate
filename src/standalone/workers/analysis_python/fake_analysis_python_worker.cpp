#include <winsock2.h>

#include "python_worker_protocol.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

using aida::standalone::mcp::python_worker::wire::digest_t;
using aida::standalone::mcp::python_worker::wire::frame_t;
using aida::standalone::mcp::python_worker::wire::frame_reader_t;
using aida::standalone::mcp::python_worker::wire::read_state_t;
using aida::standalone::mcp::python_worker::wire::session_material_t;
using json = nlohmann::json;

bool parse_handle(const wchar_t* argument, const wchar_t* prefix, HANDLE& output) {
    const std::wstring_view value(argument ? argument : L"");
    const std::wstring_view expected(prefix);
    if (value.rfind(expected, 0) != 0)
        return false;
    wchar_t* end = nullptr;
    const auto raw = _wcstoui64(value.data() + expected.size(), &end, 10);
    if (!end || *end != L'\0' || raw == 0)
        return false;
    output = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(raw));
    return true;
}

bool receive_bootstrap(HANDLE read_handle, session_material_t& session, digest_t& manifest_hash) {
    std::array<std::uint8_t, aida::standalone::mcp::python_worker::wire::k_bootstrap_bytes> bootstrap{};
    DWORD error = ERROR_SUCCESS;
    return aida::standalone::mcp::python_worker::wire::read_all(read_handle, bootstrap.data(), bootstrap.size(), error) &&
        aida::standalone::mcp::python_worker::wire::decode_bootstrap(bootstrap.data(), bootstrap.size(), session, manifest_hash);
}

bool send(HANDLE write_handle, const session_material_t& session, std::uint64_t& sequence, const json& value) {
    const std::string payload = value.dump();
    DWORD error = ERROR_SUCCESS;
    return aida::standalone::mcp::python_worker::wire::send_frame(write_handle, session,
        aida::standalone::mcp::python_worker::wire::frame_kind_t::control, sequence++,
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), 1024U * 1024U, error);
}

std::optional<json> receive(HANDLE read_handle, const session_material_t& session, std::uint64_t& sequence,
                            std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    frame_reader_t reader;
    while (std::chrono::steady_clock::now() < deadline) {
        frame_t frame;
        DWORD error = ERROR_SUCCESS;
        const auto state = reader.poll(read_handle, session, sequence, 1024U * 1024U, frame, error);
        if (state == read_state_t::failure)
            return std::nullopt;
        if (state == read_state_t::complete) {
            ++sequence;
            const auto value = json::parse(std::string(reinterpret_cast<const char*>(frame.payload.data()), frame.payload.size()), nullptr, false);
            if (value.is_discarded() || !value.is_object())
                return std::nullopt;
            return value;
        }
        Sleep(5);
    }
    return std::nullopt;
}

bool app_container_active() {
    HANDLE token = nullptr;
    DWORD value = 0;
    DWORD returned = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    const bool result = GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value), &returned) != FALSE &&
        returned == sizeof(value) && value != 0;
    CloseHandle(token);
    return result;
}

bool child_creation_denied() {
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY policy{};
    return GetProcessMitigationPolicy(GetCurrentProcess(), ProcessChildProcessPolicy, &policy, sizeof(policy)) != FALSE &&
        policy.NoChildProcessCreation != 0;
}

bool network_denied() {
    WSADATA data{};
    const int startup = WSAStartup(MAKEWORD(2, 2), &data);
    if (startup != 0)
        return startup == WSAEACCES;
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
    const int status = connect(socket_handle, reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    const int error = status == 0 ? ERROR_SUCCESS : WSAGetLastError();
    closesocket(socket_handle);
    WSACleanup();
    return error == WSAEACCES;
}

bool only_declared_handles(HANDLE read_handle, HANDLE write_handle) {
    DWORD flags = 0;
    const bool pipes = GetHandleInformation(read_handle, &flags) != FALSE &&
        GetHandleInformation(write_handle, &flags) != FALSE;
    const auto inaccessible = [](HANDLE handle) {
        DWORD local_flags = 0;
        return !handle || handle == INVALID_HANDLE_VALUE || GetHandleInformation(handle, &local_flags) == FALSE;
    };
    DWORD handle_count = 0;
    return pipes && inaccessible(GetStdHandle(STD_INPUT_HANDLE)) &&
        inaccessible(GetStdHandle(STD_OUTPUT_HANDLE)) && inaccessible(GetStdHandle(STD_ERROR_HANDLE)) &&
        GetProcessHandleCount(GetCurrentProcess(), &handle_count) != FALSE && handle_count == 2;
}

}

int wmain(int argc, wchar_t** argv) {
    HANDLE read_handle = nullptr;
    HANDLE write_handle = nullptr;
    bool marker = false;
    for (int index = 1; index < argc; ++index) {
        marker = marker || std::wstring_view(argv[index] ? argv[index] : L"") == L"--aida-analysis-python-worker";
        if (!parse_handle(argv[index], L"--read-handle=", read_handle))
            parse_handle(argv[index], L"--write-handle=", write_handle);
    }
    if (!marker || !read_handle || !write_handle)
        return 2;
    session_material_t session;
    digest_t manifest_hash;
    if (!receive_bootstrap(read_handle, session, manifest_hash))
        return 3;
    std::uint64_t send_sequence = 1;
    std::uint64_t receive_sequence = 1;
    if (!send(write_handle, session, send_sequence, json{{"type", "hello"}, {"worker", "analysis_python"}, {"manifest_hash", manifest_hash.to_hex()}}))
        return 4;
    const auto execution = receive(read_handle, session, receive_sequence, std::chrono::seconds(10));
    if (!execution || execution->value("type", std::string()) != "execute" || !execution->contains("job_id") ||
        !(*execution)["job_id"].is_number_unsigned() || !execution->contains("script") || !(*execution)["script"].is_string())
        return 5;
    const auto job_id = (*execution)["job_id"].get<std::uint64_t>();
    const std::string script = (*execution)["script"].get<std::string>();
    if (script.find("fixture:hang") != std::string::npos) {
        for (;;)
            Sleep(1000);
    }
    if (script.find("fixture:replay") != std::string::npos) {
        const std::string payload = json{{"type", "heartbeat"}, {"job_id", job_id}}.dump();
        DWORD error = ERROR_SUCCESS;
        if (!aida::standalone::mcp::python_worker::wire::send_frame(write_handle, session,
                aida::standalone::mcp::python_worker::wire::frame_kind_t::control, send_sequence,
                reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), 1024U * 1024U, error))
            return 6;
        return aida::standalone::mcp::python_worker::wire::send_frame(write_handle, session,
            aida::standalone::mcp::python_worker::wire::frame_kind_t::control, send_sequence,
            reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size(), 1024U * 1024U, error) ? 0 : 7;
    }
    if (script.find("fixture:cancel") != std::string::npos) {
        const auto cancellation = receive(read_handle, session, receive_sequence, std::chrono::seconds(10));
        if (!cancellation || cancellation->value("type", std::string()) != "cancel")
            return 8;
        return send(write_handle, session, send_sequence, json{{"type", "result"}, {"job_id", job_id},
            {"status", "cancelled"}, {"result", "cancelled"}, {"stdout", ""}, {"stderr", ""},
            {"error_code", "PYTHON_WORKER_CANCELLED"}}) ? 0 : 9;
    }
    if (script.find("fixture:workspace") != std::string::npos) {
        if (!send(write_handle, session, send_sequence, json{{"type", "workspace_request"}, {"request_id", 1},
                {"operation", "metadata"}, {"arguments", json::object()}}))
            return 10;
        const auto workspace = receive(read_handle, session, receive_sequence, std::chrono::seconds(10));
        if (!workspace || workspace->value("type", std::string()) != "workspace_response" ||
            workspace->value("success", false) != true)
            return 11;
    }
    if (script.find("fixture:containment") != std::string::npos) {
        const bool contained = app_container_active() && network_denied() && child_creation_denied() &&
            only_declared_handles(read_handle, write_handle);
        return send(write_handle, session, send_sequence, json{{"type", "result"}, {"job_id", job_id},
            {"status", contained ? "ok" : "error"}, {"result", contained ? "contained" : "containment failure"},
            {"stdout", ""}, {"stderr", ""}, {"error_code", contained ? "" : "PYTHON_WORKER_CONTAINMENT_FAILURE"}}) ? 0 : 12;
    }
    if (script.find("fixture:output") != std::string::npos) {
        return send(write_handle, session, send_sequence, json{{"type", "result"}, {"job_id", job_id},
            {"status", "ok"}, {"result", "ok"}, {"stdout", std::string(1024, 'x')}, {"stderr", ""}, {"error_code", ""}}) ? 0 : 13;
    }
    return send(write_handle, session, send_sequence, json{{"type", "result"}, {"job_id", job_id},
        {"status", "ok"}, {"result", "ok"}, {"stdout", "fixture output\n"}, {"stderr", ""}, {"error_code", ""}}) ? 0 : 14;
}
