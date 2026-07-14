#include "python_worker_protocol.hpp"
#include "../../src/standalone/tests/c03/assertion_telemetry/assertion_telemetry.hpp"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

int main()
{
    using namespace aida::standalone::mcp::python_worker::wire;
	const auto check = [](bool condition, std::string_view message) {
		aida::analysis::c03_test::assertion_telemetry::record_assertion(
			condition, message, __FILE__, __LINE__);
		return condition;
	};
    session_material_t session;
    if (!check(make_session(session) && !session.nonce_hash.empty(),
		"analysis Python session material creation"))
        return 1;
    digest_t manifest;
    const std::string manifest_material = "aida-c03-analysis-python-protocol-selftest";
    if (!check(sha256(manifest_material.data(), manifest_material.size(), manifest),
		"analysis Python manifest digest"))
        return 1;
    const auto bootstrap = encode_bootstrap(session, manifest);
    session_material_t decoded_session;
    digest_t decoded_manifest;
    if (!check(decode_bootstrap(bootstrap.data(), bootstrap.size(), decoded_session, decoded_manifest) &&
        decoded_session.nonce == session.nonce && decoded_session.key == session.key &&
		decoded_session.nonce_hash == session.nonce_hash && decoded_manifest == manifest,
		"analysis Python bootstrap round trip"))
        return 1;
    auto malformed = bootstrap;
    malformed[0] ^= 0x80U;
    if (!check(!decode_bootstrap(malformed.data(), malformed.size(), decoded_session, decoded_manifest),
		"analysis Python malformed bootstrap rejection"))
        return 1;
    HANDLE read_handle = nullptr;
    HANDLE write_handle = nullptr;
    if (!check(CreatePipe(&read_handle, &write_handle, nullptr, 0) != FALSE,
		"analysis Python protocol pipe creation"))
        return 1;
    const auto close_handles = [&]() {
        CloseHandle(read_handle);
        CloseHandle(write_handle);
    };
    const std::array<std::uint8_t, 7> payload{{1U, 3U, 5U, 7U, 11U, 13U, 17U}};
    DWORD error = ERROR_SUCCESS;
    if (!check(send_frame(write_handle, session, frame_kind_t::control, 1U,
            payload.data(), payload.size(), 4096U, error), "analysis Python authenticated frame send")) {
        close_handles();
        return 1;
    }
    frame_reader_t reader;
    frame_t frame;
    const auto state = reader.poll(read_handle, session, 1U, 4096U, frame, error);
    close_handles();
    if (!check(state == read_state_t::complete && frame.sequence == 1U && frame.payload ==
        std::vector<std::uint8_t>(payload.begin(), payload.end()),
		"analysis Python authenticated frame receive"))
        return 1;
    if (!check(reader.poll(INVALID_HANDLE_VALUE, session, 1U, 4096U, frame, error) == read_state_t::failure,
		"analysis Python invalid handle rejection"))
        return 1;
    std::cout << "analysis Python authenticated protocol selftest passed\n";
    return 0;
}
