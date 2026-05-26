#include <cstdint>

namespace {

constexpr std::uint32_t kProtocolMagic = 0x41444941u;

enum class protocol_message_kind : std::uint32_t {
    handshake = 1,
    data = 2,
    close = 3,
    fault = 4
};

struct protocol_frame_header {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t header_size;
    std::uint32_t payload_size;
    protocol_message_kind kind;
    std::uint64_t sequence;
};

struct protocol_auth_context {
    std::uint8_t nonce[16];
    std::uint8_t tag[16];
    std::uint32_t flags;
};

struct protocol_session_state {
    protocol_frame_header last_frame;
    protocol_auth_context auth;
    std::uint64_t accepted_frames;
    std::uint64_t rejected_frames;
};

struct protocol_dispatch_record {
    protocol_message_kind kind;
    std::uint32_t handler_id;
    std::uint32_t minimum_size;
    std::uint32_t maximum_size;
};

constexpr protocol_dispatch_record kProtocolDispatchTable[] = {
    {protocol_message_kind::handshake, 0x1001u, 0u, 128u},
    {protocol_message_kind::data, 0x1002u, 1u, 4096u},
    {protocol_message_kind::close, 0x1003u, 0u, 64u},
    {protocol_message_kind::fault, 0x1004u, 0u, 256u}
};

volatile std::uint64_t g_protocol_sink = 0;

bool protocol_kind_supported(protocol_message_kind kind) noexcept
{
    for (const auto& record : kProtocolDispatchTable) {
        if (record.kind == kind) {
            return true;
        }
    }
    return false;
}

std::uint32_t protocol_handler_id(protocol_message_kind kind) noexcept
{
    for (const auto& record : kProtocolDispatchTable) {
        if (record.kind == kind) {
            return record.handler_id;
        }
    }
    return 0u;
}

}

extern "C" __declspec(noinline) std::uint32_t vuln_protocol_checksum(const std::uint8_t* data, std::uint32_t size) noexcept
{
    if (data == nullptr) {
        return 0u;
    }

    std::uint32_t hash = 2166136261u;
    for (std::uint32_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

extern "C" __declspec(noinline) bool vuln_protocol_validate_header(const protocol_frame_header* header) noexcept
{
    if (header == nullptr) {
        return false;
    }

    if (header->magic != kProtocolMagic) {
        return false;
    }

    if (header->version != 1u || header->header_size < static_cast<std::uint32_t>(sizeof(protocol_frame_header))) {
        return false;
    }

    if (header->payload_size > 4096u) {
        return false;
    }

    return protocol_kind_supported(header->kind);
}

extern "C" __declspec(noinline) std::uint32_t vuln_protocol_dispatch(const protocol_frame_header* header, protocol_session_state* session) noexcept
{
    if (!vuln_protocol_validate_header(header)) {
        if (session != nullptr) {
            ++session->rejected_frames;
        }
        return 0u;
    }

    if (session != nullptr) {
        session->last_frame = *header;
        ++session->accepted_frames;
    }

    return protocol_handler_id(header->kind);
}

int main()
{
    protocol_frame_header header{};
    header.magic = kProtocolMagic;
    header.version = 1u;
    header.header_size = static_cast<std::uint32_t>(sizeof(protocol_frame_header));
    header.payload_size = 8u;
    header.kind = protocol_message_kind::data;
    header.sequence = 7u;

    protocol_session_state session{};
    const std::uint8_t payload[] = {0x41u, 0x69u, 0x44u, 0x41u, 0x10u, 0x20u, 0x30u, 0x40u};

    const std::uint32_t checksum = vuln_protocol_checksum(payload, static_cast<std::uint32_t>(sizeof(payload)));
    const std::uint32_t handler_id = vuln_protocol_dispatch(&header, &session);
    g_protocol_sink = static_cast<std::uint64_t>(checksum) ^ handler_id ^ session.accepted_frames;

    return g_protocol_sink == 0ull ? 1 : 0;
}
