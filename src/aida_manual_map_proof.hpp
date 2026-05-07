#pragma once

#include <cstdint>

namespace aida_manual_map
{
    constexpr uint64_t kMarkerValue       = 0xA1DA0143A1DA0143ULL;
    constexpr uint64_t kProofMagic        = 0xA1DAB001A1DAB001ULL;
    constexpr uint32_t kProofVersion      = 2u;
    constexpr uint32_t kProofBufferLen    = 256u;
    constexpr uint32_t kPipeSecretLen     = 32u;
    constexpr uint32_t kAiSessionKeyLen   = 32u;
    constexpr uint32_t kProofPlanLen      = 32u;
    constexpr uint32_t kForbiddenHashLen  = 32u;

    constexpr uint32_t kProofMagicValid   = 0x55554E4Fu;
    constexpr uint32_t kProofMagicCleared = 0x00000000u;

    struct alignas(16) proof_buffer_t
    {
        uint64_t magic;
        uint32_t version;
        uint32_t flags;
        uint64_t parent_pid;
        uint64_t ida_pid;
        uint64_t timestamp_unix;
        uint64_t feature_epoch;
        uint64_t runtime_nonce_seed;
        uint64_t plan_id_hash;
        uint8_t  pipe_secret[kPipeSecretLen];
        uint8_t  ai_session_key[kAiSessionKeyLen];
        char     plan[kProofPlanLen];
        uint8_t  forbidden_hash_standalone[kForbiddenHashLen];
        uint8_t  forbidden_hash_plugin[kForbiddenHashLen];
        uint8_t  forbidden_hash_arc[kForbiddenHashLen];
    };

    static_assert(sizeof(proof_buffer_t) == kProofBufferLen,
                  "proof_buffer_t must occupy exactly kProofBufferLen bytes");

    constexpr const wchar_t* kPipePrefix = L"\\\\.\\pipe\\aida_ida_";

    enum verb_t : uint32_t
    {
        verb_hello     = 0x4F4C4548u,
        verb_hello_ack = 0x4B41454Fu,
        verb_status    = 0x54415453u,
        verb_heartbeat = 0x54424548u,
        verb_kill      = 0x4C4C494Bu,
        verb_bye       = 0x21455942u,
    };

    constexpr uint32_t kFrameMaxPayload = 4096u;

    struct frame_header_t
    {
        uint32_t verb;
        uint32_t payload_len;
    };
}
