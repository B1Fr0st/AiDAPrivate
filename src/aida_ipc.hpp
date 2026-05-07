#pragma once

#include <cstdint>

#include "aida_manual_map_proof.hpp"

namespace aida_ipc
{
    bool start_if_manual_mapped(const aida_manual_map::proof_buffer_t& proof);

    void shutdown();

    bool is_pipe_alive();
}
