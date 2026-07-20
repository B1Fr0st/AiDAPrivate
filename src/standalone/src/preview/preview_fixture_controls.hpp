#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include <cstddef>
#include <cstdint>

namespace aida::preview {

enum class fixture_state_t : std::uint8_t {
    normal,
    empty,
    loading,
    error,
    disconnected,
    cancellation_requested,
    destructive_confirmation,
    recovery
};

void configure_debugger_fixture(fixture_state_t state, std::size_t cardinality);
void configure_network_fixture(fixture_state_t fixture, std::size_t cardinality);
void configure_chat_fixture(fixture_state_t state, std::size_t cardinality);
void configure_programming_fixture(fixture_state_t state, std::size_t cardinality);

}

#endif
