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
    recovery,
    approval_pending,
    approval_approved,
    approval_rejected,
    editor_proposal_review,
    editor_proposal_apply_ready,
    editor_proposal_rejected,
    editor_proposal_stale,
    editor_proposal_error,
    reverse_proposal_review,
    reverse_proposal_apply_ready,
    reverse_proposal_rejected,
    reverse_proposal_stale,
    reverse_proposal_error,
    save_failure,
    external_conflict,
    document_groups,
    size_editable_boundary,
    size_mapped_read_only,
    size_stream_loading,
    size_stream_cancelling,
    size_stream_error,
    size_stream_ready,
    size_rejected,
    fuzzer_empty,
    fuzzer_ready,
    fuzzer_loading,
    fuzzer_running,
    fuzzer_cancelling,
    fuzzer_cancelled,
    fuzzer_error,
    fuzzer_completed,
    analysis_mutation_current,
    analysis_mutation_stale_stop,
    analysis_mutation_pid_reuse
};

void configure_debugger_fixture(fixture_state_t state, std::size_t cardinality);
void configure_network_fixture(fixture_state_t fixture, std::size_t cardinality);
void configure_network_fuzzer_fixture(fixture_state_t fixture, std::size_t cardinality);
void configure_chat_fixture(fixture_state_t state, std::size_t cardinality);
void configure_programming_fixture(fixture_state_t state, std::size_t cardinality);
void configure_analysis_mutation_fixture(fixture_state_t state);
void advance_chat_fixture();

}

#endif
