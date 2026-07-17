#pragma once

#include "standalone_chat.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ui/application_view_registry.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace aida::automation_ui::entity_evidence {

enum class destination_t : std::uint8_t {
    chat,
    review,
    agent
};

struct snapshot_t {
    std::string project_id;
    std::string workspace_id;
    std::string source_view_id;
    std::string source_kind;
    std::string entity_id;
    std::string display_label;
    std::string excerpt;
    std::uint64_t address = 0;
    std::uint64_t revision = 0;
    std::uint64_t generation = 0;
    std::uint64_t snapshot_hash = 0;
    bool sensitive = false;
    bool truncated = false;
    std::function<bool(std::string&)> return_to_source;
};

inline std::uint64_t hash_text(const std::string& value) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char character : value) {
        hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(character));
        hash *= 1099511628211ULL;
    }
    return hash == 0 ? 1 : hash;
}

inline std::string bounded_utf8(const std::string& input, std::size_t maximum,
                                bool& truncated) {
    std::string output;
    output.reserve((std::min)(input.size(), maximum));
    std::size_t offset = 0;
    while (offset < input.size() && output.size() < maximum) {
        const auto lead = static_cast<unsigned char>(input[offset]);
        if (lead < 0x80U) {
            output.push_back(lead < 0x20U && lead != '\n' && lead != '\t'
                ? ' ' : static_cast<char>(lead));
            ++offset;
            continue;
        }
        std::size_t width = lead >= 0xC2U && lead <= 0xDFU ? 2U
            : lead >= 0xE0U && lead <= 0xEFU ? 3U
            : lead >= 0xF0U && lead <= 0xF4U ? 4U : 0U;
        bool valid = width != 0 && offset + width <= input.size();
        for (std::size_t index = 1; valid && index < width; ++index) {
            const auto continuation = static_cast<unsigned char>(input[offset + index]);
            valid = continuation >= 0x80U && continuation <= 0xBFU;
        }
        if (valid && width == 3U) {
            const auto second = static_cast<unsigned char>(input[offset + 1U]);
            valid = (lead != 0xE0U || second >= 0xA0U) &&
                (lead != 0xEDU || second <= 0x9FU);
        }
        if (valid && width == 4U) {
            const auto second = static_cast<unsigned char>(input[offset + 1U]);
            valid = (lead != 0xF0U || second >= 0x90U) &&
                (lead != 0xF4U || second <= 0x8FU);
        }
        if (valid && output.size() + width <= maximum) {
            output.append(input, offset, width);
            offset += width;
            continue;
        }
        constexpr char replacement[] = "\xEF\xBF\xBD";
        if (output.size() + 3U > maximum)
            break;
        output.append(replacement, 3U);
        ++offset;
    }
    truncated = truncated || offset < input.size();
    return output;
}

inline ui::action_handler_result_t dispatch(snapshot_t snapshot,
                                             destination_t destination) {
    constexpr std::size_t k_maximum_excerpt = 12U * 1024U;
    bool identity_invalid = false;
    const auto normalize_identity = [&](std::string& value, std::size_t maximum) {
        bool truncated = false;
        auto bounded = bounded_utf8(value, maximum, truncated);
        identity_invalid = identity_invalid || truncated || bounded != value;
        value = std::move(bounded);
    };
    normalize_identity(snapshot.project_id, 256U);
    normalize_identity(snapshot.workspace_id, 256U);
    normalize_identity(snapshot.source_view_id, 256U);
    normalize_identity(snapshot.source_kind, 128U);
    normalize_identity(snapshot.entity_id, 512U);
    if (identity_invalid)
        return ui::action_handler_result_t::failed(
            "The retained evidence identity is invalid or exceeds the bounded metadata contract.");
    bool label_truncated = false;
    snapshot.display_label = bounded_utf8(snapshot.display_label, 512U,
        label_truncated);
    snapshot.truncated = snapshot.truncated || label_truncated;
    snapshot.excerpt = bounded_utf8(snapshot.excerpt, k_maximum_excerpt,
        snapshot.truncated);
    if (snapshot.source_view_id.empty() || snapshot.source_kind.empty() ||
        snapshot.entity_id.empty() || snapshot.excerpt.empty())
        return ui::action_handler_result_t::failed(
            "The retained entity has no complete bounded evidence snapshot.");
    const std::uint64_t content_hash = hash_text(snapshot.excerpt);
    if (snapshot.snapshot_hash == 0) {
        snapshot.snapshot_hash = hash_text(snapshot.project_id + ":" +
            snapshot.workspace_id + ":" + snapshot.source_view_id + ":" +
            snapshot.source_kind + ":" + snapshot.entity_id + ":" +
            std::to_string(snapshot.revision) + ":" +
            std::to_string(snapshot.generation));
    }
    evidence_envelope_t envelope;
    envelope.id = "evidence.entity." + std::to_string(snapshot.snapshot_hash) +
        "." + std::to_string(content_hash);
    envelope.project_id = std::move(snapshot.project_id);
    envelope.workspace_id = std::move(snapshot.workspace_id);
    envelope.source_view_id = std::move(snapshot.source_view_id);
    envelope.source_kind = std::move(snapshot.source_kind);
    envelope.entity_id = std::move(snapshot.entity_id);
    envelope.display_label = std::move(snapshot.display_label);
    envelope.return_target = envelope.source_view_id + ":entity-hash:" +
        std::to_string(hash_text(envelope.entity_id)) +
        ":revision:" + std::to_string(snapshot.revision) +
        ":generation:" + std::to_string(snapshot.generation);
    envelope.excerpt = std::move(snapshot.excerpt);
    envelope.address = snapshot.address;
    envelope.revision = snapshot.revision;
    envelope.generation = snapshot.generation;
    envelope.snapshot_hash = snapshot.snapshot_hash;
    envelope.content_hash = content_hash;
    envelope.truncated = snapshot.truncated;
    envelope.sensitive = snapshot.sensitive;
    const std::string evidence_id = register_evidence(std::move(envelope));
    if (evidence_id.empty())
        return ui::action_handler_result_t::failed(
            "The bounded evidence registry rejected the retained entity identity.");
    if (snapshot.return_to_source)
        register_evidence_source_return(evidence_id,
            std::move(snapshot.return_to_source));
    if (destination == destination_t::review) {
        const auto opened = ui::application_views::open_or_focus(
            ui::stable_view_id_t("view.ai.evidence"));
        return opened.ok() ? ui::action_handler_result_t::completed()
            : ui::action_handler_result_t::failed(opened.detail);
    }
    std::string reason;
    const bool queued = destination == destination_t::agent
        ? queue_evidence_for_agent(evidence_id, reason)
        : queue_evidence_for_chat(evidence_id, reason);
    return queued ? ui::action_handler_result_t::completed()
        : ui::action_handler_result_t::failed(reason.empty()
            ? "The retained evidence could not be queued." : reason);
}

inline void append_actions(ui::application_ui::retained_entity_context_t& context,
                           snapshot_t snapshot,
                           ui::capability_state_t capability =
                               ui::capability_state_t::available()) {
    const auto retained_snapshot = std::make_shared<const snapshot_t>(std::move(snapshot));
    const auto add = [&](const char* id, destination_t destination) {
        context.actions.push_back({id, capability, [retained_snapshot, destination] {
            return dispatch(*retained_snapshot, destination);
        }});
    };
    add("evidence.handoff.add_chat", destination_t::chat);
    add("evidence.handoff.add_review", destination_t::review);
    add("evidence.handoff.assign_agent", destination_t::agent);
}

}
