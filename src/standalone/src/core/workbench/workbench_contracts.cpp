#include "workbench_contracts.h"

#include <algorithm>
#include <limits>
#include <unordered_set>
#include <utility>

namespace aida {
namespace workbench {
namespace {

constexpr std::uint64_t k_fnv_offset_basis = 14695981039346656037ULL;
constexpr std::uint64_t k_fnv_prime = 1099511628211ULL;

workbench_error_t error(workbench_error_code_t code, std::uint64_t subject = 0) noexcept
{
    return {code, subject};
}

bool valid_document_kind(document_kind_t kind) noexcept
{
    return kind >= document_kind_t::binary && kind <= document_kind_t::diff;
}

bool valid_view_role(view_role_t role) noexcept
{
    return role <= view_role_t::transient;
}

bool valid_selection_kind(selection_kind_t kind) noexcept
{
    return kind <= selection_kind_t::source;
}

bool valid_synchronization_policy(view_synchronization_policy_t policy) noexcept
{
    return policy <= view_synchronization_policy_t::cursor_and_selection;
}

bool synchronization_policy_matches(view_synchronization_policy_t policy,
                                    std::uint64_t group) noexcept
{
    if (!valid_synchronization_policy(policy))
        return false;
    return policy == view_synchronization_policy_t::independent ? group == 0 : group != 0;
}

bool valid_navigation_origin(navigation_origin_t origin) noexcept
{
    return origin <= navigation_origin_t::mcp;
}

bool valid_panel_kind(panel_kind_t kind) noexcept
{
    return kind <= panel_kind_t::custom;
}

bool navigation_event_equal(const navigation_event_t& lhs, const navigation_event_t& rhs)
{
    return lhs.id == rhs.id && lhs.workspace == rhs.workspace && lhs.has_source == rhs.has_source &&
           lhs.source.workspace == rhs.source.workspace && lhs.source.document == rhs.source.document &&
           lhs.source.view == rhs.source.view &&
           selection_context_equal(lhs.source.selection, rhs.source.selection) &&
           document_local_cursor_equal(lhs.source.cursor, rhs.source.cursor) &&
           lhs.source.synchronization_group == rhs.source.synchronization_group &&
           lhs.source.synchronization_policy == rhs.source.synchronization_policy &&
           document_identity_equal(lhs.target.document, rhs.target.document) &&
           selection_context_equal(lhs.target.selection, rhs.target.selection) &&
           document_local_cursor_equal(lhs.target.cursor, rhs.target.cursor) &&
           lhs.origin == rhs.origin && lhs.sequence == rhs.sequence &&
           lhs.request_focus == rhs.request_focus;
}

bool document_dto_equal(const document_persistence_dto_t& lhs,
                        const document_persistence_dto_t& rhs)
{
    return lhs.id == rhs.id && document_identity_equal(lhs.identity, rhs.identity) &&
           lhs.title == rhs.title && lhs.state_token == rhs.state_token &&
           document_local_state_equal(lhs.local_state, rhs.local_state) &&
           lhs.pinned == rhs.pinned && lhs.closeable == rhs.closeable;
}

bool view_dto_equal(const view_persistence_dto_t& lhs, const view_persistence_dto_t& rhs) noexcept
{
    return lhs.id == rhs.id && lhs.workspace == rhs.workspace && lhs.document == rhs.document &&
           lhs.role == rhs.role && lhs.synchronization_group == rhs.synchronization_group &&
           lhs.synchronization_policy == rhs.synchronization_policy &&
           lhs.focused == rhs.focused;
}

bool panel_dto_equal(const panel_state_dto_t& lhs, const panel_state_dto_t& rhs)
{
    return lhs.id == rhs.id && lhs.workspace == rhs.workspace && lhs.kind == rhs.kind &&
           lhs.visible == rhs.visible && lhs.pinned == rhs.pinned &&
           lhs.selected_document == rhs.selected_document &&
           lhs.state_token == rhs.state_token && lhs.revision == rhs.revision;
}

bool event_vector_equal(const std::vector<navigation_event_t>& lhs,
                        const std::vector<navigation_event_t>& rhs)
{
    if (lhs.size() != rhs.size())
        return false;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        if (!navigation_event_equal(lhs[index], rhs[index]))
            return false;
    }
    return true;
}

bool history_equal(const navigation_history_dto_t& lhs, const navigation_history_dto_t& rhs)
{
    return lhs.workspace == rhs.workspace && lhs.capacity == rhs.capacity &&
           event_vector_equal(lhs.back, rhs.back) && event_vector_equal(lhs.forward, rhs.forward);
}

bool find_document(const std::vector<document_persistence_dto_t>& documents,
                   document_id_t id) noexcept
{
    return std::any_of(documents.begin(), documents.end(), [id](const auto& document) {
        return document.id == id;
    });
}

bool valid_document_text(const document_persistence_dto_t& document) noexcept
{
    return document.identity.provider_key.size() <= k_max_document_key_bytes &&
           document.title.size() <= k_max_document_title_bytes &&
           document.state_token.size() <= k_max_panel_state_bytes;
}

bool valid_panel_text(const panel_state_dto_t& panel) noexcept
{
    return panel.state_token.size() <= k_max_panel_state_bytes;
}

void hash_byte(std::uint64_t& hash, std::uint8_t value) noexcept
{
    hash ^= value;
    hash *= k_fnv_prime;
}

void hash_u32(std::uint64_t& hash, std::uint32_t value) noexcept
{
    for (std::uint32_t shift = 0; shift != 32; shift += 8)
        hash_byte(hash, static_cast<std::uint8_t>(value >> shift));
}

void hash_u64(std::uint64_t& hash, std::uint64_t value) noexcept
{
    for (std::uint32_t shift = 0; shift != 64; shift += 8)
        hash_byte(hash, static_cast<std::uint8_t>(value >> shift));
}

void hash_bool(std::uint64_t& hash, bool value) noexcept
{
    hash_byte(hash, value ? 1U : 0U);
}

void hash_string(std::uint64_t& hash, const std::string& value) noexcept
{
    hash_u64(hash, static_cast<std::uint64_t>(value.size()));
    for (const char byte : value)
        hash_byte(hash, static_cast<std::uint8_t>(static_cast<unsigned char>(byte)));
}

void hash_selection(std::uint64_t& hash, const selection_context_t& selection) noexcept
{
    hash_byte(hash, static_cast<std::uint8_t>(selection.kind));
    hash_bool(hash, selection.has_address);
    hash_u64(hash, selection.address);
    hash_u64(hash, selection.extent);
    hash_string(hash, selection.entity_key);
}

void hash_cursor(std::uint64_t& hash, const document_local_cursor_t& cursor) noexcept
{
    hash_bool(hash, cursor.has_position);
    hash_u64(hash, cursor.position);
}

void hash_document_local_state(std::uint64_t& hash, const document_local_state_t& state) noexcept
{
    hash_cursor(hash, state.cursor);
    hash_selection(hash, state.selection);
}

void hash_identity(std::uint64_t& hash, const document_identity_t& identity) noexcept
{
    hash_u64(hash, identity.workspace.value);
    hash_byte(hash, static_cast<std::uint8_t>(identity.kind));
    hash_u64(hash, identity.object_id);
    hash_u64(hash, identity.variant_id);
    hash_string(hash, identity.provider_key);
    hash_bool(hash, identity.has_address);
    hash_u64(hash, identity.address);
}

void hash_event(std::uint64_t& hash, const navigation_event_t& event) noexcept
{
    hash_u64(hash, event.id.value);
    hash_u64(hash, event.workspace.value);
    hash_bool(hash, event.has_source);
    hash_u64(hash, event.source.workspace.value);
    hash_u64(hash, event.source.document.value);
    hash_u64(hash, event.source.view.value);
    hash_selection(hash, event.source.selection);
    hash_cursor(hash, event.source.cursor);
    hash_u64(hash, event.source.synchronization_group);
    hash_byte(hash, static_cast<std::uint8_t>(event.source.synchronization_policy));
    hash_identity(hash, event.target.document);
    hash_selection(hash, event.target.selection);
    hash_cursor(hash, event.target.cursor);
    hash_byte(hash, static_cast<std::uint8_t>(event.origin));
    hash_u64(hash, event.sequence);
    hash_bool(hash, event.request_focus);
}

}

bool document_identity_equal(const document_identity_t& lhs, const document_identity_t& rhs)
{
    return lhs.workspace == rhs.workspace && lhs.kind == rhs.kind && lhs.object_id == rhs.object_id &&
           lhs.variant_id == rhs.variant_id && lhs.provider_key == rhs.provider_key &&
           lhs.has_address == rhs.has_address && lhs.address == rhs.address;
}

bool document_identity_less(const document_identity_t& lhs, const document_identity_t& rhs)
{
    if (lhs.workspace != rhs.workspace)
        return lhs.workspace < rhs.workspace;
    if (lhs.kind != rhs.kind)
        return static_cast<std::uint8_t>(lhs.kind) < static_cast<std::uint8_t>(rhs.kind);
    if (lhs.object_id != rhs.object_id)
        return lhs.object_id < rhs.object_id;
    if (lhs.variant_id != rhs.variant_id)
        return lhs.variant_id < rhs.variant_id;
    if (lhs.provider_key != rhs.provider_key)
        return lhs.provider_key < rhs.provider_key;
    if (lhs.has_address != rhs.has_address)
        return !lhs.has_address;
    return lhs.address < rhs.address;
}

bool selection_context_equal(const selection_context_t& lhs, const selection_context_t& rhs)
{
    return lhs.kind == rhs.kind && lhs.has_address == rhs.has_address &&
           lhs.address == rhs.address && lhs.extent == rhs.extent &&
           lhs.entity_key == rhs.entity_key;
}

bool document_local_cursor_equal(const document_local_cursor_t& lhs,
                                 const document_local_cursor_t& rhs) noexcept
{
    return lhs.has_position == rhs.has_position && lhs.position == rhs.position;
}

bool document_local_state_equal(const document_local_state_t& lhs,
                                const document_local_state_t& rhs)
{
    return document_local_cursor_equal(lhs.cursor, rhs.cursor) &&
           selection_context_equal(lhs.selection, rhs.selection);
}

bool persistence_dto_equal(const workbench_persistence_dto_t& lhs,
                           const workbench_persistence_dto_t& rhs)
{
    workbench_persistence_dto_t canonical_lhs = lhs;
    workbench_persistence_dto_t canonical_rhs = rhs;
    if (!normalize_persistence_dto(canonical_lhs) || !normalize_persistence_dto(canonical_rhs))
        return false;
    if (canonical_lhs.schema_version != canonical_rhs.schema_version ||
        canonical_lhs.workspace != canonical_rhs.workspace ||
        canonical_lhs.revision != canonical_rhs.revision ||
        canonical_lhs.active_document != canonical_rhs.active_document ||
        canonical_lhs.documents.size() != canonical_rhs.documents.size() ||
        canonical_lhs.views.size() != canonical_rhs.views.size() ||
        canonical_lhs.panels.size() != canonical_rhs.panels.size() ||
        !history_equal(canonical_lhs.history, canonical_rhs.history)) {
        return false;
    }
    for (std::size_t index = 0; index < canonical_lhs.documents.size(); ++index) {
        if (!document_dto_equal(canonical_lhs.documents[index], canonical_rhs.documents[index]))
            return false;
    }
    for (std::size_t index = 0; index < canonical_lhs.views.size(); ++index) {
        if (!view_dto_equal(canonical_lhs.views[index], canonical_rhs.views[index]))
            return false;
    }
    for (std::size_t index = 0; index < canonical_lhs.panels.size(); ++index) {
        if (!panel_dto_equal(canonical_lhs.panels[index], canonical_rhs.panels[index]))
            return false;
    }
    return true;
}

workbench_error_t validate_document_identity(const document_identity_t& identity)
{
    if (!identity.workspace.valid())
        return error(workbench_error_code_t::invalid_workspace);
    if (!valid_document_kind(identity.kind) ||
        identity.provider_key.size() > k_max_document_key_bytes ||
        (identity.object_id == 0 && identity.provider_key.empty() && !identity.has_address)) {
        return error(workbench_error_code_t::invalid_document);
    }
    if (!identity.has_address && identity.address != 0)
        return error(workbench_error_code_t::invalid_document);
    return {};
}

workbench_error_t validate_selection_context(const selection_context_t& selection)
{
    if (!valid_selection_kind(selection.kind) || selection.entity_key.size() > k_max_document_key_bytes)
        return error(workbench_error_code_t::invalid_navigation);
    switch (selection.kind) {
        case selection_kind_t::none:
            return (!selection.has_address && selection.address == 0 && selection.extent == 0 &&
                    selection.entity_key.empty())
                ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
        case selection_kind_t::address:
            return (selection.has_address && selection.extent == 0 && selection.entity_key.empty())
                ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
        case selection_kind_t::entity:
        case selection_kind_t::source:
            return (!selection.has_address && selection.address == 0 && selection.extent == 0 &&
                    !selection.entity_key.empty())
                ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
        case selection_kind_t::range:
            return (selection.has_address && selection.extent != 0 && selection.entity_key.empty())
                ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
    }
    return error(workbench_error_code_t::invalid_navigation);
}

workbench_error_t validate_document_local_cursor(const document_local_cursor_t& cursor)
{
    return !cursor.has_position && cursor.position != 0
        ? error(workbench_error_code_t::invalid_document_state) : workbench_error_t{};
}

workbench_error_t validate_document_local_state(const document_local_state_t& state)
{
    const auto cursor_result = validate_document_local_cursor(state.cursor);
    if (!cursor_result)
        return cursor_result;
    const auto selection_result = validate_selection_context(state.selection);
    return selection_result ? workbench_error_t{} :
        error(workbench_error_code_t::invalid_document_state);
}

workbench_error_t validate_workspace_view_context(const workspace_view_context_t& context)
{
    if (!context.workspace.valid())
        return error(workbench_error_code_t::invalid_workspace);
    if (!context.document.valid() || !context.view.valid())
        return error(workbench_error_code_t::invalid_view);
    if (!synchronization_policy_matches(context.synchronization_policy,
                                        context.synchronization_group)) {
        return error(workbench_error_code_t::invalid_synchronization_policy, context.view.value);
    }
    const auto selection_result = validate_selection_context(context.selection);
    if (!selection_result)
        return selection_result;
    const auto cursor_result = validate_document_local_cursor(context.cursor);
    return cursor_result ? workbench_error_t{} :
        error(workbench_error_code_t::invalid_document_state, context.document.value);
}

workbench_error_t validate_view_context(const view_context_t& context)
{
    return validate_workspace_view_context(context);
}

workbench_error_t validate_workspace_navigation_event(const workspace_navigation_event_t& event)
{
    if (!event.id.valid() || !event.workspace.valid() || event.sequence == 0 ||
        !valid_navigation_origin(event.origin)) {
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    }
    if (event.origin == navigation_origin_t::mcp && event.request_focus)
        return error(workbench_error_code_t::focus_forbidden, event.id.value);
    const auto target_result = validate_document_identity(event.target.document);
    if (!target_result)
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    if (event.target.document.workspace != event.workspace)
        return error(workbench_error_code_t::workspace_mismatch, event.id.value);
    const auto selection_result = validate_selection_context(event.target.selection);
    if (!selection_result)
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    const auto cursor_result = validate_document_local_cursor(event.target.cursor);
    if (!cursor_result)
        return error(workbench_error_code_t::invalid_document_state, event.id.value);
    if (!event.has_source)
        return {};
    const auto source_result = validate_workspace_view_context(event.source);
    if (!source_result)
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    return event.source.workspace == event.workspace
        ? workbench_error_t{} : error(workbench_error_code_t::workspace_mismatch, event.id.value);
}

workbench_error_t validate_navigation_event(const navigation_event_t& event)
{
    return validate_workspace_navigation_event(event);
}

workbench_error_t validate_persistence_dto(const workbench_persistence_dto_t& dto)
{
    if (dto.schema_version != k_workbench_contract_schema_version || !dto.workspace.valid() ||
        !dto.revision.valid()) {
        return error(workbench_error_code_t::invalid_persistence);
    }
    if (dto.documents.size() > k_max_documents_per_workspace ||
        dto.views.size() > k_max_views_per_workspace || dto.panels.size() > k_max_panels_per_workspace) {
        return error(workbench_error_code_t::invalid_persistence);
    }
    if (dto.documents.empty() || dto.views.empty() || !dto.active_document.valid())
        return error(workbench_error_code_t::invalid_persistence, dto.active_document.value);

    std::unordered_set<std::uint64_t> document_ids;
    std::vector<document_identity_t> identities;
    document_ids.reserve(dto.documents.size());
    identities.reserve(dto.documents.size());
    for (const auto& document : dto.documents) {
        if (!document.id.valid() || !valid_document_text(document))
            return error(workbench_error_code_t::invalid_document, document.id.value);
        const auto identity_result = validate_document_identity(document.identity);
        if (!identity_result)
            return identity_result;
        const auto local_state_result = validate_document_local_state(document.local_state);
        if (!local_state_result)
            return error(workbench_error_code_t::invalid_document_state, document.id.value);
        if (document.identity.workspace != dto.workspace)
            return error(workbench_error_code_t::workspace_mismatch, document.id.value);
        if (!document_ids.insert(document.id.value).second)
            return error(workbench_error_code_t::duplicate_identifier, document.id.value);
        for (const auto& existing : identities) {
            if (document_identity_equal(existing, document.identity))
                return error(workbench_error_code_t::duplicate_identifier, document.id.value);
        }
        identities.push_back(document.identity);
    }
    if (!find_document(dto.documents, dto.active_document))
        return error(workbench_error_code_t::invalid_document, dto.active_document.value);

    std::unordered_set<std::uint64_t> view_ids;
    view_ids.reserve(dto.views.size());
    std::uint32_t focused_views = 0;
    for (const auto& view : dto.views) {
        if (!view.id.valid() || !view.document.valid() || !valid_view_role(view.role))
            return error(workbench_error_code_t::invalid_view, view.id.value);
        if (view.workspace != dto.workspace)
            return error(workbench_error_code_t::workspace_mismatch, view.id.value);
        if (!find_document(dto.documents, view.document))
            return error(workbench_error_code_t::invalid_document, view.document.value);
        if (!synchronization_policy_matches(view.synchronization_policy,
                                            view.synchronization_group)) {
            return error(workbench_error_code_t::invalid_synchronization_policy, view.id.value);
        }
        if (!view_ids.insert(view.id.value).second)
            return error(workbench_error_code_t::duplicate_identifier, view.id.value);
        focused_views += view.focused ? 1U : 0U;
        if (focused_views > 1)
            return error(workbench_error_code_t::invalid_view, view.id.value);
    }
    if (focused_views != 1)
        return error(workbench_error_code_t::invalid_view);
    const auto focused = std::find_if(dto.views.begin(), dto.views.end(),
        [](const auto& view) { return view.focused; });
    if (focused == dto.views.end() || focused->document != dto.active_document)
        return error(workbench_error_code_t::invalid_persistence, dto.active_document.value);
    std::unordered_set<std::uint64_t> panel_ids;
    panel_ids.reserve(dto.panels.size());
    for (const auto& panel : dto.panels) {
        if (!panel.id.valid() || !panel.revision.valid() || !valid_panel_kind(panel.kind) ||
            !valid_panel_text(panel)) {
            return error(workbench_error_code_t::invalid_panel, panel.id.value);
        }
        if (panel.workspace != dto.workspace)
            return error(workbench_error_code_t::workspace_mismatch, panel.id.value);
        if (panel.revision.value > dto.revision.value ||
            (panel.selected_document.valid() && !find_document(dto.documents, panel.selected_document)) ||
            !panel_ids.insert(panel.id.value).second) {
            return error(workbench_error_code_t::invalid_panel, panel.id.value);
        }
    }

    if (dto.history.workspace != dto.workspace || dto.history.capacity == 0 ||
        dto.history.capacity > k_max_history_capacity ||
        dto.history.back.size() + dto.history.forward.size() > dto.history.capacity) {
        return error(workbench_error_code_t::invalid_persistence);
    }
    std::unordered_set<std::uint64_t> history_ids;
    std::unordered_set<std::uint64_t> sequences;
    const auto validate_history_events = [&](const std::vector<navigation_event_t>& events) {
        for (const auto& event : events) {
            const auto result = validate_navigation_event(event);
            if (!result || event.workspace != dto.workspace ||
                !history_ids.insert(event.id.value).second ||
                !sequences.insert(event.sequence).second) {
                return false;
            }
        }
        return true;
    };
    return validate_history_events(dto.history.back) && validate_history_events(dto.history.forward)
        ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
}

workbench_error_t normalize_persistence_dto(workbench_persistence_dto_t& dto)
{
    dto.history.capacity = dto.history.capacity == 0 ? k_default_history_capacity :
        (dto.history.capacity > k_max_history_capacity ? k_max_history_capacity : dto.history.capacity);
    std::sort(dto.documents.begin(), dto.documents.end(), [](const auto& lhs, const auto& rhs) {
        if (document_identity_less(lhs.identity, rhs.identity))
            return true;
        if (document_identity_less(rhs.identity, lhs.identity))
            return false;
        return lhs.id < rhs.id;
    });
    std::sort(dto.panels.begin(), dto.panels.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.id < rhs.id;
    });
    return validate_persistence_dto(dto);
}

workbench_error_t next_workspace_revision(workspace_revision_t current,
                                          workspace_revision_t& output) noexcept
{
    if (!current.valid())
        return error(workbench_error_code_t::revision_mismatch);
    if (current.value == (std::numeric_limits<std::uint64_t>::max)())
        return error(workbench_error_code_t::revision_overflow, current.value);
    output = {current.value + 1U};
    return {};
}

bool revision_matches(workspace_revision_t expected, workspace_revision_t observed) noexcept
{
    return expected.valid() && observed.valid() && expected == observed;
}

workbench_error_t append_navigation_history(navigation_history_dto_t& history,
                                            const navigation_event_t& event)
{
    if (!history.workspace.valid() || history.capacity == 0 || history.capacity > k_max_history_capacity)
        return error(workbench_error_code_t::history_capacity);
    const auto event_result = validate_navigation_event(event);
    if (!event_result)
        return event_result;
    if (event.workspace != history.workspace)
        return error(workbench_error_code_t::workspace_mismatch, event.id.value);
    const auto matches = [&event](const navigation_event_t& existing) {
        return existing.id == event.id || existing.sequence == event.sequence;
    };
    if (std::any_of(history.back.begin(), history.back.end(), matches) ||
        std::any_of(history.forward.begin(), history.forward.end(), matches)) {
        return error(workbench_error_code_t::duplicate_identifier, event.id.value);
    }
    history.forward.clear();
    history.back.push_back(event);
    if (history.back.size() > history.capacity)
        history.back.erase(history.back.begin());
    return {};
}

workbench_error_t history_back(navigation_history_dto_t& history,
                               navigation_event_t& output)
{
    if (!history.workspace.valid() || history.capacity == 0 || history.capacity > k_max_history_capacity)
        return error(workbench_error_code_t::history_capacity);
    if (history.back.empty())
        return error(workbench_error_code_t::history_empty);
    output = history.back.back();
    history.back.pop_back();
    history.forward.push_back(output);
    return {};
}

workbench_error_t history_forward(navigation_history_dto_t& history,
                                  navigation_event_t& output)
{
    if (!history.workspace.valid() || history.capacity == 0 || history.capacity > k_max_history_capacity)
        return error(workbench_error_code_t::history_capacity);
    if (history.forward.empty())
        return error(workbench_error_code_t::history_empty);
    output = history.forward.back();
    history.forward.pop_back();
    history.back.push_back(output);
    return {};
}

persistence_fingerprint_t persistence_fingerprint(const workbench_persistence_dto_t& dto)
{
    workbench_persistence_dto_t canonical = dto;
    if (!normalize_persistence_dto(canonical))
        return {};
    std::uint64_t hash = k_fnv_offset_basis;
    hash_u32(hash, canonical.schema_version);
    hash_u64(hash, canonical.workspace.value);
    hash_u64(hash, canonical.revision.value);
    hash_u64(hash, static_cast<std::uint64_t>(canonical.documents.size()));
    for (const auto& document : canonical.documents) {
        hash_u64(hash, document.id.value);
        hash_identity(hash, document.identity);
        hash_string(hash, document.title);
        hash_string(hash, document.state_token);
        hash_document_local_state(hash, document.local_state);
        hash_bool(hash, document.pinned);
        hash_bool(hash, document.closeable);
    }
    hash_u64(hash, canonical.active_document.value);
    hash_u64(hash, static_cast<std::uint64_t>(canonical.views.size()));
    for (const auto& view : canonical.views) {
        hash_u64(hash, view.id.value);
        hash_u64(hash, view.workspace.value);
        hash_u64(hash, view.document.value);
        hash_byte(hash, static_cast<std::uint8_t>(view.role));
        hash_u64(hash, view.synchronization_group);
        hash_byte(hash, static_cast<std::uint8_t>(view.synchronization_policy));
        hash_bool(hash, view.focused);
    }
    hash_u64(hash, static_cast<std::uint64_t>(canonical.panels.size()));
    for (const auto& panel : canonical.panels) {
        hash_u64(hash, panel.id.value);
        hash_u64(hash, panel.workspace.value);
        hash_byte(hash, static_cast<std::uint8_t>(panel.kind));
        hash_bool(hash, panel.visible);
        hash_bool(hash, panel.pinned);
        hash_u64(hash, panel.selected_document.value);
        hash_string(hash, panel.state_token);
        hash_u64(hash, panel.revision.value);
    }
    hash_u64(hash, canonical.history.workspace.value);
    hash_u32(hash, canonical.history.capacity);
    hash_u64(hash, static_cast<std::uint64_t>(canonical.history.back.size()));
    for (const auto& event : canonical.history.back)
        hash_event(hash, event);
    hash_u64(hash, static_cast<std::uint64_t>(canonical.history.forward.size()));
    for (const auto& event : canonical.history.forward)
        hash_event(hash, event);
    return {hash};
}

workbench_error_t workbench_persistence_dto_t::validate() const
{
    return validate_persistence_dto(*this);
}

workbench_error_t workbench_persistence_dto_t::normalize()
{
    return normalize_persistence_dto(*this);
}

persistence_fingerprint_t workbench_persistence_dto_t::fingerprint() const
{
    return persistence_fingerprint(*this);
}

bool workbench_persistence_dto_t::equivalent(
    const workbench_persistence_dto_t& other) const
{
    return persistence_dto_equal(*this, other);
}

workbench_document_bridge_t::workbench_document_bridge_t(
    workspace_id_t workspace) noexcept
    : workspace_(workspace)
{
}

workbench_error_t workbench_document_bridge_t::publish(
    document_descriptor_t descriptor)
{
    const auto identity_error = validate_document_identity(descriptor.identity);
    if (!identity_error)
        return identity_error;
    if (!workspace_.valid() || descriptor.identity.workspace != workspace_)
        return error(workbench_error_code_t::workspace_mismatch, workspace_.value);
    if (descriptor.title.empty() ||
        descriptor.title.size() > k_max_document_title_bytes)
        return error(workbench_error_code_t::invalid_document);

    std::lock_guard<std::mutex> lock(mutex_);
    const auto existing = std::find_if(
        documents_.begin(), documents_.end(),
        [&descriptor](const document_descriptor_t& candidate) {
            return document_identity_equal(candidate.identity,
                                           descriptor.identity);
        });
    if (existing != documents_.end()) {
        *existing = std::move(descriptor);
        return {};
    }
    if (documents_.size() >= k_max_documents_per_workspace)
        return error(workbench_error_code_t::invalid_document,
                     static_cast<std::uint64_t>(documents_.size()));
    documents_.push_back(std::move(descriptor));
    std::sort(documents_.begin(), documents_.end(),
        [](const document_descriptor_t& lhs,
           const document_descriptor_t& rhs) {
            return document_identity_less(lhs.identity, rhs.identity);
        });
    return {};
}

workbench_error_t workbench_document_bridge_t::replace(
    std::vector<document_descriptor_t> descriptors)
{
    if (!workspace_.valid())
        return error(workbench_error_code_t::invalid_workspace, workspace_.value);
    if (descriptors.size() > k_max_documents_per_workspace)
        return error(workbench_error_code_t::invalid_document,
                     static_cast<std::uint64_t>(descriptors.size()));
    for (const auto& descriptor : descriptors) {
        const auto identity_error = validate_document_identity(descriptor.identity);
        if (!identity_error)
            return identity_error;
        if (descriptor.identity.workspace != workspace_)
            return error(workbench_error_code_t::workspace_mismatch,
                         descriptor.identity.workspace.value);
        if (descriptor.title.empty() ||
            descriptor.title.size() > k_max_document_title_bytes)
            return error(workbench_error_code_t::invalid_document);
    }
    std::sort(descriptors.begin(), descriptors.end(),
        [](const document_descriptor_t& lhs,
           const document_descriptor_t& rhs) {
            return document_identity_less(lhs.identity, rhs.identity);
        });
    for (std::size_t index = 1; index < descriptors.size(); ++index) {
        if (document_identity_equal(descriptors[index - 1].identity,
                                    descriptors[index].identity))
            return error(workbench_error_code_t::duplicate_identifier,
                         static_cast<std::uint64_t>(index));
    }
    std::lock_guard<std::mutex> lock(mutex_);
    documents_ = std::move(descriptors);
    return {};
}

workbench_error_t workbench_document_bridge_t::remove(
    const document_identity_t& identity)
{
    const auto identity_error = validate_document_identity(identity);
    if (!identity_error)
        return identity_error;
    if (identity.workspace != workspace_)
        return error(workbench_error_code_t::workspace_mismatch,
                     identity.workspace.value);
    std::lock_guard<std::mutex> lock(mutex_);
    const auto existing = std::find_if(
        documents_.begin(), documents_.end(),
        [&identity](const document_descriptor_t& candidate) {
            return document_identity_equal(candidate.identity, identity);
        });
    if (existing == documents_.end())
        return error(workbench_error_code_t::invalid_document);
    documents_.erase(existing);
    return {};
}

void workbench_document_bridge_t::clear() noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);
    documents_.clear();
}

workbench_error_t workbench_document_bridge_t::describe(
    const document_identity_t& identity,
    document_descriptor_t& output) const
{
    output = {};
    const auto identity_error = validate_document_identity(identity);
    if (!identity_error)
        return identity_error;
    if (identity.workspace != workspace_)
        return error(workbench_error_code_t::workspace_mismatch,
                     identity.workspace.value);
    std::lock_guard<std::mutex> lock(mutex_);
    const auto existing = std::find_if(
        documents_.begin(), documents_.end(),
        [&identity](const document_descriptor_t& candidate) {
            return document_identity_equal(candidate.identity, identity);
        });
    if (existing != documents_.end()) {
        output = *existing;
        return {};
    }
    const auto base = std::find_if(
        documents_.begin(), documents_.end(),
        [&identity](const document_descriptor_t& candidate) {
            return candidate.identity.workspace == identity.workspace &&
                   candidate.identity.kind == identity.kind &&
                   candidate.identity.object_id == identity.object_id &&
                   candidate.identity.variant_id == identity.variant_id &&
                   candidate.identity.provider_key == identity.provider_key &&
                   !candidate.identity.has_address;
        });
    if (base == documents_.end())
        return error(workbench_error_code_t::invalid_document);
    output = *base;
    output.identity = identity;
    return {};
}

workbench_error_t workbench_document_bridge_t::resolve(
    const navigation_event_t& event,
    navigation_resolution_t& output) const
{
    output = {};
    const auto event_error = validate_navigation_event(event);
    if (!event_error)
        return event_error;
    if (event.workspace != workspace_)
        return error(workbench_error_code_t::workspace_mismatch,
                     event.workspace.value);
    document_descriptor_t descriptor;
    const auto describe_error = describe(event.target.document, descriptor);
    if (!describe_error)
        return describe_error;
    if (!descriptor.can_open)
        return error(workbench_error_code_t::adapter_rejected,
                     event.target.document.object_id);
    output.document = event.target.document;
    output.selection = event.target.selection;
    output.cursor = event.target.cursor;
    output.requires_document_open = true;
    return {};
}

workbench_error_t workbench_document_bridge_t::resolve_target(
    const document_identity_t& source,
    document_kind_t target_kind,
    std::uint64_t address,
    navigation_resolution_t& output) const
{
    output = {};
    const auto source_error = validate_document_identity(source);
    if (!source_error)
        return source_error;
    if (source.workspace != workspace_)
        return error(workbench_error_code_t::workspace_mismatch,
                     source.workspace.value);
    if (target_kind == document_kind_t::unknown)
        return error(workbench_error_code_t::invalid_document);

    std::lock_guard<std::mutex> lock(mutex_);
    const auto source_known = std::any_of(
        documents_.begin(), documents_.end(),
        [&source](const document_descriptor_t& candidate) {
            return candidate.can_open &&
                   candidate.identity.workspace == source.workspace &&
                   candidate.identity.kind == source.kind &&
                   candidate.identity.object_id == source.object_id &&
                   candidate.identity.variant_id == source.variant_id &&
                   candidate.identity.provider_key == source.provider_key &&
                   (!candidate.identity.has_address ||
                    (source.has_address &&
                     candidate.identity.address == source.address));
        });
    if (!source_known)
        return error(workbench_error_code_t::invalid_document,
                     source.object_id);
    const document_descriptor_t* selected = nullptr;
    for (const auto& candidate : documents_) {
        if (candidate.identity.kind != target_kind || !candidate.can_open)
            continue;
        const bool same_source =
            candidate.identity.object_id == source.object_id &&
            candidate.identity.variant_id == source.variant_id &&
            candidate.identity.provider_key == source.provider_key;
        if (same_source) {
            selected = &candidate;
            break;
        }
    }
    if (!selected) {
        for (const auto& candidate : documents_) {
            if (candidate.identity.kind != target_kind || !candidate.can_open)
                continue;
            if (selected != nullptr)
                return error(workbench_error_code_t::adapter_rejected,
                             static_cast<std::uint64_t>(target_kind));
            selected = &candidate;
        }
    }
    if (!selected)
        return error(workbench_error_code_t::invalid_document,
                     static_cast<std::uint64_t>(target_kind));

    output.document = selected->identity;
    output.document.has_address = true;
    output.document.address = address;
    output.selection.kind = selection_kind_t::address;
    output.selection.has_address = true;
    output.selection.address = address;
    output.cursor.has_position = true;
    output.cursor.position = address;
    output.requires_document_open = true;
    return {};
}

workbench_error_t workbench_document_bridge_t::emit(
    const document_navigation_bridge_request_t& request,
    navigation_event_t& output) const
{
    output = {};
    const auto source_error = validate_view_context(request.source);
    if (!source_error)
        return source_error;
    if (request.source.workspace != workspace_)
        return error(workbench_error_code_t::workspace_mismatch,
                     request.source.workspace.value);

    document_descriptor_t descriptor;
    const auto describe_error = describe(request.target.document, descriptor);
    if (!describe_error)
        return describe_error;
    if (!descriptor.can_open)
        return error(workbench_error_code_t::adapter_rejected,
                     request.target.document.object_id);

    output.id = request.id;
    output.workspace = workspace_;
    output.has_source = true;
    output.source = request.source;
    output.target = request.target;
    output.origin = request.origin;
    output.sequence = request.sequence;
    output.request_focus = request.request_focus;
    const auto event_error = validate_navigation_event(output);
    if (!event_error)
        output = {};
    return event_error;
}

std::vector<document_descriptor_t>
workbench_document_bridge_t::documents() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return documents_;
}

}
}
