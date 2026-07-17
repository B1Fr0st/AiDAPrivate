#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace workbench {

constexpr std::uint32_t k_workbench_contract_schema_version = 3;
constexpr std::uint32_t k_default_history_capacity = 128;
constexpr std::uint32_t k_max_history_capacity = 1024;
constexpr std::uint32_t k_max_documents_per_workspace = 4096;
constexpr std::uint32_t k_max_views_per_workspace = 4096;
constexpr std::uint32_t k_max_panels_per_workspace = 256;
constexpr std::uint32_t k_max_document_key_bytes = 1024;
constexpr std::uint32_t k_max_document_title_bytes = 256;
constexpr std::uint32_t k_max_panel_state_bytes = 65536;

struct workspace_id_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

struct document_id_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

struct view_id_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

struct panel_instance_id_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

struct navigation_event_id_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

struct workspace_revision_t {
    std::uint64_t value = 0;

    constexpr bool valid() const noexcept { return value != 0; }
};

struct persistence_fingerprint_t {
    std::uint64_t value = 0;
};

constexpr bool operator==(workspace_id_t lhs, workspace_id_t rhs) noexcept { return lhs.value == rhs.value; }
constexpr bool operator!=(workspace_id_t lhs, workspace_id_t rhs) noexcept { return !(lhs == rhs); }
constexpr bool operator<(workspace_id_t lhs, workspace_id_t rhs) noexcept { return lhs.value < rhs.value; }
constexpr bool operator==(document_id_t lhs, document_id_t rhs) noexcept { return lhs.value == rhs.value; }
constexpr bool operator!=(document_id_t lhs, document_id_t rhs) noexcept { return !(lhs == rhs); }
constexpr bool operator<(document_id_t lhs, document_id_t rhs) noexcept { return lhs.value < rhs.value; }
constexpr bool operator==(view_id_t lhs, view_id_t rhs) noexcept { return lhs.value == rhs.value; }
constexpr bool operator!=(view_id_t lhs, view_id_t rhs) noexcept { return !(lhs == rhs); }
constexpr bool operator<(view_id_t lhs, view_id_t rhs) noexcept { return lhs.value < rhs.value; }
constexpr bool operator==(panel_instance_id_t lhs, panel_instance_id_t rhs) noexcept { return lhs.value == rhs.value; }
constexpr bool operator!=(panel_instance_id_t lhs, panel_instance_id_t rhs) noexcept { return !(lhs == rhs); }
constexpr bool operator<(panel_instance_id_t lhs, panel_instance_id_t rhs) noexcept { return lhs.value < rhs.value; }
constexpr bool operator==(navigation_event_id_t lhs, navigation_event_id_t rhs) noexcept { return lhs.value == rhs.value; }
constexpr bool operator!=(navigation_event_id_t lhs, navigation_event_id_t rhs) noexcept { return !(lhs == rhs); }
constexpr bool operator<(navigation_event_id_t lhs, navigation_event_id_t rhs) noexcept { return lhs.value < rhs.value; }
constexpr bool operator==(workspace_revision_t lhs, workspace_revision_t rhs) noexcept { return lhs.value == rhs.value; }
constexpr bool operator!=(workspace_revision_t lhs, workspace_revision_t rhs) noexcept { return !(lhs == rhs); }
constexpr bool operator<(workspace_revision_t lhs, workspace_revision_t rhs) noexcept { return lhs.value < rhs.value; }
constexpr bool operator==(persistence_fingerprint_t lhs, persistence_fingerprint_t rhs) noexcept { return lhs.value == rhs.value; }
constexpr bool operator!=(persistence_fingerprint_t lhs, persistence_fingerprint_t rhs) noexcept { return !(lhs == rhs); }

enum class workbench_error_code_t : std::uint16_t {
    none = 0,
    invalid_workspace,
    invalid_document,
    invalid_view,
    duplicate_identifier,
    workspace_mismatch,
    invalid_navigation,
    invalid_panel,
    invalid_layout,
    invalid_persistence,
    revision_mismatch,
    revision_overflow,
    history_empty,
    history_capacity,
    adapter_rejected,
    invalid_document_state,
    invalid_synchronization_policy,
    focus_forbidden
};

struct workbench_error_t {
    workbench_error_code_t code = workbench_error_code_t::none;
    std::uint64_t subject = 0;

    constexpr bool ok() const noexcept { return code == workbench_error_code_t::none; }
    constexpr explicit operator bool() const noexcept { return ok(); }
};

enum class document_kind_t : std::uint8_t {
    unknown = 0,
    binary = 1,
    disassembly = 2,
    hex = 3,
    pseudocode = 4,
    graph = 5,
    strings = 6,
    imports = 7,
    exports = 8,
    functions = 9,
    types = 10,
    diagnostics = 11,
    bookmarks = 12,
    memory = 13,
    debugger = 14,
    custom = 15,
    diff = 16
};

enum class view_role_t : std::uint8_t {
    primary = 0,
    secondary = 1,
    preview = 2,
    inspector = 3,
    transient = 4
};

enum class selection_kind_t : std::uint8_t {
    none = 0,
    address = 1,
    entity = 2,
    range = 3,
    source = 4
};

enum class view_synchronization_policy_t : std::uint8_t {
    independent = 0,
    selection = 1,
    cursor_and_selection = 2
};

enum class navigation_origin_t : std::uint8_t {
    user = 0,
    history = 1,
    navigator = 2,
    inspector = 3,
    command = 4,
    adapter = 5,
    restore = 6,
    mcp = 7
};

enum class panel_kind_t : std::uint8_t {
    navigator = 0,
    inspector = 1,
    output = 2,
    diagnostics = 3,
    bookmarks = 4,
    progress = 5,
    custom = 6
};

struct document_identity_t {
    workspace_id_t workspace;
    document_kind_t kind = document_kind_t::unknown;
    std::uint64_t object_id = 0;
    std::uint64_t variant_id = 0;
    std::string provider_key;
    bool has_address = false;
    std::uint64_t address = 0;
};

struct selection_context_t {
    selection_kind_t kind = selection_kind_t::none;
    bool has_address = false;
    std::uint64_t address = 0;
    std::uint64_t extent = 0;
    std::string entity_key;
};

struct document_local_cursor_t {
    bool has_position = false;
    std::uint64_t position = 0;
};

struct document_local_state_t {
    document_local_cursor_t cursor;
    selection_context_t selection;
};

struct workspace_view_context_t {
    workspace_id_t workspace;
    document_id_t document;
    view_id_t view;
    selection_context_t selection;
    document_local_cursor_t cursor;
    std::uint64_t synchronization_group = 0;
    view_synchronization_policy_t synchronization_policy =
        view_synchronization_policy_t::independent;
};

using view_context_t = workspace_view_context_t;

struct navigation_target_t {
    document_identity_t document;
    selection_context_t selection;
    document_local_cursor_t cursor;
};

struct workspace_navigation_event_t {
    navigation_event_id_t id;
    workspace_id_t workspace;
    bool has_source = false;
    workspace_view_context_t source;
    navigation_target_t target;
    navigation_origin_t origin = navigation_origin_t::user;
    std::uint64_t sequence = 0;
    bool request_focus = true;
};

using navigation_event_t = workspace_navigation_event_t;

struct document_persistence_dto_t {
    document_id_t id;
    document_identity_t identity;
    std::string title;
    std::string state_token;
    document_local_state_t local_state;
    bool pinned = false;
    bool closeable = true;
};

struct view_persistence_dto_t {
    view_id_t id;
    workspace_id_t workspace;
    document_id_t document;
    view_role_t role = view_role_t::primary;
    std::uint64_t synchronization_group = 0;
    view_synchronization_policy_t synchronization_policy =
        view_synchronization_policy_t::independent;
    bool focused = false;
};

struct panel_state_dto_t {
    panel_instance_id_t id;
    workspace_id_t workspace;
    panel_kind_t kind = panel_kind_t::navigator;
    bool visible = true;
    bool pinned = false;
    document_id_t selected_document;
    std::string state_token;
    workspace_revision_t revision;
};

struct navigation_history_dto_t {
    workspace_id_t workspace;
    std::uint32_t capacity = k_default_history_capacity;
    std::vector<navigation_event_t> back;
    std::vector<navigation_event_t> forward;
};

struct workbench_persistence_dto_t {
    std::uint32_t schema_version = k_workbench_contract_schema_version;
    workspace_id_t workspace;
    workspace_revision_t revision;
    std::vector<document_persistence_dto_t> documents;
    document_id_t active_document;
    std::vector<view_persistence_dto_t> views;
    std::vector<panel_state_dto_t> panels;
    navigation_history_dto_t history;

    workbench_error_t validate() const;
    workbench_error_t normalize();
    persistence_fingerprint_t fingerprint() const;
    bool equivalent(const workbench_persistence_dto_t& other) const;
};

struct document_descriptor_t {
    document_identity_t identity;
    std::string title;
    bool can_open = false;
};

struct navigation_resolution_t {
    document_identity_t document;
    selection_context_t selection;
    document_local_cursor_t cursor;
    bool requires_document_open = false;
};

struct legacy_view_binding_t {
    document_kind_t kind = document_kind_t::unknown;
    view_role_t role = view_role_t::primary;
    std::uint64_t legacy_view_tag = 0;
};

class document_catalog_adapter_t {
public:
    virtual ~document_catalog_adapter_t() = default;
    virtual workbench_error_t describe(const document_identity_t& identity,
                                       document_descriptor_t& output) const = 0;
};

class navigation_adapter_t {
public:
    virtual ~navigation_adapter_t() = default;
    virtual workbench_error_t resolve(const navigation_event_t& event,
                                      navigation_resolution_t& output) const = 0;
};

class view_context_adapter_t {
public:
    virtual ~view_context_adapter_t() = default;
    virtual workbench_error_t bind(const view_context_t& context,
                                   legacy_view_binding_t& output) const = 0;
};

class workbench_persistence_adapter_t {
public:
    virtual ~workbench_persistence_adapter_t() = default;
    virtual workbench_error_t load(workspace_id_t workspace,
                                   workbench_persistence_dto_t& output) const = 0;
    virtual workbench_error_t store(const workbench_persistence_dto_t& input) = 0;
};

struct document_navigation_bridge_request_t {
    navigation_event_id_t id;
    std::uint64_t sequence = 0;
    navigation_origin_t origin = navigation_origin_t::adapter;
    view_context_t source;
    navigation_target_t target;
    bool request_focus = true;
};

class workbench_document_bridge_t final : public document_catalog_adapter_t,
                                          public navigation_adapter_t {
public:
    explicit workbench_document_bridge_t(workspace_id_t workspace) noexcept;

    workbench_document_bridge_t(const workbench_document_bridge_t&) = delete;
    workbench_document_bridge_t& operator=(const workbench_document_bridge_t&) = delete;

    workbench_error_t publish(document_descriptor_t descriptor);
    workbench_error_t replace(std::vector<document_descriptor_t> descriptors);
    workbench_error_t remove(const document_identity_t& identity);
    void clear() noexcept;

    workbench_error_t describe(const document_identity_t& identity,
                               document_descriptor_t& output) const override;
    workbench_error_t resolve(const navigation_event_t& event,
                              navigation_resolution_t& output) const override;

    workbench_error_t resolve_target(const document_identity_t& source,
                                     document_kind_t target_kind,
                                     std::uint64_t address,
                                     navigation_resolution_t& output) const;
    workbench_error_t emit(const document_navigation_bridge_request_t& request,
                           navigation_event_t& output) const;

    std::vector<document_descriptor_t> documents() const;
    workspace_id_t workspace() const noexcept { return workspace_; }

private:
    workspace_id_t workspace_;
    mutable std::mutex mutex_;
    std::vector<document_descriptor_t> documents_;
};

bool document_identity_equal(const document_identity_t& lhs, const document_identity_t& rhs);
bool document_identity_less(const document_identity_t& lhs, const document_identity_t& rhs);
bool selection_context_equal(const selection_context_t& lhs, const selection_context_t& rhs);
bool document_local_cursor_equal(const document_local_cursor_t& lhs,
                                 const document_local_cursor_t& rhs) noexcept;
bool document_local_state_equal(const document_local_state_t& lhs,
                                const document_local_state_t& rhs);
bool persistence_dto_equal(const workbench_persistence_dto_t& lhs,
                           const workbench_persistence_dto_t& rhs);

workbench_error_t validate_document_identity(const document_identity_t& identity);
workbench_error_t validate_selection_context(const selection_context_t& selection);
workbench_error_t validate_document_local_cursor(const document_local_cursor_t& cursor);
workbench_error_t validate_document_local_state(const document_local_state_t& state);
workbench_error_t validate_workspace_view_context(const workspace_view_context_t& context);
workbench_error_t validate_view_context(const view_context_t& context);
workbench_error_t validate_workspace_navigation_event(const workspace_navigation_event_t& event);
workbench_error_t validate_navigation_event(const navigation_event_t& event);
workbench_error_t validate_persistence_dto(const workbench_persistence_dto_t& dto);

workbench_error_t normalize_persistence_dto(workbench_persistence_dto_t& dto);

workbench_error_t next_workspace_revision(workspace_revision_t current,
                                          workspace_revision_t& output) noexcept;
bool revision_matches(workspace_revision_t expected, workspace_revision_t observed) noexcept;

workbench_error_t append_navigation_history(navigation_history_dto_t& history,
                                            const navigation_event_t& event);
workbench_error_t history_back(navigation_history_dto_t& history,
                               navigation_event_t& output);
workbench_error_t history_forward(navigation_history_dto_t& history,
                                  navigation_event_t& output);

persistence_fingerprint_t persistence_fingerprint(const workbench_persistence_dto_t& dto);

}
}
