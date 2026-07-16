#include "core/ui/workspace_layout.hpp"
#include "core/ui/application_view_registry.hpp"

#include "imgui/imgui_internal.h"

#include <algorithm>
#include <cstdint>
#include <array>
#include <initializer_list>
#include <map>
#include <string>

namespace aida::ui::workspace_layout {
namespace {

constexpr std::array<workspace_preset_descriptor_t, 8> kPresetDescriptors{{
    {workspace_preset_t::analysis, "analysis", "Analysis", "Disassembly, pseudocode, graph, symbols, references and inspection"},
    {workspace_preset_t::debugging, "debugging", "Debugging", "Execution controls, CPU, registers, breakpoints, threads, stack and trace"},
    {workspace_preset_t::memory, "memory", "Memory", "Process sessions, scans, results, memory map, hex, pointers and patches"},
    {workspace_preset_t::types_structures, "types-structures", "Types and Structures", "Type catalogs, structure layouts, live values and propagation"},
    {workspace_preset_t::network, "network", "Network", "Proxy history, repeater, browser, protocol streams and evidence"},
    {workspace_preset_t::automation_ai, "automation-ai", "Automation and AI", "Chat, agents, skills, MCP activity, evidence review and tasks"},
    {workspace_preset_t::programming, "programming", "Programming", "Project explorer, source editing, search, terminal, problems and debugging"},
    {workspace_preset_t::safe, "safe", "Safe Layout", "Recovery workspace with Start Center, diagnostics and essential navigation"}
}};

const workspace_preset_descriptor_t& descriptor_for(workspace_preset_t preset) noexcept
{
    for (const auto& descriptor : kPresetDescriptors) {
        if (descriptor.id == preset)
            return descriptor;
    }
    return kPresetDescriptors.front();
}

struct layout_ratios_t {
    float left = 0.18f;
    float right = 0.22f;
    float bottom = 0.24f;
};

layout_ratios_t calculate_layout_ratios(workspace_preset_t preset, ImVec2 size,
    float dpi_scale) noexcept
{
    const float desired_left_ratio = preset == workspace_preset_t::memory ? 0.23f :
        preset == workspace_preset_t::automation_ai ? 0.21f :
        preset == workspace_preset_t::debugging || preset == workspace_preset_t::network ? 0.20f : 0.18f;
    const float desired_right_ratio = preset == workspace_preset_t::types_structures ? 0.26f :
        preset == workspace_preset_t::automation_ai ? 0.24f : 0.22f;
    const float desired_bottom_ratio = preset == workspace_preset_t::debugging ? 0.30f :
        preset == workspace_preset_t::network ? 0.28f :
        preset == workspace_preset_t::programming ? 0.25f :
        preset == workspace_preset_t::safe ? 0.18f : 0.24f;
    const float scale = dpi_scale > 0.0f ? dpi_scale : 1.0f;
    const float usable_width = (std::max)(size.x, 1.0f);
    const float usable_height = (std::max)(size.y, 1.0f);
    const float center_minimum = (std::min)(480.0f * scale, usable_width * 0.60f);
    const float side_floor = (std::min)(180.0f * scale, usable_width * 0.20f);
    float left_width = (std::max)(usable_width * desired_left_ratio, side_floor);
    float right_width = (std::max)(usable_width * desired_right_ratio, side_floor);
    const float side_budget = (std::max)(0.0f, usable_width - center_minimum);
    const float requested_sides = left_width + right_width;
    if (requested_sides > side_budget && requested_sides > 0.0f) {
        const float contraction = side_budget / requested_sides;
        left_width *= contraction;
        right_width *= contraction;
    }
    layout_ratios_t ratios;
    ratios.left = (std::clamp)(left_width / usable_width, 0.05f, 0.45f);
    const float width_after_left = (std::max)(1.0f, usable_width - left_width);
    ratios.right = (std::clamp)(right_width / width_after_left, 0.05f, 0.55f);
    const float document_height_minimum = (std::min)(300.0f * scale, usable_height * 0.72f);
    const float bottom_floor = (std::min)(140.0f * scale, usable_height * 0.22f);
    const float bottom_height = (std::clamp)(usable_height * desired_bottom_ratio,
        bottom_floor, (std::max)(bottom_floor, usable_height - document_height_minimum));
    ratios.bottom = (std::clamp)(bottom_height / usable_height, 0.08f, 0.45f);
    return ratios;
}

}

const workspace_preset_descriptor_t* presets(std::size_t& count) noexcept
{
    count = kPresetDescriptors.size();
    return kPresetDescriptors.data();
}

}

#if defined(__EMSCRIPTEN__) || defined(AIDA_IMGUI_STUDIO_PREVIEW)

namespace aida::ui::workspace_layout {
namespace {

constexpr std::size_t kPreviewMaximumPayloadBytes = 4U * 1024U * 1024U;
#if defined(IMGUI_HAS_DOCK)
constexpr const char* kPreviewCompatibilityWindowName = "Compatibility IDE###aida.view.shell.compatibility";
#endif

std::size_t preset_index(workspace_preset_t preset) noexcept
{
    return static_cast<std::size_t>(preset);
}

struct preview_state_t {
    bool initialized = false;
    bool root_prepared = false;
    ImGuiID root = 0;
    dock_nodes_t nodes;
    std::string in_memory_layout;
    std::array<std::string, kPresetDescriptors.size()> layouts;
    std::map<std::string, std::string> user_layouts;
    workspace_preset_t active = workspace_preset_t::analysis;
    workspace_preset_t pending = workspace_preset_t::analysis;
    bool locked = false;
    bool rebuild = false;
};

void build_preview_recipe(preview_state_t& current, ImGuiID root_dockspace_id,
    ImVec2 position, ImVec2 size) noexcept;

preview_state_t& preview_state() noexcept
{
    static preview_state_t value;
    return value;
}

void apply_preview_lock(ImGuiDockNode* node, bool locked) noexcept
{
    if (!node)
        return;
    constexpr ImGuiDockNodeFlags flags =
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoDocking) |
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoUndocking) |
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoResize);
    node->SetLocalFlags(locked
        ? static_cast<ImGuiDockNodeFlags>(node->LocalFlags | flags)
        : static_cast<ImGuiDockNodeFlags>(node->LocalFlags & ~flags));
    apply_preview_lock(node->ChildNodes[0], locked);
    apply_preview_lock(node->ChildNodes[1], locked);
}

}

bool initialize(ImGuiID root_dockspace_id) noexcept
{
    preview_state_t& current = preview_state();
    current.initialized = true;
    current.root = root_dockspace_id;
    current.nodes.root = root_dockspace_id;
    return true;
}

void prepare_root(ImGuiID root_dockspace_id, ImVec2 position, ImVec2 size) noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized || current.root != root_dockspace_id)
        return;
#if defined(IMGUI_HAS_DOCK)
    if (!current.root_prepared || current.rebuild) {
        if (!current.rebuild && !current.layouts[preset_index(current.pending)].empty()) {
            const std::string& saved = current.layouts[preset_index(current.pending)];
            ImGui::LoadIniSettingsFromMemory(saved.data(), saved.size());
        } else {
            build_preview_recipe(current, root_dockspace_id, position, size);
        }
        current.active = current.pending;
        current.rebuild = false;
        current.root_prepared = true;
        ImGui::GetIO().WantSaveIniSettings = true;
    }
#else
    static_cast<void>(position);
    static_cast<void>(size);
#endif
    current.root_prepared = true;
    apply_preview_lock(ImGui::DockBuilderGetNode(root_dockspace_id), current.locked);
}

namespace {

void build_preview_recipe(preview_state_t& current, ImGuiID root_dockspace_id,
    ImVec2 position, ImVec2 size) noexcept
{
#if defined(IMGUI_HAS_DOCK)
    const workspace_preset_t preset = current.pending;
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const layout_ratios_t ratios = calculate_layout_ratios(preset, size,
        viewport ? viewport->DpiScale : 1.0f);
    ImGui::DockBuilderRemoveNode(root_dockspace_id);
    ImGui::DockBuilderAddNode(root_dockspace_id,
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_DockSpace) |
            static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_PassthruCentralNode));
    ImGui::DockBuilderSetNodePos(root_dockspace_id, position);
    ImGui::DockBuilderSetNodeSize(root_dockspace_id, size);
    ImGuiID center = root_dockspace_id;
    ImGuiID left = 0;
    ImGuiID right = 0;
    ImGuiID bottom = 0;
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, ratios.left, &left, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, ratios.right, &right, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, ratios.bottom, &bottom, &center);
    ImGui::DockBuilderDockWindow(kPreviewCompatibilityWindowName, center);
    ImGui::DockBuilderFinish(root_dockspace_id);
    current.nodes = {root_dockspace_id, left, center, right, bottom};
#else
    static_cast<void>(current);
    static_cast<void>(root_dockspace_id);
    static_cast<void>(position);
    static_cast<void>(size);
#endif
}

}

ImGuiID node_id(dock_role_t role) noexcept
{
    const dock_nodes_t& nodes = preview_state().nodes;
    switch (role) {
    case dock_role_t::root: return nodes.root;
    case dock_role_t::navigator: return nodes.navigator;
    case dock_role_t::documents: return nodes.documents;
    case dock_role_t::inspector: return nodes.inspector;
    case dock_role_t::bottom: return nodes.bottom;
    default: return 0;
    }
}

void persist_if_requested() noexcept
{
    preview_state_t& current = preview_state();
    if (!current.initialized)
        return;
    ImGuiIO& io = ImGui::GetIO();
    if (!io.WantSaveIniSettings)
        return;
    std::size_t payload_size = 0;
    const char* payload = ImGui::SaveIniSettingsToMemory(&payload_size);
    try {
        if (payload && payload_size <= kPreviewMaximumPayloadBytes &&
            (current.in_memory_layout.size() != payload_size ||
             current.in_memory_layout.compare(0, payload_size, payload, payload_size) != 0))
            current.in_memory_layout.assign(payload, payload_size);
        if (!current.in_memory_layout.empty())
            current.layouts[preset_index(current.active)] = current.in_memory_layout;
    } catch (...) {
        current.in_memory_layout.clear();
    }
    io.WantSaveIniSettings = false;
}


workspace_preset_t active_preset() noexcept { return preview_state().active; }
std::string_view active_preset_name() noexcept { return descriptor_for(active_preset()).display_name; }
bool layout_locked() noexcept { return preview_state().locked; }
void set_layout_locked(bool locked) noexcept
{
    preview_state_t& current = preview_state();
    current.locked = locked;
    apply_preview_lock(ImGui::DockBuilderGetNode(current.root), locked);
}

workspace_request_result_t switch_to(workspace_preset_t preset) noexcept
{
    preview_state_t& current = preview_state();
    if (current.active == preset && !current.rebuild)
        return workspace_request_result_t::unchanged;
    persist_if_requested();
    current.pending = preset;
    current.rebuild = current.layouts[preset_index(preset)].empty();
    current.root_prepared = false;
    return workspace_request_result_t::completed;
}

workspace_request_result_t save_user_layout(std::string_view name) noexcept
{
    if (name.empty() || name.size() > 64)
        return workspace_request_result_t::invalid_name;
    ImGui::GetIO().WantSaveIniSettings = true;
    persist_if_requested();
    preview_state_t& current = preview_state();
    try {
        current.user_layouts[std::string(name)] = current.in_memory_layout;
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    return workspace_request_result_t::completed;
}

workspace_request_result_t load_user_layout(std::string_view name) noexcept
{
    if (name.empty() || name.size() > 64)
        return workspace_request_result_t::invalid_name;
    preview_state_t& current = preview_state();
    try {
        const auto found = current.user_layouts.find(std::string(name));
        if (found == current.user_layouts.end())
            return workspace_request_result_t::unavailable;
        ImGui::LoadIniSettingsFromMemory(found->second.data(), found->second.size());
        current.in_memory_layout = found->second;
        current.root_prepared = true;
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    return workspace_request_result_t::completed;
}

workspace_request_result_t restore_builtin(workspace_preset_t preset) noexcept
{
    preview_state_t& current = preview_state();
    current.layouts[preset_index(preset)].clear();
    current.pending = preset;
    current.rebuild = true;
    current.root_prepared = false;
    return workspace_request_result_t::completed;
}

workspace_request_result_t reset_current() noexcept { return restore_builtin(active_preset()); }

workspace_request_result_t reset_all() noexcept
{
    preview_state_t& current = preview_state();
    for (auto& layout : current.layouts)
        layout.clear();
    return restore_builtin(workspace_preset_t::analysis);
}

workspace_request_result_t activate_safe_layout() noexcept
{
    return restore_builtin(workspace_preset_t::safe);
}

workspace_request_result_t open_missing_views() noexcept
{
    preview_state_t& current = preview_state();
    current.rebuild = true;
    current.root_prepared = false;
    return workspace_request_result_t::completed;
}

void shutdown() noexcept
{
    preview_state() = {};
}

}

#else

#if !defined(AIDA_IMGUI_SOURCE_SHA256)
#error AIDA_IMGUI_SOURCE_SHA256 must identify the audited vendored Dear ImGui source
#endif

#include "core/infra/executor.hpp"
#include "helpers/diag_log.hpp"

#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace aida::ui::workspace_layout {
namespace {

constexpr std::uint32_t kSchemaVersion = 2;
constexpr std::size_t kMaximumPayloadBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaximumContainerBytes = kMaximumPayloadBytes + 1024U;
constexpr std::string_view kMagic = "AIDA_WORKSPACE_LAYOUT\r\n";
constexpr std::string_view kHeaderTerminator = "\r\n\r\n";
constexpr std::string_view kImguiSourceFingerprint = AIDA_IMGUI_SOURCE_SHA256;
constexpr const char* kCompatibilityWindowName = "Compatibility IDE###aida.view.shell.compatibility";

enum class read_result_t {
    absent,
    io_failure,
    invalid,
    valid
};

struct state_t {
    bool initialized = false;
    bool needs_default = false;
    bool root_prepared = false;
    bool recovered_from_backup = false;
    bool preserve_recovery_backup = false;
    bool persistence_available = false;
    ImGuiID expected_root = 0;
    workspace_preset_t active = workspace_preset_t::analysis;
    workspace_preset_t pending = workspace_preset_t::analysis;
    bool rebuild_requested = false;
    bool locked = false;
    ImVec2 last_position{0.0f, 0.0f};
    ImVec2 last_size{0.0f, 0.0f};
    ImVec2 rehome_work_position{0.0f, 0.0f};
    ImVec2 rehome_work_size{0.0f, 0.0f};
    float rehome_dpi_scale = 0.0f;
    bool rehome_initialized = false;
    std::uint64_t next_save_attempt_ms = 0;
    std::uint64_t generation = 0;
    dock_nodes_t nodes;
    std::filesystem::path directory;
    std::filesystem::path primary;
    std::filesystem::path backup;
    std::filesystem::path invalid;
    std::filesystem::path active_record;
    std::filesystem::path legacy_primary;
};

struct layout_paths_t {
    std::filesystem::path directory;
    std::filesystem::path primary;
    std::filesystem::path backup;
    std::filesystem::path invalid;
};

struct record_metadata_t {
    std::uint64_t generation = 0;
    bool clean_shutdown = false;
    dock_nodes_t nodes;
    workspace_preset_t preset = workspace_preset_t::analysis;
    bool locked = false;
};

state_t& state() noexcept
{
    static state_t value;
    return value;
}

dock_nodes_t resolved_nodes(const state_t& current) noexcept
{
    dock_nodes_t nodes = current.nodes;
    nodes.root = current.expected_root;
    const auto resolve = [root = nodes.root](ImGuiID candidate) noexcept {
        return candidate != 0 && ImGui::DockBuilderGetNode(candidate) != nullptr
            ? candidate
            : root;
    };
    nodes.navigator = resolve(nodes.navigator);
    nodes.documents = resolve(nodes.documents);
    nodes.inspector = resolve(nodes.inspector);
    nodes.bottom = resolve(nodes.bottom);
    return nodes;
}

std::mutex& write_mutex() noexcept
{
    static std::mutex value;
    return value;
}

std::atomic<std::uint64_t>& committed_generation() noexcept
{
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::atomic<std::uint64_t>& failed_generation() noexcept
{
    static std::atomic<std::uint64_t> value{0};
    return value;
}

std::uint64_t fnv1a64(std::string_view value) noexcept
{
    std::uint64_t hash = 14695981039346656037ULL;
    for (const unsigned char byte : value) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool parse_decimal(std::string_view value, std::uint64_t& output) noexcept
{
    if (value.empty())
        return false;
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size())
        return false;
    output = parsed;
    return true;
}

bool parse_hex(std::string_view value, std::uint64_t& output) noexcept
{
    if (value.empty())
        return false;
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 16);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size())
        return false;
    output = parsed;
    return true;
}

bool select_preset_paths(state_t& current, workspace_preset_t preset) noexcept
{
    try {
        const std::string_view id = descriptor_for(preset).stable_id;
        const std::wstring wide_id(id.begin(), id.end());
        current.primary = current.directory / (wide_id + L".aida-layout");
        current.backup = current.directory / (wide_id + L".aida-layout.bak");
        current.invalid = current.directory / (wide_id + L".aida-layout.invalid");
        return true;
    } catch (...) {
        return false;
    }
}

bool assign_paths(state_t& current) noexcept
{
    PWSTR roaming = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_CREATE, nullptr, &roaming);
    if (FAILED(result) || !roaming)
        return false;
    try {
        current.directory = std::filesystem::path(roaming) / L"AiDA" / L"Standalone" / L"workspaces";
        current.active_record = current.directory / L"active-workspace-v2.txt";
        current.legacy_primary = current.directory / L"standalone-layout-v1.aida-layout";
        if (!select_preset_paths(current, current.active))
            return false;
    } catch (...) {
        CoTaskMemFree(roaming);
        return false;
    }
    CoTaskMemFree(roaming);
    return true;
}

void load_active_workspace_record(state_t& current) noexcept
{
    HANDLE file = CreateFileW(current.active_record.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return;
    char value[64]{};
    DWORD read = 0;
    const bool valid = ReadFile(file, value, sizeof(value) - 1U, &read, nullptr) != FALSE;
    CloseHandle(file);
    if (!valid || read == 0 || read >= sizeof(value))
        return;
    const std::string_view record(value, read);
    const std::size_t separator = record.find('\n');
    const std::string_view id = record.substr(0, separator);
    current.locked = separator != std::string_view::npos &&
        separator + 1U < record.size() && record[separator + 1U] == '1';
    for (const auto& descriptor : kPresetDescriptors) {
        if (id == descriptor.stable_id) {
            current.active = descriptor.id;
            current.pending = descriptor.id;
            if (!select_preset_paths(current, descriptor.id))
                return;
            return;
        }
    }
}

bool save_active_workspace_record(const state_t& current) noexcept
{
    std::error_code error;
    std::filesystem::create_directories(current.directory, error);
    if (error)
        return false;
    std::filesystem::path temporary = current.active_record;
    temporary += L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    std::string record;
    try {
        record = std::string(descriptor_for(current.active).stable_id) +
            (current.locked ? "\n1" : "\n0");
    } catch (...) {
        CloseHandle(file);
        DeleteFileW(temporary.c_str());
        return false;
    }
    DWORD written = 0;
    const bool saved = WriteFile(file, record.data(), static_cast<DWORD>(record.size()), &written, nullptr) != FALSE &&
        written == record.size() && FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (!saved || !MoveFileExW(temporary.c_str(), current.active_record.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}

bool read_file_bounded(const std::filesystem::path& path, std::vector<char>& output, read_result_t& result) noexcept
{
    result = read_result_t::io_failure;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        result = GetLastError() == ERROR_FILE_NOT_FOUND ? read_result_t::absent : read_result_t::io_failure;
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        static_cast<unsigned long long>(size.QuadPart) > kMaximumContainerBytes) {
        CloseHandle(file);
        result = read_result_t::invalid;
        return false;
    }

    try {
        output.resize(static_cast<std::size_t>(size.QuadPart));
    } catch (...) {
        CloseHandle(file);
        result = read_result_t::io_failure;
        return false;
    }

    std::size_t offset = 0;
    while (offset < output.size()) {
        const DWORD requested = static_cast<DWORD>((std::min)(output.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD completed = 0;
        if (!ReadFile(file, output.data() + offset, requested, &completed, nullptr) || completed == 0) {
            CloseHandle(file);
            output.clear();
            result = read_result_t::io_failure;
            return false;
        }
        offset += completed;
    }
    CloseHandle(file);
    result = read_result_t::valid;
    return true;
}

bool extract_payload(const std::vector<char>& container, ImGuiID expected_root,
    std::string_view& payload, record_metadata_t* metadata) noexcept
{
    const std::string_view input(container.data(), container.size());
    if (input.size() < kMagic.size() || input.substr(0, kMagic.size()) != kMagic)
        return false;
    const std::size_t terminator = input.find(kHeaderTerminator, kMagic.size());
    if (terminator == std::string_view::npos || terminator > 768U)
        return false;

    std::uint64_t schema = 0;
    std::uint64_t payload_bytes = 0;
    std::uint64_t checksum = 0;
    std::uint64_t generation = 0;
    std::uint64_t clean_shutdown = 0;
    std::uint64_t node_root = 0;
    std::uint64_t node_navigator = 0;
    std::uint64_t node_documents = 0;
    std::uint64_t node_inspector = 0;
    std::uint64_t node_bottom = 0;
    bool schema_seen = false;
    bool bytes_seen = false;
    bool checksum_seen = false;
    bool imgui_seen = false;
    bool imgui_source_seen = false;
    bool preset_seen = false;
    workspace_preset_t parsed_preset = workspace_preset_t::analysis;
    bool preset_revision_seen = false;
    bool registry_seen = false;
    bool generation_seen = false;
    bool clean_seen = false;
    bool lock_seen = false;
    std::uint64_t layout_locked = 0;
    bool node_root_seen = false;
    bool node_navigator_seen = false;
    bool node_documents_seen = false;
    bool node_inspector_seen = false;
    bool node_bottom_seen = false;
    std::size_t cursor = kMagic.size();
    while (cursor < terminator) {
        const std::size_t line_end = input.find("\r\n", cursor);
        if (line_end == std::string_view::npos || line_end > terminator)
            return false;
        const std::string_view line = input.substr(cursor, line_end - cursor);
        const std::size_t separator = line.find('=');
        if (separator == std::string_view::npos)
            return false;
        const std::string_view key = line.substr(0, separator);
        const std::string_view value = line.substr(separator + 1U);
        if (key == "schema") {
            if (schema_seen || !parse_decimal(value, schema))
                return false;
            schema_seen = true;
        } else if (key == "payload_bytes") {
            if (bytes_seen || !parse_decimal(value, payload_bytes))
                return false;
            bytes_seen = true;
        } else if (key == "payload_fnv1a64") {
            if (checksum_seen || !parse_hex(value, checksum))
                return false;
            checksum_seen = true;
        } else if (key == "imgui_version") {
            if (imgui_seen || value != IMGUI_VERSION)
                return false;
            imgui_seen = true;
        } else if (key == "imgui_source_sha256") {
            if (imgui_source_seen || value != kImguiSourceFingerprint)
                return false;
            imgui_source_seen = true;
        } else if (key == "preset_id") {
            if (preset_seen)
                return false;
            bool recognized = false;
            for (const auto& descriptor : kPresetDescriptors) {
                if (value == descriptor.stable_id) {
                    parsed_preset = descriptor.id;
                    recognized = true;
                    break;
                }
            }
            if (!recognized)
                return false;
            preset_seen = true;
        } else if (key == "preset_revision") {
            std::uint64_t preset_revision = 0;
            if (preset_revision_seen || !parse_decimal(value, preset_revision) ||
                (preset_revision != 1 && preset_revision != 2))
                return false;
            preset_revision_seen = true;
        } else if (key == "view_registry") {
            if (registry_seen || (value != "compatibility-v1" && value != "stable-v2"))
                return false;
            registry_seen = true;
        } else if (key == "generation") {
            if (generation_seen || !parse_decimal(value, generation) || generation == 0)
                return false;
            generation_seen = true;
        } else if (key == "clean_shutdown") {
            if (clean_seen || !parse_decimal(value, clean_shutdown) || clean_shutdown > 1)
                return false;
            clean_seen = true;
        } else if (key == "layout_locked") {
            if (lock_seen || !parse_decimal(value, layout_locked) || layout_locked > 1)
                return false;
            lock_seen = true;
        } else if (key == "node_root") {
            if (node_root_seen || !parse_hex(value, node_root))
                return false;
            node_root_seen = true;
        } else if (key == "node_navigator") {
            if (node_navigator_seen || !parse_hex(value, node_navigator))
                return false;
            node_navigator_seen = true;
        } else if (key == "node_documents") {
            if (node_documents_seen || !parse_hex(value, node_documents))
                return false;
            node_documents_seen = true;
        } else if (key == "node_inspector") {
            if (node_inspector_seen || !parse_hex(value, node_inspector))
                return false;
            node_inspector_seen = true;
        } else if (key == "node_bottom") {
            if (node_bottom_seen || !parse_hex(value, node_bottom))
                return false;
            node_bottom_seen = true;
        } else {
            return false;
        }
        cursor = line_end + 2U;
    }

    const std::size_t payload_offset = terminator + kHeaderTerminator.size();
    if (!schema_seen || !bytes_seen || !checksum_seen || !imgui_seen || !imgui_source_seen || !preset_seen ||
        !preset_revision_seen || !registry_seen || !generation_seen || !clean_seen ||
        !node_root_seen || !node_navigator_seen || !node_documents_seen ||
        !node_inspector_seen || !node_bottom_seen ||
        (schema != 1 && schema != kSchemaVersion) ||
        payload_bytes == 0 || payload_bytes > kMaximumPayloadBytes ||
        payload_offset > input.size() || payload_bytes != input.size() - payload_offset)
        return false;

    payload = input.substr(payload_offset, static_cast<std::size_t>(payload_bytes));
    if (payload.find('\0') != std::string_view::npos || fnv1a64(payload) != checksum ||
        payload.find("[Docking][Data]") == std::string_view::npos)
        return false;

    const std::uint64_t maximum_id = static_cast<std::uint64_t>((std::numeric_limits<ImGuiID>::max)());
    const bool roles_valid = node_root == expected_root && node_root <= maximum_id &&
        node_navigator != 0 && node_navigator <= maximum_id &&
        node_documents != 0 && node_documents <= maximum_id &&
        node_inspector != 0 && node_inspector <= maximum_id &&
        node_bottom != 0 && node_bottom <= maximum_id &&
        node_root != node_navigator && node_root != node_documents &&
        node_root != node_inspector && node_root != node_bottom &&
        node_navigator != node_documents && node_navigator != node_inspector &&
        node_navigator != node_bottom && node_documents != node_inspector &&
        node_documents != node_bottom && node_inspector != node_bottom;
    if (!roles_valid)
        return false;

    const std::size_t docking_start = payload.find("[Docking][Data]");
    const std::size_t next_section = payload.find("\n[", docking_start + 1U);
    const std::string_view docking_data = next_section == std::string_view::npos
        ? payload.substr(docking_start)
        : payload.substr(docking_start, next_section - docking_start);
    const auto contains_node = [docking_data](std::uint64_t raw_id) noexcept {
        char token[32]{};
        const int length = std::snprintf(token, sizeof(token), "ID=0x%08X",
            static_cast<ImGuiID>(raw_id));
        return length > 0 && static_cast<std::size_t>(length) < sizeof(token) &&
            docking_data.find(std::string_view(token, static_cast<std::size_t>(length))) != std::string_view::npos;
    };
    if (!contains_node(node_root) || !contains_node(node_navigator) ||
        !contains_node(node_documents) || !contains_node(node_inspector) ||
        !contains_node(node_bottom))
        return false;

    if (metadata) {
        metadata->generation = generation;
        metadata->clean_shutdown = clean_shutdown != 0;
        metadata->nodes = {
            static_cast<ImGuiID>(node_root),
            static_cast<ImGuiID>(node_navigator),
            static_cast<ImGuiID>(node_documents),
            static_cast<ImGuiID>(node_inspector),
            static_cast<ImGuiID>(node_bottom)};
        metadata->preset = parsed_preset;
        metadata->locked = layout_locked != 0;
    }
    return true;
}

read_result_t load_layout_file(const std::filesystem::path& path, ImGuiID expected_root,
    record_metadata_t& metadata) noexcept
{
    std::vector<char> container;
    read_result_t result = read_result_t::io_failure;
    if (!read_file_bounded(path, container, result))
        return result;
    std::string_view payload;
    if (!extract_payload(container, expected_root, payload, &metadata))
        return read_result_t::invalid;
    ImGui::LoadIniSettingsFromMemory(payload.data(), payload.size());
    return read_result_t::valid;
}

bool validate_layout_file(const std::filesystem::path& path, ImGuiID expected_root) noexcept
{
    std::vector<char> container;
    read_result_t result = read_result_t::io_failure;
    if (!read_file_bounded(path, container, result))
        return false;
    std::string_view payload;
    return extract_payload(container, expected_root, payload, nullptr);
}

bool inspect_layout_file(const std::filesystem::path& path, ImGuiID expected_root,
    record_metadata_t& metadata) noexcept
{
    std::vector<char> container;
    read_result_t result = read_result_t::io_failure;
    if (!read_file_bounded(path, container, result))
        return false;
    std::string_view payload;
    return extract_payload(container, expected_root, payload, &metadata);
}

bool write_all(HANDLE file, std::string_view data) noexcept
{
    std::size_t offset = 0;
    while (offset < data.size()) {
        const DWORD requested = static_cast<DWORD>((std::min)(data.size() - offset,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD completed = 0;
        if (!WriteFile(file, data.data() + offset, requested, &completed, nullptr) || completed == 0)
            return false;
        offset += completed;
    }
    return true;
}

bool refresh_backup_atomic(const layout_paths_t& paths) noexcept
{
    std::filesystem::path temporary;
    try {
        temporary = paths.backup;
        temporary += L".tmp";
    } catch (...) {
        return false;
    }
    DeleteFileW(temporary.c_str());
    if (!CopyFileW(paths.primary.c_str(), temporary.c_str(), TRUE))
        return false;
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    const bool flushed = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (!flushed || !MoveFileExW(temporary.c_str(), paths.backup.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}

bool save_payload(const layout_paths_t& paths, ImGuiID expected_root, std::string_view payload,
    std::uint64_t generation, bool clean_shutdown, bool skip_backup,
    const dock_nodes_t& nodes, workspace_preset_t preset, bool locked)
{
    if (payload.empty() || payload.size() > kMaximumPayloadBytes || generation == 0 ||
        payload.find("[Docking][Data]") == std::string_view::npos)
        return false;

    std::error_code directory_error;
    std::filesystem::create_directories(paths.directory, directory_error);
    if (directory_error)
        return false;

    char header[768]{};
    const int header_length = std::snprintf(header, sizeof(header),
        "AIDA_WORKSPACE_LAYOUT\r\nschema=%u\r\nimgui_version=%s\r\nimgui_source_sha256=%.*s\r\npreset_id=%.*s\r\npreset_revision=2\r\nview_registry=stable-v2\r\ngeneration=%llu\r\nclean_shutdown=%u\r\nlayout_locked=%u\r\nnode_root=%08X\r\nnode_navigator=%08X\r\nnode_documents=%08X\r\nnode_inspector=%08X\r\nnode_bottom=%08X\r\npayload_bytes=%llu\r\npayload_fnv1a64=%016llx\r\n\r\n",
        kSchemaVersion,
        IMGUI_VERSION,
        static_cast<int>(kImguiSourceFingerprint.size()), kImguiSourceFingerprint.data(),
        static_cast<int>(descriptor_for(preset).stable_id.size()), descriptor_for(preset).stable_id.data(),
        static_cast<unsigned long long>(generation),
        clean_shutdown ? 1U : 0U,
        locked ? 1U : 0U,
        nodes.root, nodes.navigator, nodes.documents, nodes.inspector, nodes.bottom,
        static_cast<unsigned long long>(payload.size()),
        static_cast<unsigned long long>(fnv1a64(payload)));
    if (header_length <= 0 || static_cast<std::size_t>(header_length) >= sizeof(header))
        return false;

    std::filesystem::path temporary = paths.primary;
    temporary += L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    const bool wrote = write_all(file, std::string_view(header, static_cast<std::size_t>(header_length))) &&
        write_all(file, payload) && FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (!wrote) {
        DeleteFileW(temporary.c_str());
        return false;
    }

    if (!skip_backup && GetFileAttributesW(paths.primary.c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (validate_layout_file(paths.primary, expected_root)) {
            if (!refresh_backup_atomic(paths)) {
                DeleteFileW(temporary.c_str());
                return false;
            }
        } else if (!MoveFileExW(paths.primary.c_str(), paths.invalid.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFileW(temporary.c_str());
            return false;
        }
    }
    if (!MoveFileExW(temporary.c_str(), paths.primary.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}

layout_paths_t capture_paths(const state_t& current)
{
    return {current.directory, current.primary, current.backup, current.invalid};
}

bool write_generation(const layout_paths_t& paths, ImGuiID expected_root,
    std::string_view payload, std::uint64_t generation, bool clean_shutdown,
    bool skip_backup, const dock_nodes_t& nodes, workspace_preset_t preset, bool locked) noexcept
{
    std::lock_guard<std::mutex> lock(write_mutex());
    if (generation <= committed_generation().load(std::memory_order_acquire))
        return true;
    const std::uint64_t started_ms = static_cast<std::uint64_t>(GetTickCount64());
    bool saved = false;
    try {
        saved = save_payload(paths, expected_root, payload, generation, clean_shutdown, skip_backup, nodes, preset, locked);
    } catch (...) {
        saved = false;
    }
    if (saved)
        committed_generation().store(generation, std::memory_order_release);
    else
        failed_generation().store(generation, std::memory_order_release);
    diag::log_tagged_fmt("workspace_layout",
        "layout_write_complete generation=%llu clean_shutdown=%d payload_bytes=%llu payload_fnv1a64=%016llx elapsed_ms=%llu result=%s",
        static_cast<unsigned long long>(generation), clean_shutdown ? 1 : 0,
        static_cast<unsigned long long>(payload.size()),
        static_cast<unsigned long long>(fnv1a64(payload)),
        static_cast<unsigned long long>(static_cast<std::uint64_t>(GetTickCount64()) - started_ms),
        saved ? "saved" : "failed");
    return saved;
}

bool queue_write(const layout_paths_t& paths, ImGuiID expected_root,
    std::string_view payload, std::uint64_t generation, bool skip_backup,
    const dock_nodes_t& nodes, workspace_preset_t preset, bool locked)
{
    auto immutable_payload = std::make_shared<const std::string>(payload);
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "workspace_layout";
    submission.label = "workspace_layout_atomic_save";
    submission.thread_class = "diagnostics_io";
    submission.domain = aida::infra::executor::domain_t::diagnostics;
    submission.priority = 1;
    submission.generation = generation;
    submission.diagnostic_id = "workspace_layout.save";
    submission.ui_access_policy = "none";
    submission.failure_policy = "retain_last_known_good";
    submission.shutdown_policy = "drain";
    submission.body = [paths, expected_root, immutable_payload, generation, skip_backup, nodes, preset, locked]() {
        write_generation(paths, expected_root, *immutable_payload, generation, false, skip_backup, nodes, preset, locked);
    };
    return aida::infra::executor::submit(std::move(submission)).submitted;
}

void dock_named_windows(workspace_preset_t preset, ImGuiID left, ImGuiID center,
    ImGuiID right, ImGuiID bottom, bool missing_only = false) noexcept
{
    const auto dock = [missing_only](ImGuiID node, std::initializer_list<const char*> stable_ids) {
        for (const char* stable_id : stable_ids) {
            const std::string window_name = application_views::ensure_window_name(
                stable_view_id_t(stable_id));
            if (window_name.empty())
                continue;
            ImGuiWindow* window = ImGui::FindWindowByName(window_name.c_str());
            if (!missing_only || !window || window->DockId == 0)
                ImGui::DockBuilderDockWindow(window_name.c_str(), node);
        }
    };
    ImGuiWindow* compatibility = ImGui::FindWindowByName(kCompatibilityWindowName);
    if (!missing_only || !compatibility || compatibility->DockId == 0)
        ImGui::DockBuilderDockWindow(kCompatibilityWindowName, center);
    if (preset == workspace_preset_t::analysis) {
        dock(left, {"view.project_explorer", "view.analysis.functions"});
        dock(center, {"document.disassembly", "document.pseudocode", "document.graph", "document.hex", "document.code"});
        dock(right, {"view.analysis.references", "view.analysis.binary_map"});
        dock(bottom, {"view.output", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::debugging) {
        dock(left, {"view.debug.threads", "view.debug.modules", "view.debug.call_stack"});
        dock(center, {"view.debug.cpu", "document.code", "document.hex", "view.debug.cfg"});
        dock(right, {"view.debug.breakpoints", "view.debug.watches"});
        dock(bottom, {"view.debug.memory_map", "view.debug.trace", "view.debug.patches", "view.debug.seh", "view.debug.handles", "view.terminal", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::memory) {
        dock(left, {"view.memory.value_scan", "view.memory.crypto", "view.memory.aob"});
        dock(center, {"document.hex", "view.memory.pointers", "view.memory.snapshots"});
        dock(right, {"view.debug.memory_map", "view.types.dissector"});
        dock(bottom, {"view.debug.patches", "view.debug.watches", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::types_structures) {
        dock(left, {"view.types.structures", "view.types.unions", "view.types.enums", "view.types.typedefs", "view.types.functions", "view.types.inferred"});
        dock(center, {"view.types.struct_recon", "document.code", "document.hex"});
        dock(right, {"view.types.dissector"});
        dock(bottom, {"view.analysis.references", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::network) {
        dock(left, {"view.network.site_map", "view.network.scope", "view.network.cookies", "view.network.session"});
        dock(center, {"view.network.proxy", "view.network.intercept", "view.network.repeater", "view.network.browser", "view.network.api"});
        dock(right, {"view.network.decoder", "view.network.comparer", "view.network.scanner", "view.network.reports"});
        dock(bottom, {"view.network.capture", "view.network.logger", "view.network.websocket", "view.network.h2_editor", "view.background_tasks", "view.diagnostics"});
    } else if (preset == workspace_preset_t::automation_ai) {
        dock(left, {"view.ai.agents", "view.ai.skills", "view.project_explorer"});
        dock(center, {"view.ai_chat", "document.code"});
        dock(right, {"view.settings"});
        dock(bottom, {"view.background_tasks", "view.mcp_log", "view.output", "view.terminal", "view.diagnostics"});
    } else if (preset == workspace_preset_t::programming) {
        dock(left, {"view.project_explorer", "view.workspace_search"});
        dock(center, {"document.code", "document.disassembly", "document.pseudocode"});
        dock(right, {"view.analysis.references", "view.ai_chat"});
        dock(bottom, {"view.output", "view.terminal", "view.background_tasks", "view.diagnostics"});
    } else {
        dock(left, {"view.project_explorer", "view.recent"});
        dock(center, {"document.code"});
        dock(right, {"view.ai_chat"});
        dock(bottom, {"view.diagnostics", "view.output"});
    }
}

void build_default_layout(ImGuiID root_dockspace_id, ImVec2 position, ImVec2 size,
    workspace_preset_t preset) noexcept
{
    ImGui::DockBuilderRemoveNode(root_dockspace_id);
    ImGui::DockBuilderAddNode(root_dockspace_id,
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_DockSpace) |
            static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_PassthruCentralNode));
    ImGui::DockBuilderSetNodePos(root_dockspace_id, position);
    ImGui::DockBuilderSetNodeSize(root_dockspace_id, size);

    ImGuiID center = root_dockspace_id;
    ImGuiID left = 0;
    ImGuiID right = 0;
    ImGuiID bottom = 0;
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const layout_ratios_t ratios = calculate_layout_ratios(preset, size,
        viewport ? viewport->DpiScale : 1.0f);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, ratios.left, &left, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, ratios.right, &right, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, ratios.bottom, &bottom, &center);
    dock_named_windows(preset, left, center, right, bottom);
    ImGui::DockBuilderFinish(root_dockspace_id);
    state().nodes = {root_dockspace_id, left, center, right, bottom};
    ImGui::GetIO().WantSaveIniSettings = true;
}

void apply_lock_recursive(ImGuiDockNode* node, bool locked) noexcept
{
    if (!node)
        return;
    constexpr ImGuiDockNodeFlags flags =
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoDocking) |
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoUndocking) |
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoResize);
    node->SetLocalFlags(locked
        ? static_cast<ImGuiDockNodeFlags>(node->LocalFlags | flags)
        : static_cast<ImGuiDockNodeFlags>(node->LocalFlags & ~flags));
    apply_lock_recursive(node->ChildNodes[0], locked);
    apply_lock_recursive(node->ChildNodes[1], locked);
}

void rehome_floating_windows() noexcept
{
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGuiContext* context = ImGui::GetCurrentContext();
    if (!viewport || !context)
        return;
    const float scale = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
    const float visible_width = 96.0f * scale;
    const float visible_height = 28.0f * scale;
    const ImVec2 work_min = viewport->WorkPos;
    const ImVec2 work_max(viewport->WorkPos.x + viewport->WorkSize.x,
        viewport->WorkPos.y + viewport->WorkSize.y);
    for (ImGuiWindow* window : context->Windows) {
        if (!window || !window->WasActive || window->DockId != 0 ||
            (window->Flags & (ImGuiWindowFlags_ChildWindow | ImGuiWindowFlags_Popup |
                ImGuiWindowFlags_Tooltip | ImGuiWindowFlags_NoSavedSettings)) != 0)
            continue;
        const float minimum_x = work_min.x - (std::max)(0.0f, window->SizeFull.x - visible_width);
        const float maximum_x = work_max.x - (std::min)(visible_width, window->SizeFull.x);
        const float minimum_y = work_min.y;
        const float maximum_y = work_max.y - (std::min)(visible_height, window->SizeFull.y);
        const ImVec2 clamped(
            std::clamp(window->Pos.x, minimum_x, (std::max)(minimum_x, maximum_x)),
            std::clamp(window->Pos.y, minimum_y, (std::max)(minimum_y, maximum_y)));
        if (clamped.x != window->Pos.x || clamped.y != window->Pos.y)
            ImGui::SetWindowPos(window, clamped, ImGuiCond_Always);
    }
}

bool valid_user_layout_name(std::string_view name) noexcept
{
    if (name.empty() || name.size() > 64)
        return false;
    for (const unsigned char character : name) {
        if (!(character >= 'a' && character <= 'z') &&
            !(character >= 'A' && character <= 'Z') &&
            !(character >= '0' && character <= '9') &&
            character != '-' && character != '_' && character != ' ')
            return false;
    }
    return true;
}

std::filesystem::path user_layout_path(const state_t& current, std::string_view name)
{
    std::wstring wide(name.begin(), name.end());
    for (wchar_t& character : wide) {
        if (character == L' ')
            character = L'_';
    }
    return current.directory / L"user" / (wide + L".aida-layout");
}

bool save_current_synchronously(state_t& current, const layout_paths_t& paths,
    bool clean_shutdown) noexcept
{
    if (!current.root_prepared || !current.persistence_available)
        return true;
    std::size_t payload_size = 0;
    const char* payload = ImGui::SaveIniSettingsToMemory(&payload_size);
    current.nodes = resolved_nodes(current);
    if (!payload)
        return false;
    const std::uint64_t generation = (std::max)(current.generation,
        committed_generation().load(std::memory_order_acquire)) + 1ULL;
    const bool saved = write_generation(paths, current.expected_root,
        std::string_view(payload, payload_size), generation, clean_shutdown,
        current.recovered_from_backup || current.preserve_recovery_backup,
        current.nodes, current.active, current.locked);
    if (saved)
        current.generation = generation;
    return saved;
}

}

bool initialize(ImGuiID root_dockspace_id) noexcept
{
    state_t& current = state();
    if (current.initialized)
        return true;
    current.expected_root = root_dockspace_id;
    current.nodes.root = root_dockspace_id;
    current.needs_default = true;
    current.root_prepared = false;
    if (!assign_paths(current)) {
        diag::log_tagged_critical("workspace_layout", "persistence_path_unavailable");
        current.initialized = true;
        return false;
    }
    load_active_workspace_record(current);
    current.persistence_available = true;

    record_metadata_t loaded_metadata;
    read_result_t primary_result = load_layout_file(current.primary, root_dockspace_id, loaded_metadata);
    bool migrated_legacy = false;
    if (primary_result == read_result_t::absent && current.active == workspace_preset_t::analysis) {
        primary_result = load_layout_file(current.legacy_primary, root_dockspace_id, loaded_metadata);
        migrated_legacy = primary_result == read_result_t::valid;
    }
    if (primary_result == read_result_t::valid && loaded_metadata.preset != current.active)
        primary_result = read_result_t::invalid;
    if (primary_result == read_result_t::valid) {
        current.active = loaded_metadata.preset;
        current.pending = loaded_metadata.preset;
        current.needs_default = false;
        current.generation = loaded_metadata.generation;
        current.nodes = loaded_metadata.nodes;
        current.locked = loaded_metadata.locked;
        committed_generation().store(current.generation, std::memory_order_release);
        if (!loaded_metadata.clean_shutdown) {
            record_metadata_t recovery_metadata;
            const bool recovery_available = inspect_layout_file(
                current.backup, root_dockspace_id, recovery_metadata);
            current.preserve_recovery_backup = recovery_available;
            diag::log_tagged_critical_fmt("workspace_layout",
                "layout_unclean_start policy=use_valid_primary_preserve_last_good recovery_available=%d recovery_generation=%llu recovery_clean=%d",
                recovery_available ? 1 : 0,
                static_cast<unsigned long long>(recovery_metadata.generation),
                recovery_available && recovery_metadata.clean_shutdown ? 1 : 0);
        }
        ImGui::GetIO().WantSaveIniSettings = true;
        diag::log_tagged_fmt("workspace_layout",
            "layout_loaded source=%s schema=%u generation=%llu clean_shutdown=%d",
            migrated_legacy ? "legacy" : "primary",
            kSchemaVersion,
            static_cast<unsigned long long>(current.generation), loaded_metadata.clean_shutdown ? 1 : 0);
    } else {
        if (primary_result == read_result_t::invalid)
            MoveFileExW(current.primary.c_str(), current.invalid.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        record_metadata_t backup_metadata;
        read_result_t backup_result = load_layout_file(current.backup, root_dockspace_id, backup_metadata);
        if (backup_result == read_result_t::valid && backup_metadata.preset != current.active)
            backup_result = read_result_t::invalid;
        if (backup_result == read_result_t::valid) {
            current.active = backup_metadata.preset;
            current.pending = backup_metadata.preset;
            current.needs_default = false;
            current.recovered_from_backup = true;
            current.generation = backup_metadata.generation;
            current.nodes = backup_metadata.nodes;
            current.locked = backup_metadata.locked;
            committed_generation().store(current.generation, std::memory_order_release);
            ImGui::GetIO().WantSaveIniSettings = true;
            diag::log_tagged_critical_fmt("workspace_layout",
                "layout_recovered source=backup schema=%u generation=%llu clean_shutdown=%d",
                kSchemaVersion,
                static_cast<unsigned long long>(current.generation), backup_metadata.clean_shutdown ? 1 : 0);
        } else if (primary_result != read_result_t::absent || backup_result != read_result_t::absent) {
            current.active = workspace_preset_t::safe;
            current.pending = workspace_preset_t::safe;
            if (!select_preset_paths(current, current.active))
                current.persistence_available = false;
            diag::log_tagged_critical_fmt("workspace_layout",
                "layout_recovery_safe primary_result=%u backup_result=%u",
                static_cast<unsigned>(primary_result), static_cast<unsigned>(backup_result));
        } else {
            diag::log_tagged_fmt("workspace_layout", "layout_first_run_default schema=%u", kSchemaVersion);
        }
    }
    current.initialized = true;
    return true;
}

void prepare_root(ImGuiID root_dockspace_id, ImVec2 position, ImVec2 size) noexcept
{
    state_t& current = state();
    if (!current.initialized || current.expected_root != root_dockspace_id)
        return;
    current.last_position = position;
    current.last_size = ImVec2((std::max)(size.x, 320.0f), (std::max)(size.y, 240.0f));
    if (!current.root_prepared) {
        if (current.needs_default || ImGui::DockBuilderGetNode(root_dockspace_id) == nullptr) {
            const bool recovery = !current.needs_default;
            build_default_layout(root_dockspace_id, position, size, current.pending);
            current.active = current.pending;
            current.rebuild_requested = false;
            current.needs_default = false;
            diag::log_tagged_fmt("workspace_layout",
                "layout_builder_applied_once root=0x%08X reason=%s work_size=%.0fx%.0f",
                root_dockspace_id, recovery ? "missing_loaded_root" : "first_run_or_recovery",
                size.x, size.y);
        }
        current.root_prepared = true;
    }
    apply_lock_recursive(ImGui::DockBuilderGetNode(root_dockspace_id), current.locked);
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (viewport) {
        const float dpi_scale = viewport->DpiScale > 0.0f ? viewport->DpiScale : 1.0f;
        const bool geometry_changed = !current.rehome_initialized ||
            current.rehome_work_position.x != viewport->WorkPos.x ||
            current.rehome_work_position.y != viewport->WorkPos.y ||
            current.rehome_work_size.x != viewport->WorkSize.x ||
            current.rehome_work_size.y != viewport->WorkSize.y ||
            current.rehome_dpi_scale != dpi_scale;
        if (geometry_changed) {
            current.rehome_work_position = viewport->WorkPos;
            current.rehome_work_size = viewport->WorkSize;
            current.rehome_dpi_scale = dpi_scale;
            current.rehome_initialized = true;
            rehome_floating_windows();
        }
    }
}

ImGuiID node_id(dock_role_t role) noexcept
{
    const dock_nodes_t nodes = resolved_nodes(state());
    switch (role) {
    case dock_role_t::root: return nodes.root;
    case dock_role_t::navigator: return nodes.navigator;
    case dock_role_t::documents: return nodes.documents;
    case dock_role_t::inspector: return nodes.inspector;
    case dock_role_t::bottom: return nodes.bottom;
    default: return 0;
    }
}

workspace_preset_t active_preset() noexcept { return state().active; }
std::string_view active_preset_name() noexcept { return descriptor_for(active_preset()).display_name; }
bool layout_locked() noexcept { return state().locked; }

void set_layout_locked(bool locked) noexcept
{
    state_t& current = state();
    current.locked = locked;
    apply_lock_recursive(ImGui::DockBuilderGetNode(current.expected_root), locked);
    if (current.persistence_available)
        save_active_workspace_record(current);
    ImGui::GetIO().WantSaveIniSettings = true;
}

workspace_request_result_t switch_to(workspace_preset_t preset) noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (current.active == preset && !current.rebuild_requested)
        return workspace_request_result_t::unchanged;
    if (!save_current_synchronously(current, capture_paths(current), false))
        return workspace_request_result_t::failed;
    current.pending = preset;
    if (!select_preset_paths(current, preset))
        return workspace_request_result_t::failed;
    ImGui::DockBuilderRemoveNode(current.expected_root);
    record_metadata_t metadata;
    read_result_t loaded = load_layout_file(current.primary, current.expected_root, metadata);
    if (loaded == read_result_t::valid && metadata.preset != preset)
        loaded = read_result_t::invalid;
    current.active = preset;
    current.generation = (std::max)(current.generation, metadata.generation);
    current.nodes.root = current.expected_root;
    current.needs_default = loaded != read_result_t::valid;
    if (loaded == read_result_t::valid) {
        current.nodes = metadata.nodes;
        current.locked = metadata.locked;
    } else {
        current.locked = false;
        if (loaded == read_result_t::invalid)
            MoveFileExW(current.primary.c_str(), current.invalid.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    current.rebuild_requested = current.needs_default;
    current.root_prepared = false;
    current.recovered_from_backup = false;
    current.preserve_recovery_backup = false;
    save_active_workspace_record(current);
    return workspace_request_result_t::completed;
}

workspace_request_result_t save_user_layout(std::string_view name) noexcept
{
    state_t& current = state();
    if (!valid_user_layout_name(name))
        return workspace_request_result_t::invalid_name;
    if (!current.initialized || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    layout_paths_t paths = capture_paths(current);
    try {
        paths.directory = current.directory / L"user";
        paths.primary = user_layout_path(current, name);
        paths.backup = paths.primary;
        paths.backup += L".bak";
        paths.invalid = paths.primary;
        paths.invalid += L".invalid";
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    return save_current_synchronously(current, paths, false)
        ? workspace_request_result_t::completed
        : workspace_request_result_t::failed;
}

workspace_request_result_t load_user_layout(std::string_view name) noexcept
{
    state_t& current = state();
    if (!valid_user_layout_name(name))
        return workspace_request_result_t::invalid_name;
    if (!current.initialized || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (!save_current_synchronously(current, capture_paths(current), false))
        return workspace_request_result_t::failed;
    record_metadata_t metadata;
    std::filesystem::path path;
    try {
        path = user_layout_path(current, name);
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    if (!inspect_layout_file(path, current.expected_root, metadata))
        return workspace_request_result_t::unavailable;
    ImGui::DockBuilderRemoveNode(current.expected_root);
    if (load_layout_file(path, current.expected_root, metadata) != read_result_t::valid) {
        current.needs_default = true;
        current.root_prepared = false;
        return workspace_request_result_t::failed;
    }
    current.active = metadata.preset;
    current.pending = metadata.preset;
    if (!select_preset_paths(current, current.active))
        return workspace_request_result_t::failed;
    current.nodes = metadata.nodes;
    current.locked = metadata.locked;
    current.generation = (std::max)(current.generation, metadata.generation);
    current.needs_default = false;
    current.root_prepared = false;
    save_active_workspace_record(current);
    return workspace_request_result_t::completed;
}

workspace_request_result_t restore_builtin(workspace_preset_t preset) noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    if (!select_preset_paths(current, preset))
        return workspace_request_result_t::failed;
    DeleteFileW(current.primary.c_str());
    DeleteFileW(current.backup.c_str());
    DeleteFileW(current.invalid.c_str());
    current.active = preset;
    current.pending = preset;
    current.nodes = {current.expected_root, 0, 0, 0, 0};
    current.locked = false;
    current.needs_default = true;
    current.rebuild_requested = true;
    current.root_prepared = false;
    current.recovered_from_backup = false;
    current.preserve_recovery_backup = false;
    save_active_workspace_record(current);
    return workspace_request_result_t::completed;
}

workspace_request_result_t reset_current() noexcept { return restore_builtin(active_preset()); }

workspace_request_result_t reset_all() noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.persistence_available)
        return workspace_request_result_t::unavailable;
    for (const auto& descriptor : kPresetDescriptors) {
        if (!select_preset_paths(current, descriptor.id))
            return workspace_request_result_t::failed;
        DeleteFileW(current.primary.c_str());
        DeleteFileW(current.backup.c_str());
        DeleteFileW(current.invalid.c_str());
    }
    try {
        std::filesystem::path user_directory = current.directory / L"user";
        std::error_code error;
        for (const auto& entry : std::filesystem::directory_iterator(user_directory, error)) {
            if (!error && entry.is_regular_file(error) && entry.path().extension() == L".aida-layout")
                std::filesystem::remove(entry.path(), error);
        }
    } catch (...) {
        return workspace_request_result_t::failed;
    }
    return restore_builtin(workspace_preset_t::analysis);
}

workspace_request_result_t activate_safe_layout() noexcept
{
    return restore_builtin(workspace_preset_t::safe);
}

workspace_request_result_t open_missing_views() noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared)
        return workspace_request_result_t::unavailable;
    const dock_nodes_t nodes = resolved_nodes(current);
    dock_named_windows(current.active, nodes.navigator, nodes.documents,
        nodes.inspector, nodes.bottom, true);
    ImGui::DockBuilderFinish(current.expected_root);
    ImGui::GetIO().WantSaveIniSettings = true;
    return workspace_request_result_t::completed;
}

void persist_if_requested() noexcept
{
    state_t& current = state();
    if (!current.initialized || !current.root_prepared || !current.persistence_available)
        return;
    ImGuiIO& io = ImGui::GetIO();
    const std::uint64_t now_ms = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t completed = committed_generation().load(std::memory_order_acquire);
    if (current.generation != 0 && completed >= current.generation)
        current.recovered_from_backup = false;
    const std::uint64_t failed = failed_generation().exchange(0, std::memory_order_acq_rel);
    if (failed != 0 && failed == current.generation) {
        io.WantSaveIniSettings = true;
        current.next_save_attempt_ms = now_ms + 5000ULL;
        diag::log_tagged_critical_fmt("workspace_layout",
            "layout_async_save_failed generation=%llu",
            static_cast<unsigned long long>(failed));
    }
    if (!io.WantSaveIniSettings)
        return;
    if (current.next_save_attempt_ms != 0 && now_ms < current.next_save_attempt_ms)
        return;
    std::size_t payload_size = 0;
    const char* payload = ImGui::SaveIniSettingsToMemory(&payload_size);
    current.nodes = resolved_nodes(current);
    bool queued = false;
    const std::uint64_t next_generation = current.generation + 1ULL;
    try {
        queued = payload && queue_write(capture_paths(current), current.expected_root,
            std::string_view(payload, payload_size), next_generation,
            current.recovered_from_backup || current.preserve_recovery_backup,
            current.nodes, current.active, current.locked);
    } catch (...) {
        queued = false;
    }
    if (queued) {
        io.WantSaveIniSettings = false;
        current.generation = next_generation;
        current.next_save_attempt_ms = 0;
        diag::log_tagged_fmt("workspace_layout",
            "layout_save_queued generation=%llu payload_bytes=%llu",
            static_cast<unsigned long long>(next_generation),
            static_cast<unsigned long long>(payload_size));
    } else {
        current.next_save_attempt_ms = now_ms + 5000ULL;
        diag::log_tagged_critical_fmt("workspace_layout", "layout_save_queue_failed payload_bytes=%llu",
            static_cast<unsigned long long>(payload_size));
    }
}

void shutdown() noexcept
{
    state_t& current = state();
    if (!current.initialized)
        return;
    if (current.root_prepared && current.persistence_available) {
        std::size_t payload_size = 0;
        const char* payload = ImGui::SaveIniSettingsToMemory(&payload_size);
        current.nodes = resolved_nodes(current);
        bool saved = false;
        const std::uint64_t final_generation = current.generation + 1ULL;
        try {
            saved = payload && write_generation(capture_paths(current), current.expected_root,
                std::string_view(payload, payload_size), final_generation, true,
                current.recovered_from_backup || current.preserve_recovery_backup,
                current.nodes, current.active, current.locked);
        } catch (...) {
            saved = false;
        }
        if (!saved)
            diag::log_tagged_critical_fmt("workspace_layout", "layout_shutdown_save_failed payload_bytes=%llu",
                static_cast<unsigned long long>(payload_size));
        else
            diag::log_tagged_fmt("workspace_layout",
                "layout_shutdown_save_complete generation=%llu payload_bytes=%llu clean_shutdown=1",
                static_cast<unsigned long long>(final_generation),
                static_cast<unsigned long long>(payload_size));
    }
    current = {};
}

}

#endif
