#pragma once

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/studio_semantics.hpp"
#endif

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace network_view::human_request_editor {

enum class mode_t : std::uint8_t {
    raw = 0,
    pretty
};

struct state_t {
    std::string identity;
    std::vector<char> raw;
    std::vector<char> request_line;
    std::vector<char> headers;
    std::vector<char> body;
    std::string line_ending = "\r\n";
    std::string error;
    std::uint64_t authority_hash = 0;
    std::size_t max_bytes = 0;
    std::size_t raw_length = 0;
    std::size_t request_line_length = 0;
    std::size_t headers_length = 0;
    std::size_t body_length = 0;
    mode_t mode = mode_t::raw;
    bool editable = true;
    bool raw_dirty = false;
    bool pretty_dirty = false;
    bool parsed = false;
    bool oversized = false;
    bool binary = false;
    char search[160] = {};
    std::vector<std::size_t> matches;
    int active_match = -1;
    bool select_match = false;
};

struct render_config_t {
    const char* stable_id = "request-editor";
    ImVec2 size = ImVec2(0.f, 0.f);
    std::size_t max_bytes = 1U << 20;
    bool editable = true;
    bool allow_empty = false;
    const char* semantic_parent_id = nullptr;
};

struct render_result_t {
    bool authority_changed = false;
    bool mode_changed = false;
    bool search_changed = false;
    bool has_unapplied_pretty = false;
    bool valid = false;
    bool editable = false;
};

struct fixed_state_t {
    state_t editor;
    std::string authority;
    std::uint64_t buffer_hash = 0;
};

inline std::uint64_t hash_bytes(std::string_view value) noexcept {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const unsigned char byte : value) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    hash ^= static_cast<std::uint64_t>(value.size());
    hash *= 1099511628211ULL;
    return hash == 0 ? 1 : hash;
}

inline bool contains_binary_bytes(std::string_view value) noexcept {
    const char* cursor = value.data();
    const char* const end = cursor + value.size();
    while (cursor < end) {
        unsigned int codepoint = 0;
        const int consumed = ImTextCharFromUtf8(&codepoint, cursor, end);
        if (consumed <= 0 || cursor + consumed > end ||
            codepoint == IM_UNICODE_CODEPOINT_INVALID ||
            (codepoint < 0x20U && codepoint != '\r' && codepoint != '\n' &&
             codepoint != '\t') || codepoint == 0x7FU)
            return true;
        cursor += consumed;
    }
    return false;
}

inline void assign_buffer(std::vector<char>& buffer, std::size_t capacity,
                          std::string_view value, std::size_t& length) {
    if (buffer.size() != capacity + 1)
        buffer.resize(capacity + 1);
    length = std::min(value.size(), capacity);
    if (length != 0)
        std::memcpy(buffer.data(), value.data(), length);
    buffer[length] = '\0';
}

inline std::size_t bounded_length(const std::vector<char>& buffer) noexcept {
    if (buffer.empty())
        return 0;
    const auto found = std::find(buffer.begin(), buffer.end(), '\0');
    return static_cast<std::size_t>(std::distance(buffer.begin(), found));
}

inline bool valid_header_name(std::string_view name) noexcept {
    if (name.empty())
        return false;
    return std::all_of(name.begin(), name.end(), [](const unsigned char value) {
        return std::isalnum(value) != 0 || value == '!' || value == '#' || value == '$' ||
            value == '%' || value == '&' || value == '\'' || value == '*' || value == '+' ||
            value == '-' || value == '.' || value == '^' || value == '_' || value == '`' ||
            value == '|' || value == '~';
    });
}

inline bool validate_request_line(std::string_view line) noexcept {
    const auto first = line.find(' ');
    if (first == std::string_view::npos || first == 0)
        return false;
    const auto second = line.find(' ', first + 1);
    if (second == std::string_view::npos || second == first + 1 || second + 1 >= line.size())
        return false;
    return line.find_first_of("\r\n", second + 1) == std::string_view::npos &&
        line.substr(second + 1, 5) == "HTTP/";
}

inline bool validate_headers(std::string_view headers, std::string& error) {
    if (!headers.empty() && (headers.back() == '\r' || headers.back() == '\n')) {
        error = "Header fields must not include the blank-line body separator.";
        return false;
    }
    std::size_t offset = 0;
    while (offset < headers.size()) {
        const auto end = headers.find('\n', offset);
        const auto count = (end == std::string_view::npos ? headers.size() : end) - offset;
        std::string_view line = headers.substr(offset, count);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (line.empty()) {
            error = "Header fields cannot contain an embedded blank line.";
            return false;
        }
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || !valid_header_name(line.substr(0, colon))) {
            error = "Each header must use a valid HTTP field name followed by a colon.";
            return false;
        }
        if (end == std::string_view::npos)
            break;
        offset = end + 1;
    }
    return true;
}

inline void parse_pretty(state_t& state, std::string_view authority) {
    state.parsed = false;
    state.error.clear();
    if (state.oversized) {
        state.error = "The request exceeds this editor's bounded capacity.";
        return;
    }
    if (state.binary) {
        state.error = "The request contains binary or invalid UTF-8 bytes and cannot be represented by the text editor.";
        return;
    }
    const auto crlf_boundary = authority.find("\r\n\r\n");
    const auto lf_boundary = authority.find("\n\n");
    const bool use_crlf = crlf_boundary != std::string_view::npos &&
        (lf_boundary == std::string_view::npos || crlf_boundary <= lf_boundary);
    const auto boundary = use_crlf ? crlf_boundary : lf_boundary;
    const std::size_t separator_size = use_crlf ? 4U : 2U;
    const auto header_section = boundary == std::string_view::npos
        ? authority : authority.substr(0, boundary);
    state.line_ending = use_crlf ? "\r\n" : "\n";
    const auto first_line_end = header_section.find(state.line_ending);
    const auto request_line = first_line_end == std::string_view::npos
        ? header_section : header_section.substr(0, first_line_end);
    const auto headers = first_line_end == std::string_view::npos
        ? std::string_view{} : header_section.substr(first_line_end + state.line_ending.size());
    const auto body = boundary == std::string_view::npos
        ? std::string_view{} : authority.substr(boundary + separator_size);
    if (!validate_request_line(request_line)) {
        state.error = "The raw request does not contain a valid HTTP request line.";
        return;
    }
    std::string header_error;
    if (!validate_headers(headers, header_error)) {
        state.error = std::move(header_error);
        return;
    }
    assign_buffer(state.request_line, state.max_bytes, request_line, state.request_line_length);
    assign_buffer(state.headers, state.max_bytes, headers, state.headers_length);
    assign_buffer(state.body, state.max_bytes, body, state.body_length);
    state.pretty_dirty = false;
    state.parsed = true;
}

inline void load(state_t& state, std::string_view identity, std::string_view authority,
                 const render_config_t& config) {
    state = {};
    state.identity.assign(identity);
    state.max_bytes = std::max<std::size_t>(1024, config.max_bytes);
    state.editable = config.editable;
    state.authority_hash = hash_bytes(authority);
    state.oversized = authority.size() > state.max_bytes;
    state.binary = contains_binary_bytes(authority);
    assign_buffer(state.raw, state.max_bytes, authority, state.raw_length);
    parse_pretty(state, authority);
}

inline void update_matches(state_t& state, std::string_view source) {
    state.matches.clear();
    state.active_match = -1;
    const std::string_view query(state.search);
    if (query.empty())
        return;
    std::size_t offset = 0;
    while (offset <= source.size() && state.matches.size() < 10000) {
        const auto found = source.find(query, offset);
        if (found == std::string_view::npos)
            break;
        state.matches.push_back(found);
        offset = found + std::max<std::size_t>(1, query.size());
    }
    if (!state.matches.empty())
        state.active_match = 0;
}

inline int select_match_callback(ImGuiInputTextCallbackData* data) {
    auto* state = static_cast<state_t*>(data->UserData);
    if (!state || !state->select_match || state->active_match < 0 ||
        state->active_match >= static_cast<int>(state->matches.size()))
        return 0;
    const auto begin = state->matches[static_cast<std::size_t>(state->active_match)];
    const auto end = begin + std::strlen(state->search);
    data->CursorPos = static_cast<int>(std::min<std::size_t>(begin, static_cast<std::size_t>(data->BufTextLen)));
    data->SelectionStart = data->CursorPos;
    data->SelectionEnd = static_cast<int>(std::min<std::size_t>(end, static_cast<std::size_t>(data->BufTextLen)));
    state->select_match = false;
    return 0;
}

inline void register_semantic(const render_config_t& config, std::string_view suffix,
                              std::string_view type, bool disabled = false);

inline render_result_t render(state_t& state, std::string_view identity,
                              std::string& authority, const render_config_t& config) {
    render_result_t result;
    const auto current_hash = hash_bytes(authority);
    if (state.identity != identity || state.max_bytes != std::max<std::size_t>(1024, config.max_bytes) ||
        state.authority_hash != current_hash)
        load(state, identity, authority, config);
    if (config.allow_empty && authority.empty())
        state.error.clear();
    state.editable = config.editable;
    result.editable = state.editable && !state.oversized && !state.binary;

    ImGui::PushID(config.stable_id);
    const mode_t previous_mode = state.mode;
    const bool raw_selected = state.mode == mode_t::raw;
    if (raw_selected)
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_ButtonActive));
    if (ImGui::SmallButton("Raw##mode-raw")) {
        state.mode = mode_t::raw;
        result.mode_changed = true;
    }
    register_semantic(config, "mode.raw", "network-request-editor-mode");
    if (raw_selected)
        ImGui::PopStyleColor();
    ImGui::SameLine();
    const bool pretty_available = state.parsed || state.pretty_dirty;
    if (!pretty_available)
        ImGui::BeginDisabled();
    const bool pretty_selected = state.mode == mode_t::pretty;
    if (pretty_selected)
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_ButtonActive));
    if (ImGui::SmallButton("Pretty##mode-pretty")) {
        state.mode = mode_t::pretty;
        result.mode_changed = true;
    }
    register_semantic(config, "mode.pretty", "network-request-editor-mode", !pretty_available);
    if (pretty_selected)
        ImGui::PopStyleColor();
    if (!pretty_available)
        ImGui::EndDisabled();
    if (state.mode != previous_mode) {
        const std::string_view source = state.mode == mode_t::raw
            ? std::string_view(state.raw.data(), state.raw_length)
            : std::string_view(state.body.data(), state.body_length);
        update_matches(state, source);
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(std::min(220.f, std::max(96.f, ImGui::GetContentRegionAvail().x - 132.f)));
    if (ImGui::InputTextWithHint("##find", state.mode == mode_t::raw ? "Find in Raw" : "Find in Body",
            state.search, sizeof(state.search))) {
        const std::string_view source = state.mode == mode_t::raw
            ? std::string_view(state.raw.data(), state.raw_length)
            : std::string_view(state.body.data(), state.body_length);
        update_matches(state, source);
        state.select_match = !state.matches.empty();
        result.search_changed = true;
    }
    register_semantic(config, "find.query", "network-request-editor-find");
    ImGui::SameLine();
    const bool has_matches = !state.matches.empty();
    if (!has_matches)
        ImGui::BeginDisabled();
    if (ImGui::SmallButton("Prev##find")) {
        state.active_match = (state.active_match - 1 + static_cast<int>(state.matches.size())) %
            static_cast<int>(state.matches.size());
        state.select_match = true;
    }
    register_semantic(config, "find.previous", "network-request-editor-action", !has_matches);
    ImGui::SameLine();
    if (ImGui::SmallButton("Next##find")) {
        state.active_match = (state.active_match + 1) % static_cast<int>(state.matches.size());
        state.select_match = true;
    }
    register_semantic(config, "find.next", "network-request-editor-action", !has_matches);
    if (!has_matches)
        ImGui::EndDisabled();
    ImGui::SameLine();
    if (has_matches)
        ImGui::TextDisabled("%d/%zu", state.active_match + 1, state.matches.size());
    else if (state.search[0] != '\0')
        ImGui::TextDisabled("0/0");
    if (state.raw_dirty || state.pretty_dirty) {
        ImGui::SameLine();
        ImGui::TextDisabled(state.pretty_dirty ? "UNAPPLIED" : "MODIFIED");
    }

    const ImVec2 editor_size(config.size.x, std::max(64.f, config.size.y - ImGui::GetFrameHeightWithSpacing()));
    if (state.mode == mode_t::raw) {
        ImGuiInputTextFlags flags = ImGuiInputTextFlags_CallbackAlways;
        if (!result.editable)
            flags |= ImGuiInputTextFlags_ReadOnly;
        if (ImGui::InputTextMultiline("##raw", state.raw.data(), state.raw.size(), editor_size,
                flags, select_match_callback, &state) && result.editable) {
            state.raw_length = bounded_length(state.raw);
            authority.assign(state.raw.data(), state.raw_length);
            state.authority_hash = hash_bytes(authority);
            state.raw_dirty = true;
            parse_pretty(state, authority);
            state.raw_dirty = true;
            update_matches(state, std::string_view(state.raw.data(), state.raw_length));
            result.authority_changed = true;
        }
        register_semantic(config, "raw", "network-request-editor-raw", !result.editable);
    } else {
        const float structured_height = std::max(64.f,
            editor_size.y - ImGui::GetFrameHeightWithSpacing() * 2.f - 8.f);
        const float body_height = std::max(32.f, structured_height * 0.42f);
        const float header_height = std::max(32.f, structured_height - body_height);
        if (!result.editable)
            ImGui::BeginDisabled();
        ImGui::SetNextItemWidth(-1.f);
        if (ImGui::InputText("##request-line", state.request_line.data(), state.request_line.size())) {
            state.request_line_length = bounded_length(state.request_line);
            state.pretty_dirty = true;
        }
        register_semantic(config, "pretty.request-line", "network-request-editor-request-line", !result.editable);
        if (ImGui::InputTextMultiline("##headers", state.headers.data(), state.headers.size(),
                ImVec2(-1.f, header_height))) {
            state.headers_length = bounded_length(state.headers);
            state.pretty_dirty = true;
        }
        register_semantic(config, "pretty.headers", "network-request-editor-headers", !result.editable);
        if (ImGui::InputTextMultiline("##body", state.body.data(), state.body.size(),
                ImVec2(-1.f, body_height), ImGuiInputTextFlags_CallbackAlways,
                select_match_callback, &state)) {
            state.body_length = bounded_length(state.body);
            state.pretty_dirty = true;
            update_matches(state, std::string_view(state.body.data(), state.body_length));
        }
        register_semantic(config, "pretty.body", "network-request-editor-body", !result.editable);
        if (!result.editable)
            ImGui::EndDisabled();

        std::string validation_error;
        const std::string_view request_line(state.request_line.data(), state.request_line_length);
        const std::string_view headers(state.headers.data(), state.headers_length);
        const std::string_view body(state.body.data(), state.body_length);
        const bool valid_line = validate_request_line(request_line);
        const bool valid_headers = validate_headers(headers, validation_error);
        std::string candidate;
        if (valid_line && valid_headers) {
            candidate.reserve(request_line.size() + headers.size() + body.size() + 8);
            candidate.append(request_line);
            candidate.append(state.line_ending);
            if (!headers.empty()) {
                candidate.append(headers);
                candidate.append(state.line_ending);
            }
            candidate.append(state.line_ending);
            candidate.append(body);
            if (candidate.size() > state.max_bytes)
                validation_error = "The edited request exceeds this editor's bounded capacity.";
        } else if (!valid_line) {
            validation_error = "The request line must contain method, target, and HTTP version.";
        }
        if (state.pretty_dirty)
            state.error = validation_error;
        const bool can_apply = state.pretty_dirty && result.editable && validation_error.empty();
        if (!can_apply)
            ImGui::BeginDisabled();
        if (ImGui::SmallButton("Apply to Raw##pretty-apply")) {
            authority = std::move(candidate);
            state.authority_hash = hash_bytes(authority);
            assign_buffer(state.raw, state.max_bytes, authority, state.raw_length);
            state.pretty_dirty = false;
            state.raw_dirty = true;
            state.error.clear();
            result.authority_changed = true;
        }
        register_semantic(config, "pretty.apply", "network-request-editor-action", !can_apply);
        if (!can_apply)
            ImGui::EndDisabled();
        ImGui::SameLine();
        const bool can_discard = state.pretty_dirty && result.editable;
        if (!can_discard)
            ImGui::BeginDisabled();
        if (ImGui::SmallButton("Discard Pretty Edits##pretty-discard"))
            parse_pretty(state, authority);
        register_semantic(config, "pretty.discard", "network-request-editor-action", !can_discard);
        if (!can_discard)
            ImGui::EndDisabled();
    }

    if (state.oversized)
        ImGui::TextWrapped("Read-only: %zu bytes exceeds the %zu-byte editor limit.",
            authority.size(), state.max_bytes);
    else if (state.binary)
        ImGui::TextWrapped("Read-only: binary or invalid UTF-8 bytes cannot be represented safely by this text editor.");
    else if (!state.error.empty())
        ImGui::TextWrapped("%s", state.error.c_str());
    result.has_unapplied_pretty = state.pretty_dirty;
    result.valid = result.editable && (config.allow_empty || !authority.empty()) &&
        !state.pretty_dirty && state.error.empty();
    ImGui::PopID();
    return result;
}

template <std::size_t Capacity>
inline render_result_t render_fixed(fixed_state_t& state, std::string_view identity,
                                    char (&authority_buffer)[Capacity],
                                    render_config_t config) {
    const auto terminator = std::find(authority_buffer, authority_buffer + Capacity, '\0');
    const std::string_view external(authority_buffer,
        static_cast<std::size_t>(std::distance(authority_buffer, terminator)));
    const auto external_hash = hash_bytes(external);
    if (state.buffer_hash != external_hash) {
        state.authority.assign(external);
        state.buffer_hash = external_hash;
    }
    config.max_bytes = std::min<std::size_t>(config.max_bytes, Capacity - 1);
    auto result = render(state.editor, identity, state.authority, config);
    if (result.authority_changed) {
        if (state.authority.size() >= Capacity) {
            result.authority_changed = false;
            result.valid = false;
            state.editor.error = "The edited request exceeds its destination buffer capacity.";
        } else {
            std::memcpy(authority_buffer, state.authority.data(), state.authority.size());
            authority_buffer[state.authority.size()] = '\0';
            state.buffer_hash = hash_bytes(state.authority);
        }
    }
    return result;
}

inline void mark_clean(state_t& state) noexcept {
    state.raw_dirty = false;
}

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline void register_semantic(const render_config_t& config, std::string_view suffix,
                              std::string_view type, bool disabled) {
    std::string id = "aida.network.request-editor.";
    id.append(config.stable_id ? config.stable_id : "editor");
    id.push_back('.');
    id.append(suffix);
    static_cast<void>(aida::preview::semantics::register_last_item(
        id, type, false, disabled,
        config.semantic_parent_id ? std::string_view(config.semantic_parent_id) : std::string_view{}));
}
#else
inline void register_semantic(const render_config_t&, std::string_view,
                              std::string_view, bool) {}
#endif

}
