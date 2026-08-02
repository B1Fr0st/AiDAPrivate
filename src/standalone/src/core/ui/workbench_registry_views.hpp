#pragma once

#include "../ai/standalone_chat.hpp"
#include "../analysis/workspace/paged_snapshot_view.hpp"
#include "../disasm/disasm_view.hpp"
#include "../editor/code_editor.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#include "application_view_registry.hpp"
#include "application_ui_runtime.hpp"
#include "design_system.hpp"

#include "imgui/imgui.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace aida::ui::workbench_registry_views {
namespace detail {

class frame_cancellation_t final
    : public aida::workbench::navigator::navigator_cancellation_t,
      public aida::workbench::diff_document::diff_cancellation_t {
public:
    explicit frame_cancellation_t(std::uint32_t budget_ms)
        : deadline_(std::chrono::steady_clock::now() +
            std::chrono::milliseconds(budget_ms)) {}

    bool cancelled() const noexcept override {
        return std::chrono::steady_clock::now() >= deadline_;
    }

private:
    std::chrono::steady_clock::time_point deadline_;
};

struct inspector_row_t final {
    std::string label;
    std::string value;
    std::string provenance;
};

struct inspector_view_snapshot_t final {
    aida::workbench::inspector::inspector_context_t context;
    std::uint64_t analysis_generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::string display_name;
    std::string qualified_name;
    std::string entity_kind;
    std::string document_kind;
    std::string module_name;
    std::string source_path;
    bool has_va = false;
    std::uint64_t va = 0;
    bool has_rva = false;
    std::uint64_t rva = 0;
    bool has_file_offset = false;
    std::uint64_t file_offset = 0;
    std::vector<inspector_row_t> identity;
    std::vector<inspector_row_t> location;
    std::vector<inspector_row_t> bytes;
    std::vector<inspector_row_t> operands;
    std::vector<inspector_row_t> xrefs;
    std::vector<inspector_row_t> calls;
    std::vector<inspector_row_t> stack_locals;
    std::vector<inspector_row_t> types;
    std::vector<inspector_row_t> overlays;
    std::vector<inspector_row_t> diagnostics;
    std::vector<inspector_row_t> provenance;
};

struct programming_inspector_snapshot_t final {
    std::uint64_t document_id = 0;
    std::uint64_t revision = 0;
    code_editor_widget::document_state_t document;
    std::vector<inspector_row_t> identity;
    std::vector<inspector_row_t> location;
    std::vector<inspector_row_t> editing;
};

enum class inspector_source_t : std::uint8_t {
    analysis = 0,
    programming
};

struct state_t final {
    aida::workbench::navigator::navigator_domain_t navigator_domain =
        aida::workbench::navigator::navigator_domain_t::functions;
    std::uint64_t navigator_selected_id = 0;
    std::uint64_t last_address = 0;
    std::uint64_t diff_offset = 0;
    std::uint64_t diff_total = 0;
    aida::workbench::diff_document::diff_kind_t diff_kind =
        aida::workbench::diff_document::diff_kind_t::generation;
    std::uint64_t observed_generation = 0;
    std::uint64_t last_touch = 0;
    bool inspector_follow_selection = true;
    bool inspector_pinned = false;
    bool inspector_live_valid = false;
    bool programming_live_valid = false;
    inspector_source_t inspector_live_source = inspector_source_t::analysis;
    inspector_source_t inspector_pin_source = inspector_source_t::analysis;
    inspector_view_snapshot_t inspector_live;
    std::optional<inspector_view_snapshot_t> inspector_pin;
    programming_inspector_snapshot_t programming_live;
    std::optional<programming_inspector_snapshot_t> programming_pin;
    std::string inspector_handoff_status;
};

inline std::string hexadecimal(std::uint64_t value, unsigned minimum_digits = 0) {
    char buffer[32];
    const unsigned digits = (std::min)(minimum_digits, 16U);
    std::snprintf(buffer, sizeof(buffer), "0x%0*llX", static_cast<int>(digits),
        static_cast<unsigned long long>(value));
    return buffer;
}

inline const char* document_kind_label(aida::workbench::document_kind_t kind) noexcept {
    using kind_t = aida::workbench::document_kind_t;
    switch (kind) {
    case kind_t::binary: return "Binary";
    case kind_t::disassembly: return "Disassembly";
    case kind_t::hex: return "Hex";
    case kind_t::pseudocode: return "Pseudocode";
    case kind_t::graph: return "Graph";
    case kind_t::strings: return "Strings";
    case kind_t::imports: return "Imports";
    case kind_t::exports: return "Exports";
    case kind_t::functions: return "Functions";
    case kind_t::types: return "Types";
    case kind_t::diagnostics: return "Diagnostics";
    case kind_t::bookmarks: return "Bookmarks";
    case kind_t::memory: return "Memory";
    case kind_t::debugger: return "Debugger";
    case kind_t::custom: return "Custom";
    case kind_t::diff: return "Diff";
    case kind_t::unknown: return "Unknown";
    }
    return "Unknown";
}

inline const char* provenance_label(aida::analysis::fact_provenance_t provenance) noexcept {
    using provenance_t = aida::analysis::fact_provenance_t;
    switch (provenance) {
    case provenance_t::unknown: return "Unknown";
    case provenance_t::gap_recovery: return "Gap recovery";
    case provenance_t::linear_validation: return "Linear validation";
    case provenance_t::recursive_decode: return "Recursive decode";
    case provenance_t::relocation: return "Relocation";
    case provenance_t::call_target: return "Call target";
    case provenance_t::export_entry: return "Export metadata";
    case provenance_t::tls_entry: return "TLS metadata";
    case provenance_t::image_entry: return "Image entry";
    case provenance_t::unwind_metadata: return "Unwind metadata";
    case provenance_t::debug_symbol: return "Debug symbol";
    case provenance_t::user_definition: return "User definition";
    case provenance_t::decompiler_feedback: return "Decompiler feedback";
    }
    return "Unknown";
}

inline const char* operand_kind_label(aida::analysis::operand_kind_t kind) noexcept {
    using kind_t = aida::analysis::operand_kind_t;
    switch (kind) {
    case kind_t::none: return "None";
    case kind_t::reg: return "Register";
    case kind_t::memory: return "Memory";
    case kind_t::immediate: return "Immediate";
    case kind_t::pointer: return "Pointer";
    }
    return "Unknown";
}

inline const char* target_kind_label(aida::analysis::target_kind_record_t kind) noexcept {
    using kind_t = aida::analysis::target_kind_record_t;
    switch (kind) {
    case kind_t::branch: return "Branch";
    case kind_t::call: return "Call";
    case kind_t::data: return "Data";
    case kind_t::fallthrough: return "Fallthrough";
    }
    return "Unknown";
}

inline const char* coverage_label(aida::analysis::coverage_reason_t reason) noexcept {
    using reason_t = aida::analysis::coverage_reason_t;
    switch (reason) {
    case reason_t::decoded: return "Decoded";
    case reason_t::proven_data: return "Proven data";
    case reason_t::padding: return "Padding";
    case reason_t::conflict: return "Conflict";
    case reason_t::undecodable: return "Undecodable";
    case reason_t::non_executable: return "Non-executable";
    case reason_t::excluded_by_metadata: return "Excluded by metadata";
    case reason_t::pending: return "Pending";
    }
    return "Unknown";
}

inline std::string confidence_text(std::uint8_t confidence) {
    return std::to_string(static_cast<unsigned>(confidence)) + "%";
}

inline std::uint64_t presentation_address(
    const aida::analysis::workspace_identity_t& identity, std::uint64_t rva) noexcept {
    if (identity.target_kind() == aida::analysis::target_kind_t::live_snapshot &&
        identity.module() && rva <= (std::numeric_limits<std::uint64_t>::max)() -
            identity.module()->base)
        return identity.module()->base + rva;
    if (rva <= (std::numeric_limits<std::uint64_t>::max)() - identity.image_base())
        return identity.image_base() + rva;
    return rva;
}

inline void unavailable(std::vector<inspector_row_t>& rows, const char* reason) {
    rows.push_back({"Status", "Unavailable", reason ? reason : "No provider is available."});
}

inline programming_inspector_snapshot_t capture_programming_inspector_snapshot(
    std::uint64_t document_id, std::uint64_t revision,
    code_editor_widget::document_state_t document) {
    programming_inspector_snapshot_t output;
    output.document_id = document_id;
    output.revision = revision;
    output.document = std::move(document);
    if (!output.document.active || output.document_id == 0)
        return output;
    output.identity.push_back({"Kind", "Source document",
        "The focused application document is owned by the programming editor."});
    output.identity.push_back({"Language",
        output.document.language.empty() ? "Plain text" : output.document.language,
        "Language mode resolved by the programming document service."});
    output.identity.push_back({"Path",
        output.document.filepath.empty() ? "Untitled" : output.document.filepath,
        output.document.filepath.empty()
            ? "This document has not been assigned a file-system path."
            : "Canonical path of the focused programming document."});
    output.identity.push_back({"State", output.document.dirty ? "Modified" : "Saved",
        output.document.dirty
            ? "The focused document has changes that are not persisted."
            : "The focused document matches its persisted revision."});
    output.location.push_back({"Caret",
        "Ln " + std::to_string(output.document.caret_line + 1) + ", Col " +
            std::to_string(output.document.caret_column + 1),
        "One-based caret location in the focused programming document."});
    output.location.push_back({"Selection",
        output.document.has_selection ? "Active" : "None",
        output.document.has_selection
            ? "The programming editor owns an active text selection."
            : "The programming editor has no active text selection."});
    output.location.push_back({"Lines", std::to_string(output.document.line_count),
        "Current bounded line count reported by the programming document model."});
    output.location.push_back({"Size", std::to_string(output.document.content_bytes) + " bytes",
        "Current document content size reported by the programming document model."});
    output.editing.push_back({"Mode",
        output.document.large_file_mode ? "Large file" :
        output.document.streamed ? "Streamed" : "Editable",
        output.document.large_file_mode
            ? "Large-file safeguards are active for this document."
            : output.document.streamed
            ? "The document is backed by the bounded streaming path."
            : "The document is loaded in the full programming editor."});
    output.editing.push_back({"Text editing",
        output.document.capabilities.text_editing ? "Available" : "Read only",
        "Capability resolved by the active programming document provider."});
    output.editing.push_back({"Language services",
        output.document.capabilities.language_server ? "Connected" : "Unavailable",
        output.document.capabilities.language_server
            ? "Language-aware navigation and diagnostics are available."
            : "No language server is connected for this document."});
    output.editing.push_back({"Source debugging",
        output.document.capabilities.source_debugging ? "Available" : "Unavailable",
        output.document.capabilities.source_debugging
            ? "The active provider supports source-level debugging."
            : "The active provider does not support source-level debugging."});
    if (output.document.stream_loading)
        output.editing.push_back({"Stream", "Loading",
            "The bounded document stream is still loading."});
    else if (!output.document.stream_error.empty())
        output.editing.push_back({"Stream", "Error", output.document.stream_error});
    return output;
}

inline bool programming_snapshot_matches(const programming_inspector_snapshot_t& snapshot,
    std::uint64_t document_id, std::uint64_t revision,
    const code_editor_widget::document_state_t& document) noexcept {
    return snapshot.document_id == document_id && snapshot.revision == revision &&
        snapshot.document.filename == document.filename &&
        snapshot.document.filepath == document.filepath &&
        snapshot.document.language == document.language &&
        snapshot.document.content_bytes == document.content_bytes &&
        snapshot.document.line_count == document.line_count &&
        snapshot.document.active == document.active &&
        snapshot.document.dirty == document.dirty &&
        snapshot.document.focused == document.focused &&
        snapshot.document.caret_line == document.caret_line &&
        snapshot.document.caret_column == document.caret_column &&
        snapshot.document.has_selection == document.has_selection &&
        snapshot.document.large_file_mode == document.large_file_mode &&
        snapshot.document.streamed == document.streamed &&
        snapshot.document.stream_loading == document.stream_loading &&
        snapshot.document.stream_error == document.stream_error &&
        snapshot.document.capabilities.text_editing ==
            document.capabilities.text_editing &&
        snapshot.document.capabilities.language_server ==
            document.capabilities.language_server &&
        snapshot.document.capabilities.source_debugging ==
            document.capabilities.source_debugging;
}

inline inspector_view_snapshot_t capture_inspector_snapshot(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const aida::workbench::inspector::inspector_context_t& active,
    const aida::workbench::workbench_shell_workspace_context_t& shell) {
    inspector_view_snapshot_t output;
    output.context = active;
    output.analysis_generation = shell.analysis_generation;
    output.analysis_revision = shell.analysis_revision;
    output.overlay_revision = shell.overlay_revision;
    output.document_kind = document_kind_label(active.document.kind);
    const auto& identity = workspace->identity();
    output.display_name = identity.bin_name();
    output.qualified_name = active.selection.entity_key.empty()
        ? identity.normalized_source_path() : active.selection.entity_key;
    output.source_path = identity.normalized_source_path();
    output.module_name = identity.module() && !identity.module()->normalized_name.empty()
        ? identity.module()->normalized_name
        : (identity.normalized_member_path() ? *identity.normalized_member_path()
                                             : identity.bin_name());
    switch (active.selection.kind) {
    case aida::workbench::selection_kind_t::address: output.entity_kind = "Address"; break;
    case aida::workbench::selection_kind_t::entity: output.entity_kind = "Entity"; break;
    case aida::workbench::selection_kind_t::range: output.entity_kind = "Address range"; break;
    case aida::workbench::selection_kind_t::source: output.entity_kind = "Source location"; break;
    case aida::workbench::selection_kind_t::none: output.entity_kind = "Document"; break;
    }

    const auto image = workspace->image();
    if (active.selection.has_address) {
        const std::uint64_t address = active.selection.address;
        if (identity.target_kind() == aida::analysis::target_kind_t::live_snapshot) {
            output.has_va = true;
            output.va = address;
            if (identity.module() && address >= identity.module()->base &&
                address - identity.module()->base < identity.module()->size) {
                output.has_rva = true;
                output.rva = address - identity.module()->base;
            }
        } else if (image) {
            auto converted = image->va_to_rva(address);
            if (converted) {
                output.has_va = true;
                output.va = address;
                output.has_rva = true;
                output.rva = converted.take_value();
            } else if (address < image->image_size()) {
                output.has_rva = true;
                output.rva = address;
                auto va = image->rva_to_va(address);
                if (va) {
                    output.has_va = true;
                    output.va = va.take_value();
                }
            }
        } else {
            output.has_va = true;
            output.va = address;
        }
        if (image && output.has_rva) {
            auto offset = image->rva_to_file_offset(output.rva);
            if (offset) {
                output.has_file_offset = true;
                output.file_offset = offset.take_value();
            }
        }
    }

    const auto candidate_snapshot = workspace->snapshot();
    const bool publication_coherent = candidate_snapshot &&
        candidate_snapshot->generation == shell.analysis_generation &&
        candidate_snapshot->analysis_revision == shell.analysis_revision &&
        candidate_snapshot->overlay_revision == shell.overlay_revision;
    const auto snapshot = publication_coherent
        ? candidate_snapshot : std::shared_ptr<const aida::analysis::analysis_snapshot_t>{};
    const aida::analysis::instruction_record_t* instruction = nullptr;
    const aida::analysis::function_record_t* function = nullptr;
    const aida::analysis::symbol_record_t* symbol = nullptr;
    aida::analysis::instruction_record_t paged_instruction{};
    if (snapshot && output.has_rva) {
        const auto instruction_rows = aida::analysis::instructions_view(*snapshot);
        if (instruction_rows.resident()) {
            const auto resident = instruction_rows.resident_span();
            const auto instruction_it = std::lower_bound(resident.begin(),
                resident.end(), output.rva,
                [](const auto& candidate, std::uint64_t address) {
                    return candidate.address.value < address;
                });
            if (instruction_it != resident.end() &&
                instruction_it->address.value == output.rva)
                instruction = &*instruction_it;
        } else {
            aida::analysis::fact_page_pin_t lookup_pin;
            std::uint64_t low = 0;
            std::uint64_t high = instruction_rows.size();
            bool lookup_failed = false;
            while (low < high) {
                const std::uint64_t middle = low + (high - low) / 2ULL;
                auto row = instruction_rows.at(middle, lookup_pin);
                if (!row) {
                    lookup_failed = true;
                    break;
                }
                if (row.value()->address.value < output.rva)
                    low = middle + 1ULL;
                else
                    high = middle;
            }
            if (!lookup_failed && low < instruction_rows.size()) {
                auto row = instruction_rows.at(low, lookup_pin);
                if (row && row.value()->address.value == output.rva) {
                    paged_instruction = *row.value();
                    instruction = &paged_instruction;
                }
            }
        }
        const auto symbol_it = std::lower_bound(snapshot->symbols.begin(), snapshot->symbols.end(),
            output.rva, [](const auto& candidate, std::uint64_t address) {
                return candidate.address.value < address;
            });
        if (symbol_it != snapshot->symbols.end() && symbol_it->address.value == output.rva)
            symbol = &*symbol_it;
        auto function_it = std::upper_bound(snapshot->functions.begin(), snapshot->functions.end(),
            output.rva, [](std::uint64_t address, const auto& candidate) {
                return address < candidate.start.value;
            });
        if (function_it != snapshot->functions.begin()) {
            --function_it;
            if (function_it->start.value <= output.rva && output.rva < function_it->end.value)
                function = &*function_it;
        }
    }
    if (symbol && !symbol->name.empty()) {
        output.display_name = symbol->name;
        output.qualified_name = output.module_name + "!" + symbol->name;
        output.entity_kind = "Symbol";
    } else if (function) {
        output.display_name = "sub_" + hexadecimal(function->start.value, 8).substr(2);
        output.qualified_name = output.module_name + "!" + output.display_name;
        output.entity_kind = instruction ? "Instruction" : "Function";
    } else if (instruction) {
        output.display_name = "loc_" + hexadecimal(instruction->address.value, 8).substr(2);
        output.qualified_name = output.module_name + "!" + output.display_name;
        output.entity_kind = "Instruction";
    }

    if (instruction) {
        std::uint64_t provider_offset = 0;
        bool can_read = false;
        if (output.has_file_offset) {
            provider_offset = output.file_offset;
            can_read = true;
        } else if (identity.target_kind() == aida::analysis::target_kind_t::live_snapshot &&
                   output.has_rva) {
            provider_offset = output.rva;
            can_read = true;
        }
        if (can_read && provider_offset < workspace->provider().size()) {
            const std::uint64_t available = workspace->provider().size() - provider_offset;
            const std::uint64_t count = (std::min<std::uint64_t>)({
                instruction->length, available, 16ULL});
            auto bytes = workspace->provider().read_vector(provider_offset, count, 16,
                workspace->cancellation_token());
            if (bytes) {
                std::string text;
                char byte[4];
                for (const auto value : bytes.value()) {
                    std::snprintf(byte, sizeof(byte), "%02X", static_cast<unsigned>(value));
                    if (!text.empty()) text.push_back(' ');
                    text.append(byte);
                }
                output.bytes.push_back({"Instruction bytes", std::move(text),
                    "Read from the selected workspace byte provider."});
            }
        }
        if (output.bytes.empty())
            unavailable(output.bytes,
                "The selected instruction cannot be mapped to a readable provider offset.");

        if (snapshot) {
            const auto operand_rows = aida::analysis::operand_facts_view(*snapshot);
            aida::analysis::fact_page_pin_t operand_pin;
            if (instruction->operand_fact_begin <= operand_rows.size() &&
                instruction->operand_fact_count <= operand_rows.size() -
                    instruction->operand_fact_begin) {
                for (std::uint16_t index = 0; index < instruction->operand_fact_count; ++index) {
                    auto operand_row = operand_rows.at(instruction->operand_fact_begin + index, operand_pin);
                    if (!operand_row)
                        break;
                    const auto& operand = *operand_row.value();
                    std::string value = operand_kind_label(operand.kind);
                    if (operand.kind == aida::analysis::operand_kind_t::immediate ||
                        operand.kind == aida::analysis::operand_kind_t::pointer)
                        value += " " + hexadecimal(operand.immediate);
                    else if (operand.has_resolved_expression_value)
                        value += " -> " + hexadecimal(operand.resolved_expression_value);
                    if (operand.bit_width != 0)
                        value += " · " + std::to_string(operand.bit_width) + " bit";
                    output.operands.push_back({"Operand " + std::to_string(operand.operand_index),
                        std::move(value), "Canonical decoded operand fact."});
                }
            }
        }
    } else {
        unavailable(output.bytes, publication_coherent
            ? "No decoded instruction is selected."
            : "No analysis publication matches the active selection revision.");
    }
    if (output.operands.empty())
        unavailable(output.operands, publication_coherent
            ? "No decoded operand facts exist for this selection."
            : "No analysis publication matches the active selection revision.");

    if (snapshot && output.has_rva) {
        if (instruction) {
            const auto target_rows = aida::analysis::target_facts_view(*snapshot);
            aida::analysis::fact_page_pin_t target_pin;
            if (instruction->target_fact_begin <= target_rows.size() &&
                instruction->target_fact_count <= target_rows.size() -
                    instruction->target_fact_begin) {
                for (std::uint16_t index = 0; index < instruction->target_fact_count; ++index) {
                    auto target_row = target_rows.at(instruction->target_fact_begin + index, target_pin);
                    if (!target_row)
                        break;
                    const auto& target = *target_row.value();
                    const auto target_address = hexadecimal(
                        presentation_address(identity, target.target.value));
                    output.xrefs.push_back({"Outgoing",
                        std::string(target_kind_label(target.kind)) + " · " + target_address,
                        target.direct ? "Direct decoded target fact."
                                      : "Resolved indirect target fact."});
                    if (target.kind == aida::analysis::target_kind_record_t::call)
                        output.calls.push_back({"Calls", target_address,
                            target.direct ? "Direct decoded call target."
                                          : "Resolved indirect call target."});
                }
            }
        }
        if (!snapshot->xrefs.empty())
            output.xrefs.push_back({"Incoming", "Open with Show Xrefs (X)",
                "Incoming references are materialized by the existing cancellable Xrefs action."});
        const auto type_begin = std::lower_bound(snapshot->rich_facts.type_candidates.begin(),
            snapshot->rich_facts.type_candidates.end(), output.rva,
            [](const auto& candidate, std::uint64_t address) {
                return !candidate.address || candidate.address->value < address;
            });
        for (auto candidate = type_begin;
             candidate != snapshot->rich_facts.type_candidates.end() &&
                 candidate->address && candidate->address->value == output.rva;
             ++candidate) {
            std::string value = candidate->display_name;
            if (!candidate->canonical_type.empty())
                value += " · " + candidate->canonical_type;
            output.types.push_back({"Recovered type", std::move(value),
                "Confidence " + confidence_text(candidate->confidence)});
            if (output.types.size() >= 8)
                break;
        }
        if (instruction) {
            output.diagnostics.push_back({"Coverage", coverage_label(instruction->coverage),
                "Analysis coverage classification for the selected instruction."});
            output.provenance.push_back({"Instruction", provenance_label(instruction->provenance),
                "Confidence " + confidence_text(instruction->confidence)});
        }
        if (function)
            output.provenance.push_back({"Function", provenance_label(function->provenance),
                "Confidence " + confidence_text(function->confidence)});
        if (symbol)
            output.provenance.push_back({"Symbol", provenance_label(symbol->provenance),
                "Confidence " + confidence_text(symbol->confidence)});
    }
    if (output.xrefs.empty())
        unavailable(output.xrefs, publication_coherent
            ? "No cross-references are published for this selection."
            : "No analysis publication matches the active selection revision.");
    if (output.calls.empty())
        unavailable(output.calls, publication_coherent
            ? "No outgoing decoded call target is published inline; use Show Xrefs for incoming calls."
            : "No analysis publication matches the active selection revision.");
    unavailable(output.stack_locals,
        "No stack/local provider is registered for this selection context.");
    if (output.types.empty())
        unavailable(output.types, publication_coherent
            ? "No recovered type fact is published for this selection."
            : "No analysis publication matches the active selection revision.");
    output.overlays.push_back({"Workspace revision", std::to_string(shell.overlay_revision),
        "Selection-specific overlay enumeration is not exposed by the active Workbench adapter."});
    if (output.diagnostics.empty())
        unavailable(output.diagnostics, publication_coherent
            ? "No diagnostic fact is published for this selection."
            : "No analysis publication matches the active selection revision.");
    if (output.provenance.empty())
        unavailable(output.provenance, publication_coherent
            ? "No source-provenance fact is published for this selection."
            : "No analysis publication matches the active selection revision.");
    output.identity.push_back({"Kind", output.entity_kind,
        "Resolved from the active Workbench selection."});
    output.identity.push_back({"Document", output.document_kind,
        "Human-readable Workbench document kind."});
    output.identity.push_back({"Module", output.module_name,
        "Canonical workspace or live-module identity."});
    output.identity.push_back({"Source", output.source_path,
        "Canonical workspace source path."});
    output.location.push_back({"VA", output.has_va ? hexadecimal(output.va) : "Unavailable",
        output.has_va ? "Verified virtual address mapping."
                      : "No verified virtual address mapping exists for this selection."});
    output.location.push_back({"RVA", output.has_rva ? hexadecimal(output.rva) : "Unavailable",
        output.has_rva ? "Verified module-relative address mapping."
                       : "No verified module-relative mapping exists for this selection."});
    output.location.push_back({"File offset",
        output.has_file_offset ? hexadecimal(output.file_offset) : "Unavailable",
        output.has_file_offset ? "Verified image-to-file mapping."
                               : "The active image cannot map this selection to a file offset."});
    return output;
}

inline state_t& state_for(aida::workbench::workspace_id_t workspace) {
    static std::map<std::uint64_t, state_t> states;
    static std::uint64_t touch = 0;
    if (++touch == 0)
        touch = 1;
    auto found = states.find(workspace.value);
    if (found == states.end()) {
        if (states.size() >= 64) {
            const auto oldest = std::min_element(states.begin(), states.end(),
                [](const auto& lhs, const auto& rhs) {
                    return lhs.second.last_touch < rhs.second.last_touch;
                });
            if (oldest != states.end())
                states.erase(oldest);
        }
        found = states.try_emplace(workspace.value).first;
    }
    found->second.last_touch = touch;
    return found->second;
}

inline bool selected_context(
    std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    aida::workbench::workbench_shell_workspace_context_t& context,
    std::string& failure) {
    const auto selected = disasm_view::capture_selected_workspace();
    workspace = selected.workspace;
    if (!workspace) {
        failure = "Open and analyze a binary to use this Workbench surface.";
        return false;
    }
    const auto loaded = aida::workbench::workbench_shell_runtime_t::instance()
        .workspace_context(workspace, context);
    if (!loaded) {
        failure = "Workbench context is unavailable (" +
            std::to_string(static_cast<unsigned>(loaded.code)) + ").";
        return false;
    }
    return true;
}

inline aida::ui::application_ui::retained_entity_action_t retained_action(
    const char* id, bool enabled, const char* disabled_reason,
    std::function<aida::ui::action_handler_result_t()> invoke) {
    aida::ui::application_ui::retained_entity_action_t action;
    action.action_id = id;
    action.capability = enabled
        ? aida::ui::capability_state_t::available()
        : aida::ui::capability_state_t::unavailable(disabled_reason);
    action.invoke = std::move(invoke);
    return action;
}

inline std::function<aida::ui::capability_state_t()> workspace_identity_validator(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    std::uint64_t analysis_generation, std::uint64_t analysis_revision,
    std::uint64_t overlay_revision) {
    return [workspace, analysis_generation, analysis_revision, overlay_revision] {
        std::shared_ptr<aida::analysis::analysis_workspace_t> current_workspace;
        aida::workbench::workbench_shell_workspace_context_t current;
        std::string failure;
        if (!selected_context(current_workspace, current, failure))
            return aida::ui::capability_state_t::unavailable(failure);
        if (current_workspace != workspace ||
            current.analysis_generation != analysis_generation ||
            current.analysis_revision != analysis_revision ||
            current.overlay_revision != overlay_revision)
            return aida::ui::capability_state_t::unavailable(
                "The retained Workbench entity belongs to an older analysis or overlay revision");
        return aida::ui::capability_state_t::available();
    };
}

inline void synchronize_generation(state_t& state,
    const aida::workbench::workbench_shell_workspace_context_t& context) {
    if (state.observed_generation == context.analysis_generation)
        return;
    state.navigator_selected_id = 0;
    state.last_address = 0;
    state.diff_offset = 0;
    state.diff_total = 0;
    state.inspector_handoff_status.clear();
    state.observed_generation = context.analysis_generation;
}

inline void navigate(const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    aida::workbench::workbench_shell_workspace_context_t& context,
    std::uint64_t address, std::string entity_key,
    aida::workbench::document_kind_t kind) {
    aida::workbench::selection_context_t selection;
    selection.kind = aida::workbench::selection_kind_t::address;
    selection.has_address = true;
    selection.address = address;
    selection.entity_key = std::move(entity_key);
    aida::workbench::document_local_cursor_t cursor;
    cursor.has_position = true;
    cursor.position = address;
    static_cast<void>(aida::workbench::workbench_shell_runtime_t::instance()
        .navigate_document(workspace, kind, std::nullopt, selection, cursor, context));
}

inline std::string bounded_evidence_text(const std::string& value,
    std::size_t maximum = 512U) {
    std::string output;
    output.reserve((std::min)(value.size(), maximum));
    bool previous_space = false;
    std::size_t offset = 0;
    while (offset < value.size() && output.size() < maximum) {
        const auto character = static_cast<unsigned char>(value[offset]);
        if (character < 0x80U) {
            const bool control = character < 0x20U || character == 0x7FU;
            const char emitted = control ? ' ' : static_cast<char>(character);
            ++offset;
            if (emitted != ' ') {
                output.push_back(emitted);
                previous_space = false;
                continue;
            }
            if (output.empty() || previous_space)
                continue;
            previous_space = true;
            output.push_back(' ');
            continue;
        }
        std::size_t width = 0;
        if (character >= 0xC2U && character <= 0xDFU)
            width = 2;
        else if (character >= 0xE0U && character <= 0xEFU)
            width = 3;
        else if (character >= 0xF0U && character <= 0xF4U)
            width = 4;
        bool valid = width != 0 && offset + width <= value.size();
        for (std::size_t index = 1; valid && index < width; ++index) {
            const auto continuation = static_cast<unsigned char>(value[offset + index]);
            valid = continuation >= 0x80U && continuation <= 0xBFU;
        }
        if (valid && width == 3) {
            const auto second = static_cast<unsigned char>(value[offset + 1]);
            valid = (character != 0xE0U || second >= 0xA0U) &&
                (character != 0xEDU || second <= 0x9FU);
        }
        if (valid && width == 4) {
            const auto second = static_cast<unsigned char>(value[offset + 1]);
            valid = (character != 0xF0U || second >= 0x90U) &&
                (character != 0xF4U || second <= 0x8FU);
        }
        if (valid) {
            if (output.size() + width > maximum)
                break;
            output.append(value, offset, width);
            offset += width;
        } else {
            constexpr char replacement[] = "\xEF\xBF\xBD";
            if (output.size() + 3U > maximum)
                break;
            output.append(replacement, 3U);
            ++offset;
        }
        previous_space = false;
    }
    while (!output.empty() && output.back() == ' ')
        output.pop_back();
    return output;
}

inline std::string evidence_json_string(const std::string& value,
    std::size_t maximum = 512U) {
    const auto bounded = bounded_evidence_text(value, maximum);
    std::string output;
    output.reserve(bounded.size() + 2U);
    output.push_back('"');
    for (const char character : bounded) {
        if (character == '"' || character == '\\')
            output.push_back('\\');
        output.push_back(character);
    }
    output.push_back('"');
    return output;
}

inline std::uint64_t inspector_evidence_hash(const std::string& value) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char character : value) {
        hash ^= static_cast<unsigned char>(character);
        hash *= 1099511628211ULL;
    }
    return hash == 0 ? 1U : hash;
}

inline bool inspector_handoff_capability(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const aida::workbench::workbench_shell_workspace_context_t& shell,
    const inspector_view_snapshot_t& snapshot, std::string& reason) {
    if (!workspace) {
        reason = "The analysis workspace is no longer available.";
        return false;
    }
    if (!shell.inspector_session) {
        reason = "The active workspace has no Inspector selection provider.";
        return false;
    }
    if (snapshot.context.workspace != shell.workspace ||
        snapshot.context.document.workspace != shell.workspace) {
        reason = "The Inspector snapshot belongs to a different workspace.";
        return false;
    }
    const auto typed_context =
        aida::workbench::inspector::validate_inspector_context(snapshot.context);
    if (!typed_context) {
        reason = "The Inspector selection failed typed context validation (code " +
            std::to_string(static_cast<unsigned>(typed_context.code)) +
            ", subject " + std::to_string(typed_context.subject) + ").";
        return false;
    }
    if (snapshot.analysis_generation != shell.analysis_generation) {
        reason = "The Inspector snapshot belongs to an older analysis generation.";
        return false;
    }
    if (snapshot.analysis_revision != shell.analysis_revision) {
        reason = "The Inspector snapshot belongs to an older analysis revision.";
        return false;
    }
    if (snapshot.overlay_revision != shell.overlay_revision) {
        reason = "The Inspector snapshot belongs to an older overlay revision.";
        return false;
    }
    const auto publication = workspace->snapshot();
    if (!publication) {
        reason = "The workspace has no published analysis snapshot.";
        return false;
    }
    if (publication->generation != snapshot.analysis_generation ||
        publication->analysis_revision != snapshot.analysis_revision) {
        reason = "Analysis changed after the Inspector snapshot was captured; select the item again.";
        return false;
    }
    if (publication->overlay_revision != snapshot.overlay_revision ||
        workspace->overlay_revision() != snapshot.overlay_revision) {
        reason = "Analysis overlays changed after the Inspector snapshot was captured; select the item again.";
        return false;
    }
    reason.clear();
    return true;
}

inline std::string inspector_evidence_excerpt(
    const inspector_view_snapshot_t& snapshot, bool& truncated) {
    constexpr std::size_t k_maximum_excerpt = 12U * 1024U;
    constexpr std::size_t k_maximum_rows = 48U;
    constexpr std::size_t k_maximum_scanned_rows = 96U;
    std::ostringstream stream;
    stream << "{\"schema\":\"aida.inspector.selection.v1\","
           << "\"trust\":\"untrusted_analysis_data\","
           << "\"raw_bytes_included\":false,\"source_paths_included\":false,"
           << "\"entity_kind\":" << evidence_json_string(snapshot.entity_kind, 128U)
           << ",\"document_kind\":" << evidence_json_string(snapshot.document_kind, 128U)
           << ",\"display_name\":" << evidence_json_string(snapshot.display_name)
           << ",\"module\":" << evidence_json_string(snapshot.module_name);
    if (snapshot.has_va)
        stream << ",\"va\":" << evidence_json_string(hexadecimal(snapshot.va));
    if (snapshot.has_rva)
        stream << ",\"rva\":" << evidence_json_string(hexadecimal(snapshot.rva));
    if (snapshot.has_file_offset)
        stream << ",\"file_offset\":" << evidence_json_string(hexadecimal(snapshot.file_offset));
    stream << ",\"facts\":[";
    std::size_t emitted = 0;
    std::size_t available = 0;
    std::size_t scanned = 0;
    bool row_limit_hit = false;
    const auto append_rows = [&](const char* category,
                                 const std::vector<inspector_row_t>& rows) {
        for (const auto& row : rows) {
            if (scanned++ >= k_maximum_scanned_rows) {
                row_limit_hit = true;
                break;
            }
            if (row.value.empty() || row.value == "Unavailable")
                continue;
            ++available;
            if (emitted >= k_maximum_rows || stream.tellp() >=
                static_cast<std::streampos>(k_maximum_excerpt - 1024U))
                continue;
            if (emitted++ != 0)
                stream << ',';
            stream << "{\"category\":" << evidence_json_string(category, 64U)
                   << ",\"label\":" << evidence_json_string(row.label, 128U)
                   << ",\"value\":" << evidence_json_string(row.value) << '}';
        }
    };
    append_rows("operand", snapshot.operands);
    append_rows("xref", snapshot.xrefs);
    append_rows("call", snapshot.calls);
    append_rows("type", snapshot.types);
    append_rows("provenance", snapshot.provenance);
    stream << "]}";
    auto result = stream.str();
    truncated = row_limit_hit || available > emitted;
    if (result.size() > k_maximum_excerpt) {
        truncated = true;
        result = "{\"schema\":\"aida.inspector.selection.v1\","
            "\"trust\":\"untrusted_analysis_data\",\"truncated\":true,"
            "\"raw_bytes_included\":false,\"source_paths_included\":false,"
            "\"entity_kind\":" + evidence_json_string(snapshot.entity_kind, 128U) +
            ",\"display_name\":" + evidence_json_string(snapshot.display_name) + "}";
        if (result.size() > k_maximum_excerpt)
            return {};
    }
    return result;
}

inline bool register_inspector_evidence(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const aida::workbench::workbench_shell_workspace_context_t& shell,
    const inspector_view_snapshot_t& snapshot, std::string& evidence_id,
    std::string& reason) {
    if (!inspector_handoff_capability(workspace, shell, snapshot, reason))
        return false;
    bool truncated = false;
    const std::string excerpt = inspector_evidence_excerpt(snapshot, truncated);
    if (excerpt.empty()) {
        reason = "The Inspector selection could not be serialized as complete UTF-8 JSON within the 12 KiB evidence limit.";
        return false;
    }
    const std::uint64_t selection_hash = inspector_evidence_hash(
        std::to_string(snapshot.context.workspace.value) + ":" +
        std::to_string(static_cast<unsigned>(snapshot.context.document.kind)) + ":" +
        std::to_string(snapshot.context.document.object_id) + ":" +
        std::to_string(snapshot.context.document.variant_id) + ":" +
        snapshot.context.document.provider_key + ":" +
        std::to_string(snapshot.context.selection_generation) + ":" +
        std::to_string(static_cast<unsigned>(snapshot.context.selection.kind)) + ":" +
        std::to_string(snapshot.context.selection.address) + ":" +
        std::to_string(snapshot.context.selection.extent) + ":" +
        snapshot.context.selection.entity_key);
    const std::uint64_t provider_hash = inspector_evidence_hash(
        snapshot.context.document.provider_key);
    const std::uint64_t entity_hash = inspector_evidence_hash(
        snapshot.context.selection.entity_key);
    aida::automation_ui::evidence_envelope_t envelope;
    envelope.workspace_id = workspace->identity().binary_id().to_hex();
    envelope.source_view_id = "view.inspector";
    envelope.source_kind = "workbench_selection";
    envelope.entity_id = "selection:" + std::to_string(shell.workspace.value) + ":" +
        std::to_string(selection_hash);
    envelope.display_label = bounded_evidence_text(snapshot.display_name);
    envelope.return_target = "workbench:" + std::to_string(shell.workspace.value) +
        ":document:" + std::to_string(snapshot.context.document.object_id) +
        ":variant:" + std::to_string(snapshot.context.document.variant_id) +
        ":kind:" + std::to_string(static_cast<unsigned>(snapshot.context.document.kind)) +
        ":provider:" + std::to_string(provider_hash) +
        ":selection:" + std::to_string(snapshot.context.selection_generation) +
        ":selection-kind:" +
            std::to_string(static_cast<unsigned>(snapshot.context.selection.kind)) +
        ":entity:" + std::to_string(entity_hash) +
        (snapshot.context.selection.has_address
            ? ":address:" + hexadecimal(snapshot.context.selection.address)
            : std::string{}) +
        (snapshot.context.selection.extent != 0
            ? ":extent:" + std::to_string(snapshot.context.selection.extent)
            : std::string{});
    envelope.excerpt = excerpt;
    envelope.address = snapshot.context.selection.has_address
        ? snapshot.context.selection.address : 0;
    envelope.revision = snapshot.analysis_revision;
    envelope.generation = snapshot.analysis_generation;
    envelope.snapshot_hash = selection_hash ^ snapshot.overlay_revision;
    envelope.content_hash = inspector_evidence_hash(excerpt);
    envelope.truncated = truncated;
    envelope.sensitive = false;
    evidence_id = aida::automation_ui::register_evidence(std::move(envelope));
    if (evidence_id.empty()) {
        reason = "The bounded evidence registry rejected the Inspector selection identity.";
        return false;
    }
    reason.clear();
    return true;
}

inline void render_address_context(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    aida::workbench::workbench_shell_workspace_context_t& shell,
    const inspector_view_snapshot_t& snapshot, std::string& handoff_status) {
    const auto disassembly_context = disasm_view::capture_selected_workspace();
    const bool current_publication = snapshot.analysis_generation == shell.analysis_generation &&
        snapshot.analysis_revision == shell.analysis_revision &&
        snapshot.overlay_revision == shell.overlay_revision;
    const bool can_navigate = snapshot.context.selection.has_address && current_publication;
    const bool can_show_xrefs = can_navigate && disassembly_context.workspace == workspace &&
        disassembly_context.publication && disassembly_context.publication->snapshot;
    ImGui::PushID("workbench_inspector_address_actions");
    std::string handoff_reason;
    const bool can_handoff = inspector_handoff_capability(
        workspace, shell, snapshot, handoff_reason);
    static_cast<void>(ImGui::Selectable(
        "Selection actions", false, ImGuiSelectableFlags_AllowDoubleClick));
    const bool pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
    const bool menu_key_context = ImGui::IsItemFocused() &&
        ImGui::IsKeyPressed(ImGuiKey_Menu, false);
    const bool shift_f10_context = ImGui::IsItemFocused() &&
        ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
    const bool keyboard_context = menu_key_context || shift_f10_context;
    aida::ui::design::tooltip_for_last_item(
        "Right-click or press Menu / Shift+F10 for typed selection and evidence actions.",
        "Menu / Shift+F10", nullptr);
    if (pointer_context || keyboard_context) {
        aida::ui::application_ui::retained_entity_context_t context;
        context.owner_id = "workbench.inspector";
        context.entity_id = std::to_string(shell.workspace.value) + ":" +
            std::to_string(snapshot.context.selection_generation) + ":" +
            snapshot.context.selection.entity_key + ":" +
            std::to_string(snapshot.context.selection.address);
        context.entity_generation = snapshot.context.selection_generation;
        context.active_view = aida::ui::stable_view_id_t("view.inspector");
        context.validate_identity = workspace_identity_validator(workspace,
            snapshot.analysis_generation, snapshot.analysis_revision,
            snapshot.overlay_revision);
        const auto copy_value = [&context](const char* id, bool available,
            const char* reason, std::uint64_t value) {
            context.actions.push_back(retained_action(id, available, reason, [value] {
                const std::string text = hexadecimal(value);
                ImGui::SetClipboardText(text.c_str());
                return aida::ui::action_handler_result_t::completed();
            }));
        };
        copy_value("workbench.inspector.copy_va", snapshot.has_va,
            "The active selection has no verified virtual address mapping.", snapshot.va);
        copy_value("workbench.inspector.copy_rva", snapshot.has_rva,
            "The active selection has no verified module-relative mapping.", snapshot.rva);
        copy_value("workbench.inspector.copy_file_offset", snapshot.has_file_offset,
            "The active image cannot map this selection to a file offset.",
            snapshot.file_offset);
        const auto address = snapshot.context.selection.address;
        const auto entity_key = snapshot.context.selection.entity_key;
        auto disassembly_shell = shell;
        context.actions.push_back(retained_action(
            "workbench.inspector.follow_disassembly", can_navigate,
            "The pinned selection belongs to an older analysis or overlay revision.",
            [workspace, disassembly_shell, address, entity_key]() mutable {
                navigate(workspace, disassembly_shell, address, entity_key,
                    aida::workbench::document_kind_t::disassembly);
                return aida::ui::action_handler_result_t::completed();
            }));
        auto hex_shell = shell;
        context.actions.push_back(retained_action("workbench.inspector.follow_hex",
            can_navigate,
            "The pinned selection belongs to an older analysis or overlay revision.",
            [workspace, hex_shell, address, entity_key]() mutable {
                navigate(workspace, hex_shell, address, entity_key,
                    aida::workbench::document_kind_t::hex);
                return aida::ui::action_handler_result_t::completed();
            }));
        context.actions.push_back(retained_action("workbench.inspector.show_xrefs",
            can_show_xrefs, current_publication
                ? "The selected workspace has no published disassembly xref context."
                : "The pinned selection belongs to an older analysis or overlay revision.",
            [address, disassembly_context] {
                disasm_view::open_xrefs(address, disassembly_context);
                return aida::ui::action_handler_result_t::completed();
            }));
        const auto workspace_id = shell.workspace;
        auto chat_shell = shell;
        context.actions.push_back(retained_action("workbench.inspector.send_chat",
            can_handoff, handoff_reason.c_str(),
            [workspace, chat_shell, snapshot, workspace_id]() mutable {
                std::string evidence_id;
                std::string reason;
                auto& status = state_for(workspace_id).inspector_handoff_status;
                if (register_inspector_evidence(workspace, chat_shell, snapshot,
                        evidence_id, reason) &&
                    aida::automation_ui::queue_evidence_for_chat(evidence_id, reason)) {
                    status = "The current Inspector selection was attached to AI Chat.";
                    return aida::ui::action_handler_result_t::completed();
                }
                status = reason.empty()
                    ? "The Inspector selection could not be attached to AI Chat." : reason;
                return aida::ui::action_handler_result_t::failed(status);
            }));
        auto evidence_shell = shell;
        context.actions.push_back(retained_action("workbench.inspector.add_evidence",
            can_handoff, handoff_reason.c_str(),
            [workspace, evidence_shell, snapshot, workspace_id]() mutable {
                std::string evidence_id;
                std::string reason;
                auto& status = state_for(workspace_id).inspector_handoff_status;
                if (!register_inspector_evidence(workspace, evidence_shell, snapshot,
                        evidence_id, reason)) {
                    status = reason.empty()
                        ? "The Inspector selection could not be added to Evidence Review."
                        : reason;
                    return aida::ui::action_handler_result_t::failed(status);
                }
                const auto opened = aida::ui::application_views::open_or_focus(
                    aida::ui::stable_view_id_t("view.ai.evidence"));
                if (!opened.ok()) {
                    status = opened.detail.empty()
                        ? "Evidence Review is unavailable." : opened.detail;
                    return aida::ui::action_handler_result_t::failed(status);
                }
                status = "The current Inspector selection was added to Evidence Review.";
                return aida::ui::action_handler_result_t::completed();
            }));
        aida::ui::application_ui::open_retained_entity_context_menu(
            std::move(context), pointer_context
                ? aida::ui::context_menu_open_origin_t::pointer
                : menu_key_context
                ? aida::ui::context_menu_open_origin_t::menu_key
                : aida::ui::context_menu_open_origin_t::shift_f10);
    }
    aida::ui::application_ui::render_retained_entity_context_menu(
        "workbench.inspector");
    if (!handoff_status.empty())
        ImGui::TextWrapped("%s", handoff_status.c_str());
    ImGui::PopID();
}

inline void render_inspector_rows(const char* stable_id,
    const std::vector<inspector_row_t>& rows) {
    if (!aida::ui::design::begin_property_grid(stable_id))
        return;
    for (std::size_t index = 0; index < rows.size(); ++index) {
        const auto& row = rows[index];
        char id[32];
        std::snprintf(id, sizeof(id), "row.%llu",
            static_cast<unsigned long long>(index));
        const auto semantic = row.value == "Unavailable"
            ? aida::ui::design::semantic_t::stale
            : aida::ui::design::semantic_t::neutral;
        aida::ui::design::property_value(id, row.label.c_str(), row.value.c_str(),
            semantic, row.provenance.empty() ? nullptr : row.provenance.c_str());
    }
    aida::ui::design::end_property_grid();
}

inline void render_inspector_section(const char* title, const char* stable_id,
    const std::vector<inspector_row_t>& rows, bool open_by_default = false) {
    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_SpanAvailWidth;
    if (open_by_default)
        flags |= ImGuiTreeNodeFlags_DefaultOpen;
    if (!ImGui::CollapsingHeader(title, flags))
        return;
    render_inspector_rows(stable_id, rows);
}

inline bool diff_scope(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const aida::workbench::workbench_shell_workspace_context_t& context,
    aida::workbench::diff_document::diff_kind_t kind,
    aida::workbench::diff_document::diff_scope_t& scope) {
    scope = {};
    scope.kind = kind;
    scope.before.workspace_id = context.workspace.value;
    scope.after.workspace_id = context.workspace.value;
    scope.before.generation = context.analysis_generation;
    scope.after.generation = context.analysis_generation;
    if (kind == aida::workbench::diff_document::diff_kind_t::generation) {
        if (context.analysis_generation < 2)
            return false;
        scope.before.generation = context.analysis_generation - 1;
        return true;
    }
    if (kind == aida::workbench::diff_document::diff_kind_t::overlay) {
        if (context.overlay_revision == 0)
            return false;
        scope.before.overlay_revision = context.overlay_revision - 1;
        scope.after.overlay_revision = context.overlay_revision;
        return true;
    }
    for (const auto& other : aida::workbench::workbench_shell_runtime_t::instance()
            .analysis_workspaces()) {
        if (!other || other == workspace)
            continue;
        aida::workbench::workbench_shell_workspace_context_t other_context;
        const auto loaded = aida::workbench::workbench_shell_runtime_t::instance()
            .workspace_context(other, other_context);
        if (!loaded)
            continue;
        scope.after.workspace_id = other_context.workspace.value;
        scope.after.generation = other_context.analysis_generation;
        return true;
    }
    return false;
}

}

inline void render_navigator() {
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    aida::workbench::workbench_shell_workspace_context_t context;
    std::string failure;
    if (!detail::selected_context(workspace, context, failure)) {
        aida::ui::design::state_presentation_t empty;
        empty.stable_id = "workbench.navigator.no-workspace";
        empty.state = aida::ui::design::view_state_t::empty;
        empty.title = "No analysis workspace";
        empty.message = failure.c_str();
        static_cast<void>(aida::ui::design::render_state(empty, ImGui::GetContentRegionAvail()));
        return;
    }
    auto& state = detail::state_for(context.workspace);
    detail::synchronize_generation(state, context);
    using domain_t = aida::workbench::navigator::navigator_domain_t;
    constexpr std::array<std::pair<const char*, domain_t>, 6> domains{{
        {"Functions", domain_t::functions}, {"Imports", domain_t::imports},
        {"Exports", domain_t::exports}, {"Strings", domain_t::strings},
        {"Symbols", domain_t::symbols}, {"Types", domain_t::types}}};
    const char* preview = "Functions";
    for (const auto& domain : domains) {
        if (domain.second == state.navigator_domain) {
            preview = domain.first;
            break;
        }
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##workbench_navigator_domain", preview)) {
        for (const auto& domain : domains) {
            const bool selected = domain.second == state.navigator_domain;
            if (ImGui::Selectable(domain.first, selected)) {
                state.navigator_domain = domain.second;
                state.navigator_selected_id = 0;
            }
            if (selected)
                ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    if (!context.navigator_tree) {
        aida::ui::design::state_presentation_t disconnected;
        disconnected.stable_id = "workbench.navigator.disconnected";
        disconnected.state = aida::ui::design::view_state_t::disconnected;
        disconnected.title = "Navigator unavailable";
        disconnected.message = "The active workspace did not publish a Navigator provider for this revision.";
        const std::string target = std::to_string(context.workspace.value);
        disconnected.target = target.c_str();
        static_cast<void>(aida::ui::design::render_state(disconnected, ImGui::GetContentRegionAvail()));
        return;
    }
    aida::workbench::navigator::navigator_tree_request_t request;
    request.domain = state.navigator_domain;
    request.page.limit = 256;
    detail::frame_cancellation_t cancellation(20);
    aida::workbench::navigator::navigator_tree_page_t page;
    const auto loaded = context.navigator_tree->page(request, &cancellation, page);
    if (!loaded) {
        const std::string stage = "Provider status " + std::to_string(static_cast<unsigned>(loaded.code));
        aida::ui::design::state_presentation_t loading;
        loading.stable_id = "workbench.navigator.loading";
        loading.state = aida::ui::design::view_state_t::loading;
        loading.title = "Navigator materialization deferred";
        loading.message = "The provider has not published a coherent page for the active analysis revision yet.";
        loading.stage = stage.c_str();
        static_cast<void>(aida::ui::design::render_state(loading, ImGui::GetContentRegionAvail()));
        return;
    }
    if (page.rows.empty()) {
        aida::ui::design::state_presentation_t empty;
        empty.stable_id = "workbench.navigator.empty";
        empty.state = aida::ui::design::view_state_t::empty;
        empty.title = "No Navigator entries";
        empty.message = "The selected domain has no published entries in the active workspace revision.";
        static_cast<void>(aida::ui::design::render_state(empty, ImGui::GetContentRegionAvail()));
        return;
    }
    ImGui::TextDisabled("%llu items", static_cast<unsigned long long>(page.total_rows));
    ImGui::Separator();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(page.rows.size()));
    while (clipper.Step()) {
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
            const auto& row = page.rows[static_cast<std::size_t>(index)];
            ImGui::PushID(static_cast<int>(row.id.value & 0x7FFFFFFFU));
            const bool selected = state.navigator_selected_id == row.id.value;
            const std::string row_label(row.label);
            if (ImGui::Selectable(row_label.c_str(), selected)) {
                state.navigator_selected_id = row.id.value;
                if (row.has_address) {
                    state.last_address = row.address;
                    detail::navigate(workspace, context, row.address,
                        std::to_string(row.id.value),
                        aida::workbench::document_kind_t::disassembly);
                }
            }
            const bool menu_key_context = selected && ImGui::IsWindowFocused(
                ImGuiFocusedFlags_RootAndChildWindows) &&
                ImGui::IsKeyPressed(ImGuiKey_Menu, false);
            const bool shift_f10_context = selected && ImGui::IsWindowFocused(
                ImGuiFocusedFlags_RootAndChildWindows) && ImGui::GetIO().KeyShift &&
                ImGui::IsKeyPressed(ImGuiKey_F10, false);
            const bool keyboard_context = menu_key_context || shift_f10_context;
            const bool pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
            if (pointer_context || keyboard_context) {
                state.navigator_selected_id = row.id.value;
                aida::ui::application_ui::retained_entity_context_t retained;
                retained.owner_id = "workbench.navigator";
                retained.entity_id = std::to_string(context.workspace.value) + ":" +
                    std::to_string(row.id.value) + ":" + row_label;
                retained.entity_generation = context.analysis_generation;
                retained.active_view = aida::ui::stable_view_id_t("view.navigator");
                retained.validate_identity = detail::workspace_identity_validator(
                    workspace, context.analysis_generation, context.analysis_revision,
                    context.overlay_revision);
                const auto address = row.address;
                const auto entity = std::to_string(row.id.value);
                auto navigation_context = context;
                retained.actions.push_back(detail::retained_action(
                    "workbench.navigator.follow_disassembly", row.has_address,
                    "The retained Navigator entity has no address.",
                    [workspace, navigation_context, address, entity]() mutable {
                        detail::state_for(navigation_context.workspace).last_address = address;
                        detail::navigate(workspace, navigation_context, address, entity,
                            aida::workbench::document_kind_t::disassembly);
                        return aida::ui::action_handler_result_t::completed();
                    }));
                retained.actions.push_back(detail::retained_action(
                    "workbench.navigator.copy_address", row.has_address,
                    "The retained Navigator entity has no address.", [address] {
                        const std::string text = detail::hexadecimal(address);
                        ImGui::SetClipboardText(text.c_str());
                        return aida::ui::action_handler_result_t::completed();
                    }));
                retained.actions.push_back(detail::retained_action(
                    "workbench.navigator.copy_name", !row_label.empty(),
                    "The retained Navigator entity has no display name.", [row_label] {
                        ImGui::SetClipboardText(row_label.c_str());
                        return aida::ui::action_handler_result_t::completed();
                    }));
                aida::ui::application_ui::open_retained_entity_context_menu(
                    std::move(retained), pointer_context
                        ? aida::ui::context_menu_open_origin_t::pointer
                        : menu_key_context
                        ? aida::ui::context_menu_open_origin_t::menu_key
                        : aida::ui::context_menu_open_origin_t::shift_f10);
            }
            aida::ui::application_ui::render_retained_entity_context_menu(
                "workbench.navigator");
            ImGui::PopID();
        }
    }
}

inline void render_inspector() {
    const auto focused_view = aida::ui::application_views::registry().focused_instance();
    const bool programming_focused = focused_view &&
        focused_view->view.value() == "document.code";
    const bool inspector_focused = focused_view &&
        focused_view->view.value() == "view.inspector";
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    aida::workbench::workbench_shell_workspace_context_t context;
    std::string failure;
    const bool analysis_available = detail::selected_context(workspace, context, failure);
    auto& state = detail::state_for(analysis_available
        ? context.workspace : aida::workbench::workspace_id_t{});
    if (analysis_available)
        detail::synchronize_generation(state, context);
    const auto* active = analysis_available && context.inspector_session
        ? context.inspector_session->active_context() : nullptr;
    if (programming_focused && state.inspector_follow_selection &&
        !state.inspector_pinned) {
        const std::uint64_t document_id = code_editor_widget::active_document_id();
        auto document = code_editor_widget::document_state(document_id);
        const std::uint64_t document_revision = document.active && document_id != 0
            ? code_editor_widget::document_revision(document_id) : 0;
        if (!state.programming_live_valid ||
            !detail::programming_snapshot_matches(state.programming_live, document_id,
                document_revision, document)) {
            state.programming_live = detail::capture_programming_inspector_snapshot(
                document_id, document_revision, std::move(document));
            state.programming_live_valid = state.programming_live.document.active &&
                state.programming_live.document_id != 0;
            state.inspector_handoff_status.clear();
        }
        state.inspector_live_source = detail::inspector_source_t::programming;
    } else if (!active && state.inspector_follow_selection && !inspector_focused) {
        state.inspector_live = {};
        state.inspector_live_valid = false;
        state.inspector_live_source = detail::inspector_source_t::analysis;
        state.inspector_handoff_status.clear();
    }
    if (!programming_focused && !inspector_focused && active &&
        (state.inspector_follow_selection || !state.inspector_live_valid)) {
        const bool same_selection = state.inspector_live_valid &&
            aida::workbench::inspector::inspector_context_equal(
                state.inspector_live.context, *active) &&
            state.inspector_live.analysis_generation == context.analysis_generation &&
            state.inspector_live.analysis_revision == context.analysis_revision &&
            state.inspector_live.overlay_revision == context.overlay_revision;
        if (!same_selection) {
            state.inspector_live = detail::capture_inspector_snapshot(workspace, *active, context);
            state.inspector_live_valid = true;
            state.inspector_handoff_status.clear();
        }
        state.inspector_live_source = detail::inspector_source_t::analysis;
    }
    const auto selected_source = state.inspector_pinned
        ? state.inspector_pin_source : state.inspector_live_source;
    const auto* shown_analysis_before_controls =
        selected_source == detail::inspector_source_t::analysis
        ? state.inspector_pinned && state.inspector_pin
            ? &*state.inspector_pin
            : state.inspector_live_valid ? &state.inspector_live : nullptr
        : nullptr;
    const auto* shown_programming_before_controls =
        selected_source == detail::inspector_source_t::programming
        ? state.inspector_pinned && state.programming_pin
            ? &*state.programming_pin
            : state.programming_live_valid ? &state.programming_live : nullptr
        : nullptr;
    char revision[96];
    if (shown_analysis_before_controls) {
        std::snprintf(revision, sizeof(revision), "G%llu · A%llu · O%llu",
            static_cast<unsigned long long>(shown_analysis_before_controls->analysis_generation),
            static_cast<unsigned long long>(shown_analysis_before_controls->analysis_revision),
            static_cast<unsigned long long>(shown_analysis_before_controls->overlay_revision));
    } else if (shown_programming_before_controls) {
        std::snprintf(revision, sizeof(revision), "D%llu",
            static_cast<unsigned long long>(shown_programming_before_controls->revision));
    } else {
        std::snprintf(revision, sizeof(revision), "No synchronized revision");
    }
    const auto controls = aida::ui::design::inspector_controls("workbench.inspector.controls",
        state.inspector_follow_selection, state.inspector_pinned,
        state.inspector_pinned ? "Pinned snapshot" :
            selected_source == detail::inspector_source_t::programming
                ? "Focused code document" : "Global selection",
        revision);
    if (controls.follow_changed && !controls.pin_changed && state.inspector_pinned &&
        !state.inspector_follow_selection) {
        state.inspector_pinned = false;
        state.inspector_follow_selection = true;
    }
    if (controls.pin_changed) {
        state.inspector_handoff_status.clear();
        if (state.inspector_pinned &&
            state.inspector_live_source == detail::inspector_source_t::programming &&
            state.programming_live_valid) {
            state.programming_pin = state.programming_live;
            state.inspector_pin.reset();
            state.inspector_pin_source = detail::inspector_source_t::programming;
            state.inspector_follow_selection = false;
        } else if (state.inspector_pinned && state.inspector_live_valid) {
            state.inspector_pin = state.inspector_live;
            state.programming_pin.reset();
            state.inspector_pin_source = detail::inspector_source_t::analysis;
            state.inspector_follow_selection = false;
        } else if (state.inspector_pinned) {
            state.inspector_pinned = false;
            state.inspector_follow_selection = true;
        } else if (!state.inspector_pinned) {
            state.inspector_pin.reset();
            state.programming_pin.reset();
        }
    }
    if (state.inspector_follow_selection) {
        state.inspector_pinned = false;
        state.inspector_pin.reset();
        state.programming_pin.reset();
    }
    const auto source = state.inspector_pinned
        ? state.inspector_pin_source : state.inspector_live_source;
    const auto* shown = source == detail::inspector_source_t::analysis
        ? state.inspector_pinned && state.inspector_pin
            ? &*state.inspector_pin
            : state.inspector_live_valid ? &state.inspector_live : nullptr
        : nullptr;
    const auto* shown_programming = source == detail::inspector_source_t::programming
        ? state.inspector_pinned && state.programming_pin
            ? &*state.programming_pin
            : state.programming_live_valid ? &state.programming_live : nullptr
        : nullptr;
    ImGui::Separator();
    if (source == detail::inspector_source_t::programming) {
        if (!shown_programming) {
            aida::ui::design::state_presentation_t empty;
            empty.stable_id = "workbench.inspector.programming.empty";
            empty.state = aida::ui::design::view_state_t::empty;
            empty.title = "No programming document";
            empty.message = "Open or focus a source document to inspect its code context.";
            static_cast<void>(aida::ui::design::render_state(empty));
            return;
        }
        ImGui::TextUnformatted(shown_programming->document.filename.empty()
            ? "Untitled" : shown_programming->document.filename.c_str());
        if (!shown_programming->document.filepath.empty() &&
            shown_programming->document.filepath != shown_programming->document.filename)
            ImGui::TextDisabled("%s", shown_programming->document.filepath.c_str());
        detail::render_inspector_section("Identity", "workbench.inspector.programming.identity",
            shown_programming->identity, true);
        detail::render_inspector_section("Location", "workbench.inspector.programming.location",
            shown_programming->location, true);
        detail::render_inspector_section("Editing", "workbench.inspector.programming.editing",
            shown_programming->editing, true);
        return;
    }
    if (!shown) {
        aida::ui::design::state_presentation_t empty;
        empty.stable_id = analysis_available
            ? "workbench.inspector.empty" : "workbench.inspector.no-workspace";
        empty.state = aida::ui::design::view_state_t::empty;
        empty.title = analysis_available ? "Nothing selected" : "No analysis workspace";
        empty.message = analysis_available
            ? "Select an instruction, symbol, address, or document to inspect it."
            : failure.c_str();
        static_cast<void>(aida::ui::design::render_state(empty));
        return;
    }

    ImGui::TextUnformatted(shown->display_name.c_str());
    if (!shown->qualified_name.empty() && shown->qualified_name != shown->display_name)
        ImGui::TextDisabled("%s", shown->qualified_name.c_str());

    detail::render_inspector_section("Identity", "workbench.inspector.identity",
        shown->identity, true);
    detail::render_inspector_section("Location", "workbench.inspector.location",
        shown->location, true);
    detail::render_address_context(workspace, context, *shown,
        state.inspector_handoff_status);
    detail::render_inspector_section("Bytes", "workbench.inspector.bytes", shown->bytes, true);
    detail::render_inspector_section("Operands", "workbench.inspector.operands",
        shown->operands, true);
    detail::render_inspector_section("Cross-references", "workbench.inspector.xrefs",
        shown->xrefs, true);
    detail::render_inspector_section("Calls", "workbench.inspector.calls", shown->calls);
    detail::render_inspector_section("Stack / Locals", "workbench.inspector.stack",
        shown->stack_locals);
    detail::render_inspector_section("Types", "workbench.inspector.types", shown->types);
    detail::render_inspector_section("Overlays", "workbench.inspector.overlays",
        shown->overlays);
    detail::render_inspector_section("Diagnostics", "workbench.inspector.diagnostics",
        shown->diagnostics);
    detail::render_inspector_section("Source provenance", "workbench.inspector.provenance",
        shown->provenance);
}

inline void render_diff() {
    std::shared_ptr<aida::analysis::analysis_workspace_t> workspace;
    aida::workbench::workbench_shell_workspace_context_t context;
    std::string failure;
    if (!detail::selected_context(workspace, context, failure)) {
        ImGui::TextWrapped("%s", failure.c_str());
        return;
    }
    auto& state = detail::state_for(context.workspace);
    detail::synchronize_generation(state, context);
    if (!context.diff_document) {
        aida::ui::design::state_presentation_t disconnected;
        disconnected.stable_id = "workbench.diff.disconnected";
        disconnected.state = aida::ui::design::view_state_t::disconnected;
        disconnected.title = "Diff provider unavailable";
        disconnected.message = "The active workspace did not publish a Diff provider for this revision.";
        const std::string target = std::to_string(context.workspace.value);
        disconnected.target = target.c_str();
        static_cast<void>(aida::ui::design::render_state(disconnected, ImGui::GetContentRegionAvail()));
        return;
    }
    if (ImGui::RadioButton("Generation", state.diff_kind ==
            aida::workbench::diff_document::diff_kind_t::generation))
        state.diff_kind = aida::workbench::diff_document::diff_kind_t::generation;
    ImGui::SameLine();
    if (ImGui::RadioButton("Overlay", state.diff_kind ==
            aida::workbench::diff_document::diff_kind_t::overlay))
        state.diff_kind = aida::workbench::diff_document::diff_kind_t::overlay;
    ImGui::SameLine();
    if (ImGui::RadioButton("Workspace", state.diff_kind ==
            aida::workbench::diff_document::diff_kind_t::workspace))
        state.diff_kind = aida::workbench::diff_document::diff_kind_t::workspace;
    aida::workbench::diff_document::diff_scope_t scope;
    if (!detail::diff_scope(workspace, context, state.diff_kind, scope)) {
        aida::ui::design::state_presentation_t empty;
        empty.stable_id = "workbench.diff.missing-scope";
        empty.state = aida::ui::design::view_state_t::empty;
        empty.title = "No comparable revision";
        empty.message = "The selected diff requires another retained generation, overlay revision, or workspace.";
        static_cast<void>(aida::ui::design::render_state(empty, ImGui::GetContentRegionAvail()));
        return;
    }
    ImGui::BeginDisabled(state.diff_offset == 0);
    if (ImGui::Button("Previous"))
        state.diff_offset = state.diff_offset > 256 ? state.diff_offset - 256 : 0;
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(state.diff_total <= state.diff_offset + 256);
    if (ImGui::Button("Next"))
        state.diff_offset = (std::min)(state.diff_offset + 256,
            state.diff_total > 256 ? state.diff_total - 256 : 0);
    ImGui::EndDisabled();
    aida::workbench::diff_document::diff_page_t page;
    detail::frame_cancellation_t cancellation(30);
    const auto loaded = context.diff_document->page({state.diff_offset, 256,
        static_cast<aida::workbench::diff_document::diff_domain_t>(0xFF)},
        context.analysis_generation, scope, &cancellation, page);
    if (!loaded) {
        const std::string stage = "Provider status " + std::to_string(static_cast<unsigned>(loaded.code));
        aida::ui::design::state_presentation_t loading;
        loading.stable_id = "workbench.diff.loading";
        loading.state = aida::ui::design::view_state_t::loading;
        loading.title = "Diff materialization deferred";
        loading.message = "The provider has not published a coherent comparison page for the selected scope yet.";
        loading.stage = stage.c_str();
        static_cast<void>(aida::ui::design::render_state(loading, ImGui::GetContentRegionAvail()));
        return;
    }
    state.diff_total = page.total_entries;
    if (page.entries.empty()) {
        aida::ui::design::state_presentation_t empty;
        empty.stable_id = "workbench.diff.empty";
        empty.state = aida::ui::design::view_state_t::empty;
        empty.title = "No differences";
        empty.message = "The selected revisions contain no changes in this diff domain.";
        static_cast<void>(aida::ui::design::render_state(empty, ImGui::GetContentRegionAvail()));
        return;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%llu changes", static_cast<unsigned long long>(state.diff_total));
    ImGui::Separator();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(page.entries.size()));
    bool keyboard_context_consumed = false;
    while (clipper.Step()) {
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
            const auto& entry = page.entries[static_cast<std::size_t>(index)];
            char label[2048];
            std::snprintf(label, sizeof(label), "%016llX  %s  %s -> %s##workbench_diff_%llu",
                static_cast<unsigned long long>(entry.address), entry.entity_key.c_str(),
                entry.old_value.c_str(), entry.new_value.c_str(),
                static_cast<unsigned long long>(page.offset + static_cast<std::size_t>(index)));
            const bool selected = state.last_address != 0 && state.last_address == entry.address;
            if (ImGui::Selectable(label, selected) && entry.address != 0) {
                state.last_address = entry.address;
                detail::navigate(workspace, context, entry.address, entry.entity_key,
                    aida::workbench::document_kind_t::diff);
            }
            const bool pointer_context = ImGui::IsItemClicked(ImGuiMouseButton_Right);
            const bool menu_key_context = !keyboard_context_consumed && selected &&
                ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
                ImGui::IsKeyPressed(ImGuiKey_Menu, false);
            const bool shift_f10_context = !keyboard_context_consumed && selected &&
                ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
                ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false);
            const bool keyboard_context = menu_key_context || shift_f10_context;
            if (pointer_context || keyboard_context) {
                keyboard_context_consumed = keyboard_context;
                if (entry.address != 0)
                    state.last_address = entry.address;
                aida::ui::application_ui::retained_entity_context_t retained;
                retained.owner_id = "workbench.diff";
                retained.entity_id = std::to_string(context.workspace.value) + ":" +
                    std::to_string(page.offset + static_cast<std::size_t>(index)) + ":" +
                    std::to_string(std::hash<std::string>{}(entry.entity_key)) + ":" +
                    std::to_string(entry.address);
                retained.entity_generation = context.analysis_generation;
                retained.active_view = aida::ui::stable_view_id_t("document.diff");
                retained.validate_identity = detail::workspace_identity_validator(
                    workspace, context.analysis_generation, context.analysis_revision,
                    context.overlay_revision);
                const auto address = entry.address;
                const auto entity = entry.entity_key;
                auto navigation_context = context;
                retained.actions.push_back(detail::retained_action(
                    "workbench.diff.follow", address != 0,
                    "The retained change has no navigable address.",
                    [workspace, navigation_context, address, entity]() mutable {
                        detail::state_for(navigation_context.workspace).last_address = address;
                        detail::navigate(workspace, navigation_context, address, entity,
                            aida::workbench::document_kind_t::diff);
                        return aida::ui::action_handler_result_t::completed();
                    }));
                retained.actions.push_back(detail::retained_action(
                    "workbench.diff.copy_address", address != 0,
                    "The retained change has no address.", [address] {
                        const std::string text = detail::hexadecimal(address);
                        ImGui::SetClipboardText(text.c_str());
                        return aida::ui::action_handler_result_t::completed();
                    }));
                const std::string before = entry.old_value;
                retained.actions.push_back(detail::retained_action(
                    "workbench.diff.copy_before", true, "", [before] {
                        ImGui::SetClipboardText(before.c_str());
                        return aida::ui::action_handler_result_t::completed();
                    }));
                const std::string after = entry.new_value;
                retained.actions.push_back(detail::retained_action(
                    "workbench.diff.copy_after", true, "", [after] {
                        ImGui::SetClipboardText(after.c_str());
                        return aida::ui::action_handler_result_t::completed();
                    }));
                aida::ui::application_ui::open_retained_entity_context_menu(
                    std::move(retained), pointer_context
                        ? aida::ui::context_menu_open_origin_t::pointer
                        : menu_key_context
                        ? aida::ui::context_menu_open_origin_t::menu_key
                        : aida::ui::context_menu_open_origin_t::shift_f10);
            }
            aida::ui::application_ui::render_retained_entity_context_menu(
                "workbench.diff");
        }
    }
}

}
