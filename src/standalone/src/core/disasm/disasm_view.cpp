#include "disasm_view.hpp"

#include "comment_dialog.hpp"
#include "file_metadata_banner.hpp"
#include "pseudocode_view.hpp"
#include "rename_dialog.hpp"
#include "rename_store.hpp"
#include "comment_store.hpp"
#include "../analysis/auto_comment_store.hpp"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/disasm_preview_adapter.hpp"
#else
#include "../analysis/source_reconstruct_view.hpp"
#endif
#include "../analysis/workspace/overlay_journal.hpp"
#include "../analysis/workspace/workspace_registry.hpp"
#include "../analysis/workspace/x86_decoder.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../infra/taskflow_runtime.hpp"
#include "../scanner/aob_generator.hpp"
#include "../scanner/scan_hub_view.hpp"
#endif
#include "../ui/components.hpp"
#include "../ui/analysis_context_menu.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/metrics.hpp"
#include "../ui/theme.hpp"
#include "../../helpers/globals.h"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/diag_log.hpp"
#endif

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <fstream>
#endif
#include <limits>
#include <shared_mutex>
#include <unordered_map>
#include <utility>

namespace disasm_view {

struct workspace_model_t {
    explicit workspace_model_t(const aida::analysis::binary_id_t& id)
        : comments(id), renames(id), automatic_comments(id),
          view(std::make_shared<state_t>()) {}

    comment_store::workspace_store_t comments;
    rename_store::workspace_store_t renames;
    auto_comment_store::workspace_store_t automatic_comments;
    std::shared_ptr<state_t> view;
    std::mutex mutation_mutex;
    std::mutex initialization_mutex;
    std::atomic<bool> initialized{false};
    std::atomic<std::uint32_t> format_generation{1};
};

namespace {

using namespace aida::analysis;

std::mutex& model_registry_mutex() {
    static std::mutex value;
    return value;
}

std::unordered_map<binary_id_t, std::weak_ptr<workspace_model_t>, binary_id_hash_t>&
model_registry() {
    static std::unordered_map<binary_id_t, std::weak_ptr<workspace_model_t>, binary_id_hash_t> value;
    return value;
}

std::shared_ptr<workspace_model_t> model_for(const std::shared_ptr<analysis_workspace_t>& workspace) {
    if (!workspace)
        return {};
    const auto id = workspace->identity().binary_id();
    std::lock_guard<std::mutex> lock(model_registry_mutex());
    auto& registry = model_registry();
    for (auto it = registry.begin(); it != registry.end();) {
        if (it->second.expired())
            it = registry.erase(it);
        else
            ++it;
    }
    auto found = registry.find(id);
    if (found != registry.end()) {
        if (auto existing = found->second.lock())
            return existing;
    }
    auto created = std::make_shared<workspace_model_t>(id);
    registry[id] = created;
    return created;
}

void initialize_model(const std::shared_ptr<analysis_workspace_t>& workspace,
                      const std::shared_ptr<workspace_model_t>& model) {
    if (!workspace || !model || model->initialized.load(std::memory_order_acquire))
        return;
    std::lock_guard<std::mutex> lock(model->initialization_mutex);
    if (model->initialized.load(std::memory_order_acquire))
        return;
    if (auto overlay = workspace->overlay()) {
        const auto snapshot = overlay->snapshot();
        for (const auto& item : snapshot.items) {
            const auto& operation = item.second;
            switch (operation.kind) {
            case overlay_operation_kind_t::comment:
                model->comments.set(operation.address, operation.text);
                break;
            case overlay_operation_kind_t::name:
                model->renames.set(operation.address, operation.name);
                break;
            case overlay_operation_kind_t::bookmark: {
                const auto runtime = operation.address.value;
                std::lock_guard<std::mutex> view_lock(model->view->mutex);
                auto found = std::find_if(model->view->bookmarks.begin(),
                    model->view->bookmarks.end(), [&](const bookmark_t& bookmark) {
                        return bookmark.addr == runtime;
                    });
                if (operation.name.empty()) {
                    if (found != model->view->bookmarks.end())
                        model->view->bookmarks.erase(found);
                } else if (found == model->view->bookmarks.end()) {
                    model->view->bookmarks.push_back({runtime, operation.name});
                } else {
                    found->label = operation.name;
                }
                break;
            }
            default:
                break;
            }
        }
    }
    model->initialized.store(true, std::memory_order_release);
}

std::optional<std::uint64_t> checked_add(std::uint64_t left, std::uint64_t right) {
    if (right > (std::numeric_limits<std::uint64_t>::max)() - left)
        return {};
    return left + right;
}

std::optional<std::uint64_t> optional_value(
    aida::analysis::workspace_result_t<std::uint64_t> result) {
    if (!result)
        return {};
    return result.take_value();
}

std::optional<std::uint64_t> display_base_override(const workspace_context_t& context) {
    if (!context.view)
        return {};
    std::lock_guard<std::mutex> lock(context.view->mutex);
    return context.view->display_image_base;
}

std::uint64_t display_image_base(const workspace_context_t& context) {
    if (const auto value = display_base_override(context))
        return *value;
    return context.image ? context.image->image_base() : 0;
}

std::string byte_text(const byte_view_t& view, std::uint64_t view_offset,
                      std::uint64_t instruction_offset, std::uint8_t length) {
    if (instruction_offset < view_offset)
        return {};
    const std::uint64_t relative = instruction_offset - view_offset;
    if (relative > view.size() || length > view.size() - static_cast<std::size_t>(relative))
        return {};
    std::string output;
    output.reserve(static_cast<std::size_t>(length) * 3);
    char buffer[4]{};
    for (std::uint8_t index = 0; index < length; ++index) {
        std::snprintf(buffer, sizeof(buffer), "%02X",
            view[static_cast<std::size_t>(relative) + index]);
        if (!output.empty())
            output.push_back(' ');
        output.append(buffer);
    }
    return output;
}

std::uint64_t format_page_key(const workspace_context_t& context,
                              std::size_t begin, std::size_t end) {
    std::uint64_t value = context.publication ? context.publication->generation : 0;
    value ^= (context.publication ? context.publication->analysis_revision : 0) *
             0x9E3779B185EBCA87ULL;
    value ^= (context.publication ? context.publication->overlay_revision : 0) *
             0xC2B2AE3D27D4EB4FULL;
    value ^= static_cast<std::uint64_t>(begin) * 0x165667B19E3779F9ULL;
    value ^= static_cast<std::uint64_t>(end) * 0x85EBCA77C2B2AE63ULL;
    return value;
}

std::optional<std::pair<std::size_t, std::size_t>> instruction_range(
    const workspace_context_t& context) {
    if (!context || !context.publication->snapshot)
        return {};
    const auto& instructions = context.publication->snapshot->instructions;
    std::size_t begin = 0;
    std::size_t end = instructions.size();
    int section_index = -1;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        section_index = context.view->active_section;
    }
    if (section_index < 0 || !context.image ||
        static_cast<std::size_t>(section_index) >= context.image->sections().size())
        return std::make_pair(begin, end);
    const auto& section = context.image->sections()[static_cast<std::size_t>(section_index)];
    const auto section_end = checked_add(section.virtual_address,
        (std::max)(section.virtual_size, section.raw_size));
    if (!section_end)
        return {};
    const auto lower = std::lower_bound(instructions.begin(), instructions.end(),
        section.virtual_address, [](const instruction_record_t& instruction, std::uint64_t rva) {
            return instruction.address.value < rva;
        });
    const auto upper = std::lower_bound(lower, instructions.end(), *section_end,
        [](const instruction_record_t& instruction, std::uint64_t rva) {
            return instruction.address.value < rva;
        });
    begin = static_cast<std::size_t>(std::distance(instructions.begin(), lower));
    end = static_cast<std::size_t>(std::distance(instructions.begin(), upper));
    return std::make_pair(begin, end);
}

void publish_format_failure(const workspace_context_t& context,
                            std::uint64_t page_key, std::string error) {
    if (!context.view)
        return;
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->pending_format_pages.erase(page_key);
    context.view->format_error = std::move(error);
}

void request_format_page(const workspace_context_t& context,
                         std::size_t begin, std::size_t end) {
    if (!context || !context.publication->snapshot || !context.image || begin >= end ||
        end > context.publication->snapshot->instructions.size())
        return;
    const auto page_key = format_page_key(context, begin, end);
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        if (!context.view->pending_format_pages.insert(page_key).second)
            return;
    }
    const auto format_body = [context, begin, end, page_key](const std::atomic<bool>& cancelled) {
        if (cancelled.load(std::memory_order_acquire) ||
            context.workspace->cancellation_token().stop_requested()) {
            publish_format_failure(context, page_key, "Formatting cancelled.");
            return;
        }
        auto decoder_result = worker_owned_x86_decoder_t::create(
            context.image->architecture_mode());
        if (!decoder_result) {
            publish_format_failure(context, page_key, decoder_result.error().message);
            return;
        }
        auto decoder = decoder_result.take_value();
        const auto& instructions = context.publication->snapshot->instructions;
        std::vector<std::uint64_t> offsets(end - begin, 0);
        std::uint64_t minimum = (std::numeric_limits<std::uint64_t>::max)();
        std::uint64_t maximum = 0;
        bool contiguous_lease = true;
        for (std::size_t index = begin; index < end; ++index) {
            const auto offset = provider_offset(context, instructions[index].address);
            if (!offset) {
                contiguous_lease = false;
                continue;
            }
            offsets[index - begin] = *offset;
            minimum = (std::min)(minimum, *offset);
            const auto finish = checked_add(*offset, instructions[index].length);
            if (!finish) {
                contiguous_lease = false;
                continue;
            }
            maximum = (std::max)(maximum, *finish);
        }
        constexpr std::uint64_t maximum_page_lease = 8ULL << 20;
        if (minimum == (std::numeric_limits<std::uint64_t>::max)() || maximum < minimum ||
            maximum - minimum > maximum_page_lease)
            contiguous_lease = false;
        byte_view_t page_view;
        if (contiguous_lease) {
            auto lease = context.workspace->provider().lease(minimum, maximum - minimum,
                context.workspace->cancellation_token());
            if (lease)
                page_view = lease.take_value();
            else
                contiguous_lease = false;
        }
        std::unordered_map<entity_id_t, formatted_instruction_t> completed;
        completed.reserve(end - begin);
        instruction_format_options_t options;
        options.maximum_text_bytes = 2048;
        for (std::size_t index = begin; index < end; ++index) {
            if (cancelled.load(std::memory_order_acquire) ||
                context.workspace->cancellation_token().stop_requested())
                break;
            const auto& instruction = instructions[index];
            formatted_instruction_t row;
            row.instruction_id = instruction.id;
            row.generation = context.publication->generation;
            row.analysis_revision = context.publication->analysis_revision;
            row.overlay_revision = context.publication->overlay_revision;
            row.runtime_address = runtime_address(context, instruction.address).value_or(
                instruction.address.value);
            workspace_result_t<std::string> formatted = contiguous_lease
                ? decoder->format_one(page_view, minimum, context.workspace->provider(),
                    *context.image, instruction, options,
                    context.workspace->cancellation_token())
                : decoder->format_one(context.workspace->provider(), *context.image,
                    instruction, options, context.workspace->cancellation_token());
            if (formatted)
                row.text = formatted.take_value();
            else
                row.error = formatted.error().stable_code() + ": " + formatted.error().message;
            const auto offset = offsets[index - begin];
            if (contiguous_lease) {
                row.bytes = byte_text(page_view, minimum, offset, instruction.length);
            } else {
                auto lease = context.workspace->provider().lease(offset, instruction.length,
                    context.workspace->cancellation_token());
                if (lease)
                    row.bytes = byte_text(lease.value(), offset, offset, instruction.length);
            }
            completed.emplace(instruction.id, std::move(row));
        }
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->pending_format_pages.erase(page_key);
        if (!context.workspace || context.workspace->closed() ||
            context.workspace->generation() != context.publication->generation)
            return;
        for (auto& item : completed)
            context.view->formatted.insert_or_assign(item.first, std::move(item.second));
        context.view->format_error.clear();
    };
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const std::atomic<bool> cancelled{false};
    format_body(cancelled);
    aida::preview::disasm::record("format_visible_disassembly", begin,
        std::to_string(end - begin));
#else
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "analysis_ui";
    descriptor.label = "format_visible_disassembly";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [format_body](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
        format_body(runtime_cancel.requested);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted)
        publish_format_failure(context, page_key,
            submitted.reject_reason.empty() ? "Formatting queue rejected the page." :
                                               submitted.reject_reason);
#endif
}

void apply_committed_operation(const workspace_context_t& context,
                               const overlay_operation_t& operation) {
    if (!context.model)
        return;
    switch (operation.kind) {
    case overlay_operation_kind_t::comment:
        context.model->comments.set(operation.address, operation.text);
        break;
    case overlay_operation_kind_t::name:
        context.model->renames.set(operation.address, operation.name);
        break;
    case overlay_operation_kind_t::bookmark: {
        const auto stable_address = operation.address.value;
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            auto found = std::find_if(context.view->bookmarks.begin(),
                context.view->bookmarks.end(), [&](const bookmark_t& bookmark) {
                    return bookmark.addr == stable_address;
                });
            if (operation.name.empty()) {
                if (found != context.view->bookmarks.end())
                    context.view->bookmarks.erase(found);
            } else if (found == context.view->bookmarks.end()) {
                context.view->bookmarks.push_back({stable_address, operation.name});
            } else {
                found->label = operation.name;
            }
        }
        context.workspace->update_view_state([&](workspace_view_state_t& state) {
            auto found = std::find(state.bookmarks.begin(), state.bookmarks.end(), operation.address);
            if (operation.name.empty()) {
                if (found != state.bookmarks.end())
                    state.bookmarks.erase(found);
            } else if (found == state.bookmarks.end()) {
                state.bookmarks.push_back(operation.address);
            }
        });
        break;
    }
    default:
        break;
    }
}

bool queue_overlay_transaction(const workspace_context_t& context,
                               std::vector<overlay_operation_t> operations) {
    if (!context || context.workspace->closing() || context.workspace->closed() ||
        !context.workspace->overlay() || operations.empty())
        return false;
    const auto expected_generation = context.workspace->generation();
    const auto expected_analysis_revision = context.workspace->analysis_revision();
    const auto expected_overlay_revision = context.workspace->overlay_revision();
    context.view->pending_mutations.fetch_add(1, std::memory_order_acq_rel);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const auto preview_kind = operations.front().kind;
    const auto preview_address = operations.front().address.value;
#endif
    auto mutation_body = [context, operations = std::move(operations),
                          expected_generation, expected_analysis_revision,
                          expected_overlay_revision](
        bool cancelled) mutable {
        std::string error;
        if (cancelled) {
            error = "Mutation cancelled before execution.";
        } else if (context.workspace->generation() != expected_generation ||
                   context.workspace->analysis_revision() != expected_analysis_revision) {
            error = "The analysis publication changed before the mutation ran; select the item and retry.";
        } else {
            std::lock_guard<std::mutex> mutation_lock(context.model->mutation_mutex);
            auto overlay = context.workspace->overlay();
            if (!overlay) {
                error = "Workspace overlay is unavailable.";
            } else {
                overlay_transaction_request_t request;
                request.expected_revision = expected_overlay_revision;
                request.operations = operations;
                auto result = overlay->transact(request, context.workspace->cancellation_token());
                if (result) {
                    for (const auto& operation : operations)
                        apply_committed_operation(context, operation);
                } else {
                    error = result.error().stable_code() + ": " + result.error().message;
                }
            }
        }
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->mutation_error = std::move(error);
            context.view->formatted.clear();
            context.view->cached_overlay_revision = context.workspace->overlay_revision();
        }
        context.view->pending_mutations.fetch_sub(1, std::memory_order_acq_rel);
    };
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    mutation_body(false);
    bool succeeded = false;
    std::string mutation_detail;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        succeeded = context.view->mutation_error.empty();
        mutation_detail = succeeded
            ? std::to_string(static_cast<unsigned>(preview_kind))
            : context.view->mutation_error;
    }
    aida::preview::disasm::record("workspace_overlay_mutation", preview_address,
        std::move(mutation_detail));
    return succeeded;
#else
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "analysis_ui";
    descriptor.label = "workspace_overlay_mutation";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [mutation_body = std::move(mutation_body)](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) mutable {
        mutation_body(runtime_cancel.requested.load(std::memory_order_acquire));
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        context.view->pending_mutations.fetch_sub(1, std::memory_order_acq_rel);
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->mutation_error = submitted.reject_reason.empty()
            ? "Mutation queue rejected the request." : submitted.reject_reason;
        return false;
    }
    return true;
#endif
}

bool queue_overlay_operation(const workspace_context_t& context,
                             overlay_operation_t operation) {
    std::vector<overlay_operation_t> operations;
    operations.push_back(std::move(operation));
    return queue_overlay_transaction(context, std::move(operations));
}

std::string address_label(const workspace_context_t& context,
                          const address_t& address, addr_format_t format) {
    char buffer[48]{};
    if (format == addr_format_t::rva) {
        std::uint64_t rva = address.value;
        if (address.space != address_space_id_t::relative_virtual && context.image) {
            const auto runtime = runtime_address(context, address);
            if (runtime) {
                const auto base = display_base_override(context);
                const auto translated = base && *runtime >= *base
                    ? std::optional<std::uint64_t>(*runtime - *base)
                    : optional_value(context.image->va_to_rva(*runtime));
                if (translated)
                    rva = *translated;
            }
        }
        std::snprintf(buffer, sizeof(buffer), "+%08llX",
            static_cast<unsigned long long>(rva));
    } else if (format == addr_format_t::file_offset) {
        const auto offset = provider_offset(context, address);
        if (offset)
            std::snprintf(buffer, sizeof(buffer), "%08llX",
                static_cast<unsigned long long>(*offset));
        else
            std::snprintf(buffer, sizeof(buffer), "--------");
    } else {
        std::snprintf(buffer, sizeof(buffer), "%016llX",
            static_cast<unsigned long long>(runtime_address(context, address).value_or(address.value)));
    }
    return buffer;
}

std::optional<std::uint64_t> parse_address_text(const workspace_context_t& context,
                                                std::string text) {
    text.erase(text.begin(), std::find_if(text.begin(), text.end(), [](char value) {
        return value != ' ' && value != '\t';
    }));
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.pop_back();
    if (text.empty())
        return {};
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text.erase(0, 2);
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (parsed.ec == std::errc() && parsed.ptr == text.data() + text.size())
        return value;
    if (context.publication && context.publication->snapshot) {
        const auto& symbols = context.publication->snapshot->symbols;
        auto found = std::find_if(symbols.begin(), symbols.end(), [&](const symbol_record_t& symbol) {
            return symbol.name == text;
        });
        if (found != symbols.end())
            return runtime_address(context, found->address);
    }
    return {};
}

void render_xref_popup(const workspace_context_t& context) {
    if (!context.view)
        return;
    bool open = false;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        open = context.view->xref_popup_open;
    }
    if (open)
        ImGui::OpenPopup("Cross references##workspace_xrefs");
    if (!ImGui::BeginPopupModal("Cross references##workspace_xrefs", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize))
        return;
    std::vector<xref_popup_entry_t> entries;
    bool scanning = false;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        entries = context.view->xref_results;
        scanning = context.view->xref_scanning.load(std::memory_order_acquire);
    }
    static_cast<void>(aida::ui::search_field("xref_filter",
        context.view->xref_popup_filter, sizeof(context.view->xref_popup_filter),
        "Filter by name or address", 620.0f));
    if (scanning)
        aida::ui::inline_notice("xref_scanning", "Searching cross references",
            "Querying the workspace index for matching callers and targets.",
            aida::ui::status_kind_t::info);
    ImGui::BeginChild("##xref_rows", ImVec2(620.0f, 320.0f), true);
    const std::string filter(context.view->xref_popup_filter);
    std::size_t visible_entries = 0;
    for (const auto& entry : entries) {
        char address[32]{};
        std::snprintf(address, sizeof(address), "%016llX",
            static_cast<unsigned long long>(entry.addr));
        if (!filter.empty() && entry.function_name.find(filter) == std::string::npos &&
            std::string(address).find(filter) == std::string::npos)
            continue;
        ++visible_entries;
        std::string label = std::string(address) + "  " + entry.function_name;
        if (ImGui::Selectable(label.c_str(), false,
                ImGuiSelectableFlags_AllowDoubleClick) &&
            ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            goto_address(entry.addr, context);
            ImGui::CloseCurrentPopup();
        }
    }
    if (visible_entries == 0 && !scanning)
        aida::ui::compact_empty_state("xref_empty", "No cross references found",
            filter.empty() ? "No indexed references target this location."
                           : "No references match the current filter.",
            nullptr, ImVec2(0.0f, 140.0f));
    ImGui::EndChild();
    if (aida::ui::button("Close", aida::ui::button_kind_t::secondary,
            aida::ui::size_t_::sm, ImVec2(110.0f, 28.0f))) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->xref_popup_open = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void request_listing_export(const workspace_context_t& context) {
    if (!context || !context.image || !context.publication ||
        !context.publication->snapshot ||
        context.view->export_pending.exchange(true, std::memory_order_acq_rel))
        return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const auto count = context.publication->snapshot->instructions.size();
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->export_error.clear();
        context.view->export_status = "Exported " + std::to_string(count) +
            " instructions to aida_disasm_dump.txt.";
    }
    context.view->export_pending.store(false, std::memory_order_release);
    aida::preview::disasm::record("export_workspace_disassembly", count,
        "aida_disasm_dump.txt");
#else
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->export_error.clear();
        context.view->export_status = "Exporting full listing...";
    }
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    const std::string export_path = "aida_disasm_dump.txt";
    const std::string temporary_path = export_path + "." + target_id + "." +
        std::to_string(context.publication->generation) + ".tmp";
    const auto presentation_base = display_base_override(context);
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::long_running;
    descriptor.owner_subsystem = "analysis_ui";
    descriptor.label = "export_workspace_disassembly";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, export_path, temporary_path, presentation_base](
        const aida::infra::taskflow_runtime::cancellation_token_t& runtime_cancel) {
        std::string error;
        std::size_t written = 0;
        std::ofstream output(temporary_path, std::ios::binary | std::ios::trunc);
        if (!output) {
            error = "Unable to open aida_disasm_dump.txt for writing.";
        } else {
            auto decoder_result = worker_owned_x86_decoder_t::create(
                context.image->architecture_mode());
            if (!decoder_result) {
                error = decoder_result.error().stable_code() + ": " +
                    decoder_result.error().message;
            } else {
                auto decoder = decoder_result.take_value();
                instruction_format_options_t options;
                options.maximum_text_bytes = 2048;
                for (const auto& instruction : context.publication->snapshot->instructions) {
                    if (runtime_cancel.requested.load(std::memory_order_acquire) ||
                        context.workspace->cancellation_token().stop_requested()) {
                        error = "Listing export cancelled.";
                        break;
                    }
                    const auto formatted = decoder->format_one(context.workspace->provider(),
                        *context.image, instruction, options,
                        context.workspace->cancellation_token());
                    if (!formatted) {
                        error = formatted.error().stable_code() + ": " + formatted.error().message;
                        break;
                    }
                    std::string bytes;
                    if (const auto offset = provider_offset(context, instruction.address)) {
                        auto lease = context.workspace->provider().lease(*offset,
                            instruction.length, context.workspace->cancellation_token());
                        if (lease)
                            bytes = byte_text(lease.value(), *offset, *offset, instruction.length);
                    }
                    std::uint64_t display_address = instruction.address.value;
                    if (presentation_base && instruction.address.space ==
                        aida::analysis::address_space_id_t::relative_virtual) {
                        display_address = checked_add(*presentation_base,
                            instruction.address.value).value_or(instruction.address.value);
                    } else {
                        display_address = runtime_address(context,
                            instruction.address).value_or(instruction.address.value);
                    }
                    char address[32]{};
                    std::snprintf(address, sizeof(address), "%016llX",
                        static_cast<unsigned long long>(display_address));
                    output << address << "  " << bytes << "  " << formatted.value() << "\r\n";
                    if (!output) {
                        error = "Writing aida_disasm_dump.txt failed.";
                        break;
                    }
                    ++written;
                }
            }
        }
        output.close();
        if (error.empty() && !MoveFileExA(temporary_path.c_str(), export_path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            error = "Replacing aida_disasm_dump.txt failed with Win32 error " +
                std::to_string(GetLastError()) + ".";
        }
        if (!error.empty())
            DeleteFileA(temporary_path.c_str());
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->export_error = std::move(error);
            context.view->export_status = context.view->export_error.empty()
                ? "Exported " + std::to_string(written) +
                    " instructions to aida_disasm_dump.txt."
                : std::string();
        }
        context.view->export_pending.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        context.view->export_pending.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->export_status.clear();
        context.view->export_error = submitted.reject_reason.empty()
            ? "Listing export queue rejected the request." : submitted.reject_reason;
    }
#endif
}

}

workspace_context_t capture_workspace(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace) {
    workspace_context_t context;
    if (!workspace || workspace->closed())
        return context;
    context.workspace = workspace;
    context.publication = workspace->analysis_publication();
    context.image = context.publication && context.publication->snapshot
        ? context.publication->snapshot->image : workspace->image();
    context.model = model_for(workspace);
    context.view = context.model ? context.model->view : nullptr;
    context.progress = workspace->progress();
    initialize_model(workspace, context.model);
    if (context.view && context.publication) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        if (context.view->cached_generation != context.publication->generation ||
            context.view->cached_analysis_revision != context.publication->analysis_revision ||
            context.view->cached_overlay_revision != context.publication->overlay_revision) {
            context.view->formatted.clear();
            context.view->pending_format_pages.clear();
            context.view->cached_generation = context.publication->generation;
            context.view->cached_analysis_revision = context.publication->analysis_revision;
            context.view->cached_overlay_revision = context.publication->overlay_revision;
            context.model->format_generation.fetch_add(1, std::memory_order_acq_rel);
        }
        context.view->selection = workspace->view_state().selection;
    }
    return context;
}

workspace_context_t capture_selected_workspace() {
    return capture_workspace(aida::analysis::workspace_registry().selected_for_ui());
}

std::optional<aida::analysis::address_t> typed_address(
    const workspace_context_t& context, std::uint64_t value) {
    if (!context.workspace)
        return {};
    const auto& identity = context.workspace->identity();
    aida::analysis::address_t address;
    address.architecture = identity.architecture();
    address.mode = context.image ? context.image->architecture_mode() :
        (identity.architecture() == aida::analysis::architecture_id_t::x86_64
            ? aida::analysis::architecture_mode_t::x86_64
            : aida::analysis::architecture_mode_t::x86_32);
    if (identity.target_kind() == aida::analysis::target_kind_t::live_snapshot) {
        address.space = aida::analysis::address_space_id_t::live_virtual;
        address.value = value;
        return address;
    }
    if (!context.image)
        return {};
    const auto display_base = display_base_override(context);
    const std::uint64_t base = display_base.value_or(context.image->image_base());
    if (value >= base) {
        std::optional<std::uint64_t> rva;
        if (display_base) {
            const auto candidate = value - base;
            if (candidate < context.image->image_size())
                rva = candidate;
        } else {
            rva = optional_value(context.image->va_to_rva(value));
        }
        if (!rva) return {};
        address.space = aida::analysis::address_space_id_t::relative_virtual;
        address.value = *rva;
        return address;
    }
    if (value < context.image->image_size()) {
        address.space = aida::analysis::address_space_id_t::relative_virtual;
        address.value = value;
        return address;
    }
    return {};
}

std::optional<std::uint64_t> runtime_address(
    const workspace_context_t& context, const aida::analysis::address_t& address) {
    using aida::analysis::address_space_id_t;
    if (address.space == address_space_id_t::virtual_address ||
        address.space == address_space_id_t::live_virtual)
        return address.value;
    if (!context.image)
        return {};
    if (address.space == address_space_id_t::relative_virtual) {
        if (const auto base = display_base_override(context))
            return checked_add(*base, address.value);
        return optional_value(context.image->rva_to_va(address.value));
    }
    if (address.space == address_space_id_t::file_offset) {
        auto rva = optional_value(context.image->file_offset_to_rva(address.value));
        if (!rva)
            return {};
        if (const auto base = display_base_override(context))
            return checked_add(*base, *rva);
        return optional_value(context.image->rva_to_va(*rva));
    }
    return {};
}

std::optional<std::uint64_t> provider_offset(
    const workspace_context_t& context, const aida::analysis::address_t& address) {
    using aida::analysis::address_space_id_t;
    if (!context.workspace)
        return {};
    if (address.space == address_space_id_t::file_offset)
        return address.value < context.workspace->provider().size()
            ? std::optional<std::uint64_t>(address.value) : std::nullopt;
    if (address.space == address_space_id_t::live_virtual) {
        const auto& module = context.workspace->identity().module();
        if (!module || address.value < module->base || address.value - module->base >= module->size)
            return {};
        return address.value - module->base;
    }
    if (!context.image)
        return {};
    std::optional<std::uint64_t> rva;
    if (address.space == address_space_id_t::relative_virtual)
        rva = address.value;
    else if (address.space == address_space_id_t::virtual_address)
        rva = optional_value(context.image->va_to_rva(address.value));
    return rva ? optional_value(context.image->rva_to_file_offset(*rva)) : std::nullopt;
}

aida::analysis::workspace_result_t<std::vector<std::uint8_t>> read_bytes(
    const workspace_context_t& context, const aida::analysis::address_t& address,
    std::size_t size) {
    using namespace aida::analysis;
    if (!context.workspace)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_not_found,
                "workspace is unavailable", "ui_read"));
    const auto offset = provider_offset(context, address);
    if (!offset)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            make_workspace_error(workspace_error_code_t::out_of_range,
                "address is not backed by the workspace provider", "ui_read"));
    return context.workspace->provider().read_vector(*offset, size, 64ULL << 20,
        context.workspace->cancellation_token());
}

std::string resolve_symbol(const workspace_context_t& context,
                           const aida::analysis::address_t& address) {
    if (!context.publication || !context.publication->snapshot)
        return {};
    const auto& symbols = context.publication->snapshot->symbols;
    auto found = std::lower_bound(symbols.begin(), symbols.end(), address,
        [](const aida::analysis::symbol_record_t& symbol,
           const aida::analysis::address_t& value) {
            return symbol.address < value;
        });
    if (found != symbols.end() && found->address == address)
        return found->name;
    if (found != symbols.begin()) {
        --found;
        if (found->address.space == address.space && found->address.value <= address.value) {
            char suffix[32]{};
            std::snprintf(suffix, sizeof(suffix), "+0x%llX",
                static_cast<unsigned long long>(address.value - found->address.value));
            return found->name + suffix;
        }
    }
    return {};
}

std::string resolve_name(const workspace_context_t& context,
                         const aida::analysis::address_t& address) {
    if (!context.model)
        return resolve_symbol(context, address);
    return context.model->renames.resolve_or(address, resolve_symbol(context, address));
}

std::string comment(const workspace_context_t& context,
                    const aida::analysis::address_t& address) {
    return context.model ? context.model->comments.get(address) : std::string();
}

std::string auto_comment(const workspace_context_t& context,
                         const aida::analysis::address_t& address) {
    return context.model ? context.model->automatic_comments.get(address) : std::string();
}

void request_format_range(const workspace_context_t& context,
                          std::size_t begin, std::size_t end) {
    request_format_page(context, begin, end);
}

std::optional<formatted_instruction_t> formatted_instruction(
    const workspace_context_t& context, aida::analysis::entity_id_t instruction_id) {
    if (!context.view)
        return {};
    std::lock_guard<std::mutex> lock(context.view->mutex);
    auto found = context.view->formatted.find(instruction_id);
    return found == context.view->formatted.end()
        ? std::nullopt : std::optional<formatted_instruction_t>(found->second);
}

bool queue_comment(const workspace_context_t& context,
                   const aida::analysis::address_t& address, std::string text) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::comment;
    operation.address = address;
    operation.text = std::move(text);
    return queue_overlay_operation(context, std::move(operation));
}

bool queue_rename(const workspace_context_t& context,
                  const aida::analysis::address_t& address, std::string name) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::name;
    operation.address = address;
    operation.name = std::move(name);
    return queue_overlay_operation(context, std::move(operation));
}

bool queue_bookmark(const workspace_context_t& context,
                    const aida::analysis::address_t& address, std::string label) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::bookmark;
    operation.address = address;
    operation.name = std::move(label);
    return queue_overlay_operation(context, std::move(operation));
}

bool queue_patch(const workspace_context_t& context,
                 const aida::analysis::address_t& address,
                 std::vector<std::uint8_t> bytes) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::byte_patch;
    operation.address = address;
    operation.bytes = std::move(bytes);
    return queue_overlay_operation(context, std::move(operation));
}

bool queue_type_application(const workspace_context_t& context,
                            const aida::analysis::address_t& address,
                            std::string type) {
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::type_application;
    operation.address = address;
    operation.type = std::move(type);
    return queue_overlay_operation(context, std::move(operation));
}

bool queue_type_declaration(const workspace_context_t& context,
                            std::string declaration) {
    if (!context.workspace || !context.image)
        return false;
    aida::analysis::overlay_operation_t operation;
    operation.kind = aida::analysis::overlay_operation_kind_t::type_declaration;
    operation.address.space = aida::analysis::address_space_id_t::relative_virtual;
    operation.address.value = 0;
    operation.address.architecture = context.workspace->identity().architecture();
    operation.address.mode = context.image->architecture_mode();
    operation.text = std::move(declaration);
    return queue_overlay_operation(context, std::move(operation));
}

bool queue_type_declaration_and_application(
    const workspace_context_t& context,
    const aida::analysis::address_t& address,
    std::string declaration,
    std::string canonical_type) {
    if (declaration.empty() || canonical_type.empty())
        return false;
    aida::analysis::overlay_operation_t declaration_operation;
    declaration_operation.kind = aida::analysis::overlay_operation_kind_t::type_declaration;
    declaration_operation.address.space = aida::analysis::address_space_id_t::relative_virtual;
    declaration_operation.address.value = 0;
    declaration_operation.address.architecture = context.workspace
        ? context.workspace->identity().architecture()
        : address.architecture;
    declaration_operation.address.mode = context.image
        ? context.image->architecture_mode() : address.mode;
    declaration_operation.text = std::move(declaration);
    aida::analysis::overlay_operation_t application_operation;
    application_operation.kind = aida::analysis::overlay_operation_kind_t::type_application;
    application_operation.address = address;
    application_operation.type = std::move(canonical_type);
    std::vector<aida::analysis::overlay_operation_t> operations;
    operations.reserve(2);
    operations.push_back(std::move(declaration_operation));
    operations.push_back(std::move(application_operation));
    return queue_overlay_transaction(context, std::move(operations));
}

mutation_state_t mutation_state(const workspace_context_t& context) {
    mutation_state_t result;
    if (!context.workspace || !context.view)
        return result;
    result.pending = context.view->pending_mutations.load(std::memory_order_acquire);
    result.overlay_revision = context.workspace->overlay_revision();
    std::lock_guard<std::mutex> lock(context.view->mutex);
    result.error = context.view->mutation_error;
    return result;
}

namespace {

bool publish_workbench_selection(const workspace_context_t& context,
                                 const aida::analysis::address_t& destination,
                                 bool record_history) {
    const auto runtime = runtime_address(context, destination).value_or(destination.value);
    aida::workbench::selection_context_t selection;
    selection.kind = aida::workbench::selection_kind_t::address;
    selection.has_address = true;
    selection.address = runtime;
    selection.extent = 1;
    selection.entity_key = "analysis.address." + std::to_string(destination.value);
    aida::workbench::document_local_cursor_t cursor;
    cursor.has_position = true;
    cursor.position = runtime;
    aida::workbench::workbench_shell_workspace_context_t workbench;
    if (record_history) {
        return aida::workbench::workbench_shell_runtime_t::instance()
            .publish_selection(context.workspace, selection, cursor,
                aida::workbench::navigation_origin_t::user, workbench).ok();
    }
    return true;
}

void synchronize_workspace_selection(const workspace_context_t& context,
                                     const aida::analysis::address_t& destination,
                                     bool reveal) {
    if (!context.workspace || !context.view)
        return;
    const auto updated = context.workspace->update_view_state(
        [&](aida::analysis::workspace_view_state_t& state) {
            state.selection = destination;
        });
    if (!updated)
        return;
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->selection = destination;
    context.view->scroll_to_selection = reveal;
}

std::optional<aida::analysis::address_t> history_selection(
    const workspace_context_t& context,
    const aida::workbench::workbench_shell_workspace_context_t& workbench) {
    const auto active = std::find_if(
        workbench.persistence.documents.begin(), workbench.persistence.documents.end(),
        [&workbench](const aida::workbench::document_persistence_dto_t& document) {
            return document.id == workbench.persistence.active_document;
        });
    if (active == workbench.persistence.documents.end() ||
        !active->local_state.selection.has_address)
        return {};
    return typed_address(context, active->local_state.selection.address);
}

}

void select_address(const aida::analysis::address_t& destination,
                    const workspace_context_t& context,
                    bool record_history) {
    if (!context.workspace || !context.view || !context.model)
        return;
    const auto current = context.workspace->view_state().selection;
    if (current && *current == destination) {
        synchronize_workspace_selection(context, destination, false);
        return;
    }
    if (record_history && !publish_workbench_selection(context, destination, true))
        return;
    synchronize_workspace_selection(context, destination, false);
}

void select_address(std::uint64_t value, const workspace_context_t& context,
                    bool record_history) {
    const auto destination = typed_address(context, value);
    if (destination)
        select_address(*destination, context, record_history);
}

void goto_address(const aida::analysis::address_t& destination,
                  const workspace_context_t& context) {
    if (!context.workspace || !context.view || !context.model)
        return;
    const auto current = context.workspace->view_state().selection;
    if (current && *current == destination) {
        synchronize_workspace_selection(context, destination, true);
        return;
    }
    if (!publish_workbench_selection(context, destination, true))
        return;
    synchronize_workspace_selection(context, destination, true);
}

void goto_address(std::uint64_t value, const workspace_context_t& context) {
    const auto destination = typed_address(context, value);
    if (!destination)
        return;
    goto_address(*destination, context);
}

void navigate_back(const workspace_context_t& context) {
    if (!context.workspace)
        return;
    aida::workbench::workbench_shell_workspace_context_t workbench;
    const auto result = aida::workbench::workbench_shell_runtime_t::instance()
        .navigate_history(context.workspace, false, workbench);
    if (!result)
        return;
    if (const auto destination = history_selection(context, workbench))
        synchronize_workspace_selection(context, *destination, true);
}

void navigate_forward(const workspace_context_t& context) {
    if (!context.workspace)
        return;
    aida::workbench::workbench_shell_workspace_context_t workbench;
    const auto result = aida::workbench::workbench_shell_runtime_t::instance()
        .navigate_history(context.workspace, true, workbench);
    if (!result)
        return;
    if (const auto destination = history_selection(context, workbench))
        synchronize_workspace_selection(context, *destination, true);
}

void open_xrefs(std::uint64_t value, const workspace_context_t& context) {
    const auto address = typed_address(context, value);
    if (!address || !context.publication || !context.publication->snapshot ||
        context.view->xref_scanning.exchange(true, std::memory_order_acq_rel))
        return;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->xref_popup_open = true;
        context.view->xref_popup_address = *address;
        context.view->xref_results.clear();
        context.view->xref_popup_selected = -1;
    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::vector<xref_popup_entry_t> results;
    results.reserve(256);
    constexpr std::size_t maximum_results = 10000;
    for (const auto& xref : context.publication->snapshot->xrefs) {
        if (context.workspace->cancellation_token().stop_requested())
            break;
        if (xref.target != *address)
            continue;
        xref_popup_entry_t entry;
        entry.addr = runtime_address(context, xref.source).value_or(xref.source.value);
        entry.type = static_cast<int>(xref.kind);
        entry.module_name = context.workspace->identity().bin_name();
        entry.function_name = resolve_name(context, xref.source);
        results.push_back(std::move(entry));
        if (results.size() >= maximum_results)
            break;
    }
    const auto result_count = results.size();
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->xref_results = std::move(results);
    }
    context.view->xref_scanning.store(false, std::memory_order_release);
    aida::preview::disasm::record("workspace_xref_query", value,
        std::to_string(result_count));
#else
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "analysis_ui";
    descriptor.label = "workspace_xref_query";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, address = *address](
        const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        std::vector<xref_popup_entry_t> results;
        results.reserve(256);
        constexpr std::size_t maximum_results = 10000;
        for (const auto& xref : context.publication->snapshot->xrefs) {
            if (cancel.requested.load(std::memory_order_acquire) ||
                context.workspace->cancellation_token().stop_requested())
                break;
            if (xref.target != address)
                continue;
            xref_popup_entry_t entry;
            entry.addr = runtime_address(context, xref.source).value_or(xref.source.value);
            entry.type = static_cast<int>(xref.kind);
            entry.module_name = context.workspace->identity().bin_name();
            entry.function_name = resolve_name(context, xref.source);
            results.push_back(std::move(entry));
            if (results.size() >= maximum_results)
                break;
        }
        {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->xref_results = std::move(results);
        }
        context.view->xref_scanning.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        context.view->xref_scanning.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->format_error = submitted.reject_reason;
    }
#endif
}

void bump_format_generation(const workspace_context_t& context) {
    if (!context.model || !context.view)
        return;
    context.model->format_generation.fetch_add(1, std::memory_order_acq_rel);
    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->formatted.clear();
    context.view->pending_format_pages.clear();
}

void bump_format_generation() {
    bump_format_generation(capture_selected_workspace());
}

std::uint32_t format_generation(const workspace_context_t& context) {
    return context.model ? context.model->format_generation.load(std::memory_order_acquire) : 0;
}

std::uint64_t enclosing_function_start(std::uint64_t value,
                                       const workspace_context_t& context) {
    const auto address = typed_address(context, value);
    if (!address || !context.publication || !context.publication->snapshot)
        return 0;
    const auto& functions = context.publication->snapshot->functions;
    auto found = std::upper_bound(functions.begin(), functions.end(), *address,
        [](const aida::analysis::address_t& target,
           const aida::analysis::function_record_t& function) {
            return target < function.start;
        });
    if (found == functions.begin())
        return 0;
    --found;
    if (found->start.space != address->space || address->value < found->start.value ||
        address->value >= found->end.value)
        return 0;
    return runtime_address(context, found->start).value_or(found->start.value);
}

namespace {

std::uint64_t context_generation(const workspace_context_t& context) {
    if (!context.workspace)
        return 0;
    const auto generation = context.workspace->generation();
    const auto revision = context.workspace->analysis_revision();
    return generation ^ (revision + 0x9E3779B97F4A7C15ull +
        (generation << 6u) + (generation >> 2u));
}

void open_instruction_menu(const workspace_context_t& context,
                           const aida::analysis::instruction_record_t& instruction,
                           const std::optional<formatted_instruction_t>& formatted,
                           aida::ui::context_menu_open_origin_t origin) {
    using namespace aida::ui::analysis_context_menu;
    using aida::ui::action_check_state_t;
    using aida::ui::action_handler_result_t;
    using aida::ui::capability_state_t;
    context_t menu;
    menu.kind = menu_kind_t::instruction;
    menu.generation = context_generation(context);
    menu.live_generation = [context]() { return context_generation(context); };
    const auto runtime = runtime_address(context, instruction.address).value_or(
        instruction.address.value);
    addr_format_t format;
    bool show_bytes;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        format = context.view->addr_format;
        show_bytes = context.view->show_bytes;
    }
    const auto address = address_label(context, instruction.address, format);
    const auto text = formatted ? formatted->text : std::string();
    const auto bytes = formatted ? formatted->bytes : std::string();
    const auto name = resolve_name(context, instruction.address);
    auto copy = [&menu](const char* id, std::string value, const char* reason) {
        action_slot_t slot;
        if (value.empty())
            slot.capability = capability_state_t::unavailable(reason);
        slot.invoke = [value = std::move(value)]() {
            ImGui::SetClipboardText(value.c_str());
            return action_handler_result_t::completed();
        };
        menu.actions.emplace(id, std::move(slot));
    };
    copy("analysis.copy.line", address + "  " + text, "The instruction is not formatted");
    copy("analysis.copy.text", text, "The instruction is not formatted");
    copy("analysis.copy.instruction", text, "The instruction is not formatted");
    copy("analysis.copy.address", address, "The address is unavailable");
    copy("analysis.copy.bytes", bytes, "The instruction bytes are not formatted");
    copy("analysis.copy.name", name, "The selected address has no symbol name");
    menu.actions["analysis.navigate.back"].invoke = [context]() {
        navigate_back(context);
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.navigate.forward"].invoke = [context]() {
        navigate_forward(context);
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.navigate.disassembly"].invoke = [context, runtime]() {
        goto_address(runtime, context);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.disassembly"));
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.navigate.xrefs"].invoke = [context, runtime]() {
        open_xrefs(runtime, context);
        return action_handler_result_t::completed();
    };
    if (instruction.target_fact_count != 0 &&
        instruction.target_fact_begin < context.publication->snapshot->target_facts.size()) {
        const auto target = context.publication->snapshot->target_facts[instruction.target_fact_begin];
        if (target.direct) {
            menu.actions["analysis.navigate.follow"].invoke = [context, target]() {
                goto_address(runtime_address(context, target.target).value_or(target.target.value), context);
                return action_handler_result_t::completed();
            };
        }
    }
    menu.actions["analysis.modify.rename"].invoke = [context, value = instruction.address]() {
        rename_dialog::open(context, value);
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.modify.comment"].invoke = [context, value = instruction.address]() {
        comment_dialog::open(context, value);
        return action_handler_result_t::completed();
    };
    bool bookmarked;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        bookmarked = std::any_of(context.view->bookmarks.begin(), context.view->bookmarks.end(),
            [&](const bookmark_t& item) { return item.addr == instruction.address.value; });
    }
    if (bookmarked) {
        menu.actions["analysis.modify.remove_bookmark"].invoke = [context, value = instruction.address]() {
            return queue_bookmark(context, value, {})
                ? action_handler_result_t::completed()
                : action_handler_result_t::failed("The bookmark update was rejected");
        };
    } else {
        menu.actions["analysis.modify.bookmark"].invoke =
            [context, value = instruction.address, label = name.empty() ? address : name]() {
                return queue_bookmark(context, value, label)
                    ? action_handler_result_t::completed()
                    : action_handler_result_t::failed("The bookmark update was rejected");
            };
    }
    menu.actions["analysis.navigate.graph"].invoke = [context, runtime]() {
        goto_address(runtime, context);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("document.graph"));
        return action_handler_result_t::completed();
    };
    const auto function = enclosing_function_start(runtime, context);
    if (function != 0) {
        auto decompile = [context, function]() {
            pseudocode_view::request_decompile(context, function, false);
            aida::ui::application_views::open_or_focus(
                aida::ui::stable_view_id_t("document.pseudocode"));
            return action_handler_result_t::completed();
        };
        menu.actions["analysis.navigate.pseudocode"].invoke = decompile;
        menu.actions["analysis.function.decompile"].invoke = std::move(decompile);
    }
    menu.actions["analysis.function.source"].invoke = [context, runtime]() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        aida::preview::disasm::record("reconstruct_source", runtime);
#else
        source_reconstruct_view::open(context);
#endif
        return action_handler_result_t::completed();
    };
    menu.actions["analysis.function.aob"].invoke = [context, runtime]() {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        aida::preview::disasm::record("generate_aob_signature", runtime, "16:auto_wildcard");
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.memory.aob"));
#else
        const auto generator = aob_generator::state_for(context);
        int count = 16;
        bool wildcard = true;
        if (generator) {
            std::lock_guard<std::mutex> lock(generator->mutex);
            std::snprintf(generator->address_input, sizeof(generator->address_input), "%llX",
                static_cast<unsigned long long>(runtime));
            count = generator->instruction_count;
            wildcard = generator->auto_wildcard;
        }
        aob_generator::generate_from_address(context, runtime, count, wildcard);
        scan_hub_view::set_sub_tab(scan_hub_view::sub_tab_t::aob);
        aida::ui::application_views::open_or_focus(
            aida::ui::stable_view_id_t("view.memory.aob"));
#endif
        return action_handler_result_t::completed();
    };
    auto display = [&menu, context, format](const char* id, addr_format_t target) {
        action_slot_t slot;
        slot.check_state = format == target ? action_check_state_t::checked : action_check_state_t::unchecked;
        slot.invoke = [context, target]() {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->addr_format = target;
            return action_handler_result_t::completed();
        };
        menu.actions.emplace(id, std::move(slot));
    };
    display("analysis.view.va", addr_format_t::va);
    display("analysis.view.rva", addr_format_t::rva);
    display("analysis.view.file_offset", addr_format_t::file_offset);
    menu.actions["analysis.view.bytes"] = {capability_state_t::available(), [context]() {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->show_bytes = !context.view->show_bytes;
        return action_handler_result_t::completed();
    }, show_bytes ? action_check_state_t::checked : action_check_state_t::unchecked};
    menu.actions["analysis.view.full_line"] = {capability_state_t::available(), []() {
        editor_config::disasm_full_line_select = !editor_config::disasm_full_line_select;
        return action_handler_result_t::completed();
    }, editor_config::disasm_full_line_select ? action_check_state_t::checked : action_check_state_t::unchecked};
    open(std::move(menu), origin);
}

}

void render(float, float, float width, float height,
            float alpha, float, float, float,
            const workspace_context_t& context, float) {
    if (!context) {
        ImGui::BeginChild("##workspace_disassembly_empty", ImVec2(width, height), false);
        aida::ui::compact_empty_state("disassembly_workspace_empty", "No workspace selected",
            "Open or attach to a target to inspect its disassembly.", nullptr,
            ImVec2(0.0f, (std::max)(152.0f, height - aida::ui::metrics::spacing::lg)));
        ImGui::EndChild();
        return;
    }
    const std::string id = context.workspace->identity().binary_id().to_hex();
    ImGui::PushID(id.c_str());
    ImGui::BeginChild("##workspace_disassembly", ImVec2(width, height), false);
    const auto& theme = aida::ui::resolved();
    ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(theme.text_primary, alpha));

    const bool can_rebase =
        context.workspace->target_kind() == aida::analysis::target_kind_t::static_file &&
        context.image;
    aida::ui::status_kind_t header_status = aida::ui::status_kind_t::success;
    if (context.progress.readiness == aida::analysis::workspace_readiness_t::failed)
        header_status = aida::ui::status_kind_t::error;
    else if (context.progress.readiness == aida::analysis::workspace_readiness_t::analyzing ||
             context.progress.readiness == aida::analysis::workspace_readiness_t::partial ||
             context.progress.readiness == aida::analysis::workspace_readiness_t::cancelling)
        header_status = aida::ui::status_kind_t::info;
    const auto header = aida::ui::view_header("Disassembly",
        context.workspace->identity().bin_name().c_str(), "Go to",
        can_rebase ? "Rebase" : nullptr, header_status);
    if (header.primary_clicked) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->goto_visible = true;
        context.view->goto_buf[0] = '\0';
    }
    if (header.secondary_clicked && can_rebase) {
        const auto base = display_image_base(context);
        std::lock_guard<std::mutex> lock(context.view->mutex);
        std::snprintf(context.view->rebase_buf, sizeof(context.view->rebase_buf),
            "0x%llX", static_cast<unsigned long long>(base));
        context.view->rebase_error.clear();
        context.view->rebase_popup_open = true;
        ImGui::OpenPopup("Rebase###disasm_rebase_modal");
    }
    file_metadata_banner::render(context, alpha);

    bool show_bytes = false;
    int address_format = 0;
    int active_section = -1;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        show_bytes = context.view->show_bytes;
        address_format = static_cast<int>(context.view->addr_format);
        active_section = context.view->active_section;
    }
    aida::ui::begin_toolbar("##disassembly_toolbar",
        aida::ui::metrics::control::toolbar_h +
        aida::ui::metrics::toolbar::padding_y * 2.0f + 2.0f);
    aida::ui::begin_toolbar_group("history");
    if (aida::ui::toolbar_button("back", "Back", false, false,
            "Navigate to the previous location"))
        navigate_back(context);
    ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
    if (aida::ui::toolbar_button("forward", "Forward", false, false,
            "Navigate to the next location"))
        navigate_forward(context);
    aida::ui::end_toolbar_group();
    aida::ui::begin_toolbar_group("display");
    if (ImGui::Checkbox("Bytes", &show_bytes)) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->show_bytes = show_bytes;
    }
    ImGui::SameLine();
    const char* formats[] = {"VA", "RVA", "File"};
    ImGui::SetNextItemWidth(92.0f);
    if (ImGui::Combo("##address_format", &address_format, formats, 3)) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->addr_format = static_cast<addr_format_t>(address_format);
    }
    if (context.image && !context.image->sections().empty()) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(180.0f);
        const char* preview = active_section < 0 ? "All executable ranges" :
            context.image->sections()[static_cast<std::size_t>(active_section)].name.c_str();
        if (ImGui::BeginCombo("##section", preview)) {
            if (ImGui::Selectable("All executable ranges", active_section < 0)) {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                context.view->active_section = -1;
            }
            for (std::size_t index = 0; index < context.image->sections().size(); ++index) {
                const auto& section = context.image->sections()[index];
                if (!section.executable)
                    continue;
                if (ImGui::Selectable(section.name.c_str(),
                        active_section == static_cast<int>(index))) {
                    std::lock_guard<std::mutex> lock(context.view->mutex);
                    context.view->active_section = static_cast<int>(index);
                }
            }
            ImGui::EndCombo();
        }
    }
    aida::ui::end_toolbar_group(false);
    aida::ui::end_toolbar();

    const auto progress = context.progress;
    if (progress.readiness == aida::analysis::workspace_readiness_t::analyzing ||
        progress.readiness == aida::analysis::workspace_readiness_t::partial ||
        progress.readiness == aida::analysis::workspace_readiness_t::cancelling) {
        const float fraction = progress.total_units == 0 ? 0.0f :
            static_cast<float>(progress.completed_units) /
            static_cast<float>(progress.total_units);
        char progress_message[128]{};
        std::snprintf(progress_message, sizeof(progress_message), "%llu of %llu units · %.0f%%",
            static_cast<unsigned long long>(progress.completed_units),
            static_cast<unsigned long long>(progress.total_units),
            (std::clamp)(fraction, 0.0f, 1.0f) * 100.0f);
        if (aida::ui::inline_notice("analysis_progress", progress.phase.c_str(),
                progress_message, aida::ui::status_kind_t::info,
                progress.readiness == aida::analysis::workspace_readiness_t::cancelling
                    ? nullptr : "Cancel"))
            context.workspace->request_cancel();
    }
    if (progress.error) {
        const std::string message = progress.error->stable_code() + ": " +
            progress.error->message;
        aida::ui::inline_notice("analysis_error", "Analysis failed", message.c_str(),
            aida::ui::status_kind_t::error);
    }
    std::string mutation_error;
    std::string format_error;
    std::string export_error;
    std::string export_status;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        mutation_error = context.view->mutation_error;
        format_error = context.view->format_error;
        export_error = context.view->export_error;
        export_status = context.view->export_status;
    }
    if (!mutation_error.empty())
        aida::ui::inline_notice("overlay_error", "Overlay update failed",
            mutation_error.c_str(), aida::ui::status_kind_t::error);
    if (!format_error.empty() &&
        aida::ui::inline_notice("format_error", "Formatting failed", format_error.c_str(),
            aida::ui::status_kind_t::error, "Retry")) {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->format_error.clear();
        context.view->formatted.clear();
        context.view->pending_format_pages.clear();
    }
    if (!export_error.empty())
        aida::ui::inline_notice("export_error", "Export failed", export_error.c_str(),
            aida::ui::status_kind_t::error);
    else if (!export_status.empty())
        aida::ui::inline_notice("export_status", "Listing export", export_status.c_str(),
            aida::ui::status_kind_t::info);
    if (context.view->rebase_popup_open &&
        ImGui::BeginPopupModal("Rebase###disasm_rebase_modal", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::TextUnformatted("Image base");
        const bool enter = ImGui::InputTextWithHint("##rebase_image_base", "0x140000000",
            context.view->rebase_buf, sizeof(context.view->rebase_buf),
            ImGuiInputTextFlags_EnterReturnsTrue);
        if (!context.view->rebase_error.empty())
            aida::ui::inline_notice("rebase_error", "Invalid image base",
                context.view->rebase_error.c_str(), aida::ui::status_kind_t::error);
        const bool apply = aida::ui::button("Apply", aida::ui::button_kind_t::primary,
            aida::ui::size_t_::sm) || enter;
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::sm);
        const bool cancel = aida::ui::button("Cancel", aida::ui::button_kind_t::secondary,
            aida::ui::size_t_::sm) ||
            ImGui::IsKeyPressed(ImGuiKey_Escape, false);
        if (apply) {
            const auto base = parse_address_text(context, context.view->rebase_buf);
            if (!base || *base == 0 || context.image->image_size() >
                (std::numeric_limits<std::uint64_t>::max)() - *base) {
                context.view->rebase_error = "Invalid image base.";
            } else {
                {
                    std::lock_guard<std::mutex> lock(context.view->mutex);
                    context.view->display_image_base = *base == context.image->image_base()
                        ? std::nullopt : std::optional<std::uint64_t>(*base);
                    context.view->rebase_error.clear();
                    context.view->rebase_popup_open = false;
                    context.view->formatted.clear();
                    context.view->pending_format_pages.clear();
                }
                context.model->format_generation.fetch_add(1, std::memory_order_acq_rel);
                ImGui::CloseCurrentPopup();
            }
        } else if (cancel) {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->rebase_error.clear();
            context.view->rebase_popup_open = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    bool goto_visible = false;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        goto_visible = context.view->goto_visible;
    }
    if (goto_visible) {
        aida::ui::begin_toolbar("##disassembly_goto",
            aida::ui::metrics::control::toolbar_h +
            aida::ui::metrics::toolbar::padding_y * 2.0f + 2.0f);
        ImGui::PushID("goto_address");
        const ImGuiID goto_input = ImGui::GetID("##input");
        ImGui::PopID();
        static_cast<void>(aida::ui::search_field("goto_address", context.view->goto_buf,
            sizeof(context.view->goto_buf), "VA, RVA, or symbol", 300.0f));
        const bool enter = ImGui::GetActiveID() == goto_input &&
            ImGui::IsKeyPressed(ImGuiKey_Enter, false);
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::sm);
        const bool go = aida::ui::toolbar_button("goto_submit", "Go", false, false,
            "Navigate to the resolved address") || enter;
        ImGui::SameLine(0.0f, aida::ui::metrics::spacing::xs);
        const bool close_goto = aida::ui::toolbar_button("goto_close", "Close", false,
            false, "Close address search");
        aida::ui::end_toolbar();
        if (go) {
            if (auto value = parse_address_text(context, context.view->goto_buf))
                goto_address(*value, context);
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->goto_visible = false;
        } else if (close_goto) {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->goto_visible = false;
        }
    }
    const auto range = instruction_range(context);
    if (!range || !context.publication->snapshot || range->first >= range->second) {
        if (progress.readiness == aida::analysis::workspace_readiness_t::failed) {
            aida::ui::error_state("disassembly_unavailable", "Disassembly unavailable",
                "Analysis failed before any instruction records were published.", nullptr,
                ImVec2(0.0f, 152.0f));
        } else if (progress.readiness == aida::analysis::workspace_readiness_t::analyzing ||
                   progress.readiness == aida::analysis::workspace_readiness_t::partial ||
                   progress.readiness == aida::analysis::workspace_readiness_t::cancelling) {
            aida::ui::loading_state("disassembly_loading", "Preparing disassembly",
                "Instruction records will appear as soon as analysis publishes them.",
                ImVec2(0.0f, 152.0f));
        } else {
            aida::ui::compact_empty_state("disassembly_no_records", "No instructions available",
                "This target has no instruction records at the current readiness level.", nullptr,
                ImVec2(0.0f, 152.0f));
        }
        ImGui::PopStyleColor();
        ImGui::EndChild();
        ImGui::PopID();
        comment_dialog::render();
        rename_dialog::render();
        return;
    }
    ImGui::PushStyleColor(ImGuiCol_ChildBg,
        ImGui::ColorConvertU32ToFloat4(theme.panel_header));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
        ImVec2(aida::ui::metrics::table::cell_pad_x,
            aida::ui::metrics::table::cell_pad_y));
    ImGui::BeginChild("##instruction_header", ImVec2(0.0f,
        aida::ui::metrics::table::header_h), true,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::TextDisabled("Address");
    if (show_bytes) {
        ImGui::SameLine(170.0f);
        ImGui::TextDisabled("Bytes");
    }
    ImGui::SameLine(show_bytes ? 470.0f : 190.0f);
    ImGui::TextDisabled("Instruction");
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::BeginChild("##instruction_rows", ImVec2(0.0f, 0.0f), false,
        ImGuiWindowFlags_HorizontalScrollbar);
    const auto& instructions = context.publication->snapshot->instructions;
    const std::size_t count_size = range->second - range->first;
    const int count = count_size > static_cast<std::size_t>((std::numeric_limits<int>::max)())
        ? (std::numeric_limits<int>::max)() : static_cast<int>(count_size);
    const float row_height = (std::max)(aida::ui::metrics::table::compact_row_h,
        ImGui::GetTextLineHeightWithSpacing());
    std::optional<aida::analysis::address_t> selection;
    bool scroll_to_selection = false;
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        selection = context.view->selection;
        scroll_to_selection = context.view->scroll_to_selection;
    }
    if (scroll_to_selection && selection) {
        auto found = std::lower_bound(instructions.begin() + static_cast<std::ptrdiff_t>(range->first),
            instructions.begin() + static_cast<std::ptrdiff_t>(range->second), *selection,
            [](const aida::analysis::instruction_record_t& instruction,
               const aida::analysis::address_t& address) {
                return instruction.address < address;
            });
        if (found != instructions.begin() + static_cast<std::ptrdiff_t>(range->second)) {
            const auto index = static_cast<std::size_t>(std::distance(
                instructions.begin() + static_cast<std::ptrdiff_t>(range->first), found));
            ImGui::SetScrollY(static_cast<float>(index) * row_height);
        }
        std::lock_guard<std::mutex> lock(context.view->mutex);
        context.view->scroll_to_selection = false;
    }
    ImGuiListClipper clipper;
    clipper.Begin(count, row_height);
    while (clipper.Step()) {
        const std::size_t page_begin = range->first +
            static_cast<std::size_t>((std::max)(0, clipper.DisplayStart));
        const std::size_t page_end = (std::min)(range->second,
            range->first + static_cast<std::size_t>((std::max)(0, clipper.DisplayEnd)));
        request_format_page(context, page_begin, page_end);
        for (int row_index = clipper.DisplayStart; row_index < clipper.DisplayEnd; ++row_index) {
            const std::size_t index = range->first + static_cast<std::size_t>(row_index);
            if (index >= range->second)
                break;
            const auto& instruction = instructions[index];
            formatted_instruction_t formatted;
            bool formatted_ready = false;
            {
                std::lock_guard<std::mutex> lock(context.view->mutex);
                auto found = context.view->formatted.find(instruction.id);
                if (found != context.view->formatted.end()) {
                    formatted = found->second;
                    formatted_ready = true;
                }
            }
            const bool selected = selection && *selection == instruction.address;
            ImGui::PushID(static_cast<int>(instruction.id & 0x7FFFFFFF));
            const ImGuiSelectableFlags selection_flags =
                ImGuiSelectableFlags_AllowDoubleClick |
                (editor_config::disasm_full_line_select ?
                    ImGuiSelectableFlags_SpanAllColumns : ImGuiSelectableFlags_None);
            if (ImGui::Selectable("##instruction", selected,
                    selection_flags, ImVec2(0.0f, row_height))) {
                goto_address(runtime_address(context, instruction.address).value_or(
                    instruction.address.value), context);
                selection = instruction.address;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
                    instruction.target_fact_count != 0) {
                    const auto target_index = instruction.target_fact_begin;
                    if (target_index < context.publication->snapshot->target_facts.size()) {
                        const auto& target = context.publication->snapshot->target_facts[target_index];
                        if (target.direct)
                            goto_address(runtime_address(context, target.target).value_or(
                                target.target.value), context);
                    }
                }
            }
            ImGui::SameLine(0.0f, 0.0f);
            const std::string address = address_label(context, instruction.address,
                static_cast<addr_format_t>(address_format));
            ImGui::TextUnformatted(address.c_str());
            if (show_bytes) {
                ImGui::SameLine(170.0f);
                ImGui::TextDisabled("%-44s", formatted_ready ? formatted.bytes.c_str() : "");
            }
            ImGui::SameLine(show_bytes ? 470.0f : 190.0f);
            if (formatted_ready) {
                if (!formatted.error.empty())
                    ImGui::TextDisabled("%s", formatted.error.c_str());
                else
                    ImGui::TextUnformatted(formatted.text.c_str());
            } else {
                ImGui::TextDisabled("Formatting...");
            }
            const std::string name = resolve_name(context, instruction.address);
            const std::string user_comment = comment(context, instruction.address);
            const std::string generated_comment = auto_comment(context, instruction.address);
            if (!name.empty()) {
                ImGui::SameLine();
                ImGui::TextDisabled("<%s>", name.c_str());
            }
            if (!user_comment.empty() || !generated_comment.empty()) {
                ImGui::SameLine();
                const std::string combined = user_comment.empty() ? generated_comment :
                    generated_comment.empty() ? user_comment : user_comment + "; " + generated_comment;
                ImGui::TextDisabled("; %s", combined.c_str());
            }
            const bool typed_pointer_request = ImGui::IsItemClicked(ImGuiMouseButton_Right);
            if (typed_pointer_request) {
                open_instruction_menu(context, instruction,
                    formatted_ready ? std::optional<formatted_instruction_t>(formatted) : std::nullopt,
                    aida::ui::context_menu_open_origin_t::pointer);
            }
            ImGui::PopID();
        }
    }
    aida::ui::context_menu_open_origin_t analysis_menu_origin{};
    if (selection && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        aida::ui::analysis_context_menu::keyboard_request(analysis_menu_origin)) {
        const auto found = std::lower_bound(instructions.begin(), instructions.end(), *selection,
            [](const aida::analysis::instruction_record_t& instruction,
               const aida::analysis::address_t& address) { return instruction.address < address; });
        if (found != instructions.end() && found->address == *selection)
            open_instruction_menu(context, *found, formatted_instruction(context, found->id),
                analysis_menu_origin);
    }
    aida::ui::analysis_context_menu::render();
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) {
        const auto& io = ImGui::GetIO();
        if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false))
            navigate_back(context);
        if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow, false))
            navigate_forward(context);
        if (ImGui::IsKeyPressed(ImGuiKey_G, false)) {
            std::lock_guard<std::mutex> lock(context.view->mutex);
            context.view->goto_visible = true;
            context.view->goto_buf[0] = '\0';
        }
        if (selection && ImGui::IsKeyPressed(ImGuiKey_N, false))
            rename_dialog::open(context, *selection);
        if (selection && ImGui::IsKeyPressed(ImGuiKey_Semicolon, false))
            comment_dialog::open(context, *selection);
        if (selection && ImGui::IsKeyPressed(ImGuiKey_X, false))
            open_xrefs(runtime_address(context, *selection).value_or(selection->value), context);
        if (selection && ImGui::IsKeyPressed(ImGuiKey_B, false))
            queue_bookmark(context, *selection, address_label(context, *selection,
                addr_format_t::va));
        if (selection && ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
            const auto selected_runtime = runtime_address(context, *selection).value_or(selection->value);
            const auto function = enclosing_function_start(selected_runtime, context);
            if (function != 0) {
                pseudocode_view::request_decompile(context, function, false);
                aida::ui::application_views::open_or_focus(
                    aida::ui::stable_view_id_t("document.pseudocode"));
            }
        }
        if (selection && io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false)) {
            const auto found = std::lower_bound(instructions.begin(), instructions.end(), *selection,
                [](const aida::analysis::instruction_record_t& instruction,
                   const aida::analysis::address_t& address) {
                    return instruction.address < address;
                });
            if (found != instructions.end() && found->address == *selection) {
                const auto formatted = formatted_instruction(context, found->id);
                const std::string address = address_label(context, found->address,
                    static_cast<addr_format_t>(address_format));
                const std::string line = address + "  " +
                    (formatted ? formatted->text : std::string());
                ImGui::SetClipboardText(line.c_str());
            }
        }
        if (io.KeyCtrl && io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_D, false))
            request_listing_export(context);
    }
    ImGui::EndChild();
    render_xref_popup(context);
    ImGui::PopStyleColor();
    ImGui::EndChild();
    ImGui::PopID();
    comment_dialog::render();
    rename_dialog::render();
}

}
