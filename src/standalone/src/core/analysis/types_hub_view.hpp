#pragma once

#include "types_hub_view_api.hpp"
#include "pdb_parser.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "symbol_store.hpp"
#endif
#include "struct_dissector.hpp"
#include "struct_dissector_view.hpp"
#include "struct_recon_view.hpp"
#include "workspace/search_index.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/pseudocode_view.hpp"
#include "../ai/entity_evidence_handoff.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../infra/taskflow_runtime.hpp"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../session/analysis_session.hpp"
#endif
#include "../ui/theme.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/application_ui_runtime.hpp"
#include "../ui/design_system.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/win32_dialog.hpp"
#endif
#include "imgui/imgui.h"
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/studio_semantics.hpp"
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cctype>
#include <cfloat>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../preview/re_hubs_preview_adapter.hpp"
#endif

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
extern HWND g_hwnd;
#endif

namespace types_hub_view {

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline std::string studio_type_entity_id(const char* entity,
	const disasm_view::workspace_context_t& context, const std::string& entity_identity) {
	const std::string workspace_id = context.workspace
		? context.workspace->identity().binary_id().to_hex() : std::string("none");
	const std::string identity = workspace_id + ":" + entity_identity;
	std::string source(entity);
	source.push_back('-');
	source.append(aida::preview::semantics::entity_token(identity));
	return aida::preview::semantics::stable_id("aida.types", source);
}
#endif

struct type_reference_t {
    aida::analysis::address_t address;
    std::string label;
};

struct state_t {
    std::mutex mutex;
    sub_tab_t active = sub_tab_t::structs;
    std::array<char, 256> search{};
    std::array<char, 64> apply_address{};
    std::array<char, 1024> apply_type{};
    int selected = -1;
    std::string pdb_error;
    std::shared_ptr<const struct catalog_t> catalog;
    std::atomic<bool> catalog_loading{false};
    std::uint64_t catalog_generation = 0;
    std::uint64_t catalog_analysis_revision = 0;
    std::shared_ptr<const std::vector<std::size_t>> visible_indices;
    const catalog_t* visible_catalog = nullptr;
    sub_tab_t visible_tab = sub_tab_t::structs;
    std::string visible_filter;
    std::atomic<bool> visible_loading{false};
    bool list_focused = false;
    int context_row = -1;
    sub_tab_t context_tab = sub_tab_t::structs;
    std::uint64_t context_generation = 0;
    std::uint64_t context_analysis_revision = 0;
    std::string apply_status;
    bool apply_error = false;
    bool apply_pending = false;
    std::uint64_t apply_generation = 0;
    std::uint64_t apply_expected_overlay_revision = 0;
	bool declaration_review_requested = false;
	std::string declaration_review_name;
	std::shared_ptr<const std::string> declaration_review_text;
	std::weak_ptr<aida::analysis::analysis_workspace_t> declaration_review_workspace;
	std::shared_ptr<const aida::analysis::analysis_publication_t>
		declaration_review_publication;
	std::string declaration_review_workspace_id;
	std::uint64_t declaration_review_generation = 0;
	std::uint64_t declaration_review_analysis_revision = 0;
	std::uint64_t declaration_review_overlay_revision = 0;
	std::uint64_t enum_declaration_cache_generation = 0;
	std::uint64_t enum_declaration_cache_analysis_revision = 0;
	std::string enum_declaration_cache_identity;
	std::shared_ptr<const std::string> enum_declaration_cache;
    const struct catalog_t* reference_catalog = nullptr;
    std::string reference_type;
    std::shared_ptr<const std::vector<type_reference_t>> references;
    std::atomic<bool> reference_loading{false};
    const struct catalog_t* reference_request_catalog = nullptr;
    std::string reference_request_type;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    bool pdb_dialog_open = false;
    std::array<char, 260> pdb_dialog_path{};
#endif
};

struct struct_entry_t {
    std::string module;
    pdb_parser::struct_def_t definition;
};

struct enum_entry_t {
    std::string module;
    pdb_parser::enum_def_t definition;
};

struct function_entry_t {
    aida::analysis::address_t address;
    std::string name;
	std::string signature;
    std::uint64_t size = 0;
    std::string provenance;
};

struct typedef_entry_t {
    aida::analysis::address_t address;
    std::string name;
    std::string canonical_type;
    bool explicitly_unknown = false;
    std::uint8_t confidence = 0;
};

struct catalog_t {
    std::vector<struct_entry_t> structs;
    std::vector<struct_entry_t> unions;
    std::vector<enum_entry_t> enums;
    std::vector<function_entry_t> functions;
    std::vector<typedef_entry_t> typedefs;
};

inline std::mutex& state_registry_mutex() {
    static std::mutex value;
    return value;
}

inline std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<state_t>,
    aida::analysis::binary_id_hash_t>& state_registry() {
    static std::unordered_map<aida::analysis::binary_id_t, std::shared_ptr<state_t>,
        aida::analysis::binary_id_hash_t> value;
    return value;
}

inline std::shared_ptr<state_t> state_for(const disasm_view::workspace_context_t& context) {
    if (!context.workspace)
        return {};
    std::lock_guard<std::mutex> lock(state_registry_mutex());
    auto& values = state_registry();
    const auto id = context.workspace->identity().binary_id();
    auto found = values.find(id);
    if (found != values.end())
        return found->second;
    auto created = std::make_shared<state_t>();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::snprintf(created->pdb_dialog_path.data(), created->pdb_dialog_path.size(),
        "%s", "AiDA_Target.pdb");
#endif
    values.emplace(id, created);
    return created;
}

inline std::atomic<int>& default_active_tab() {
    static std::atomic<int> value{static_cast<int>(sub_tab_t::structs)};
    return value;
}

inline const char* sub_tab_label(sub_tab_t tab) {
    static constexpr const char* labels[] = {
        "Structures", "Unions", "Enums", "Typedefs", "Functions", "Inferred", "Dissector"
    };
    const int index = static_cast<int>(tab);
    return index >= 0 && index < static_cast<int>(sub_tab_t::COUNT) ? labels[index] : "";
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
inline std::shared_ptr<symbol_store::workspace_state_t> symbol_state_for(
    const disasm_view::workspace_context_t& context) {
    if (!context.workspace)
        return {};
    return analysis_session::symbols_for_workspace(context.workspace);
}
#endif

inline std::string provenance_name(aida::analysis::fact_provenance_t provenance) {
    using aida::analysis::fact_provenance_t;
    switch (provenance) {
    case fact_provenance_t::gap_recovery: return "gap recovery";
    case fact_provenance_t::linear_validation: return "validated sweep";
    case fact_provenance_t::recursive_decode: return "recursive traversal";
    case fact_provenance_t::relocation: return "relocation";
    case fact_provenance_t::call_target: return "call target";
    case fact_provenance_t::export_entry: return "export";
    case fact_provenance_t::tls_entry: return "TLS";
    case fact_provenance_t::image_entry: return "entry point";
    case fact_provenance_t::unwind_metadata: return "unwind";
    case fact_provenance_t::debug_symbol: return "debug symbol";
    case fact_provenance_t::user_definition: return "user";
    case fact_provenance_t::decompiler_feedback: return "decompiler";
    case fact_provenance_t::unknown: return "unknown";
    }
    return "unknown";
}

inline catalog_t build_catalog(const disasm_view::workspace_context_t& context) {
    catalog_t catalog;
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (auto symbols = symbol_state_for(context)) {
        const auto modules = symbols->modules_snapshot();
        for (const auto& module : modules) {
            const auto& pdb = module.second.pdb;
            if (!pdb.loaded)
                continue;
            for (const auto& definition : pdb.structs) {
                struct_entry_t entry{module.first, definition};
                if (definition.is_union)
                    catalog.unions.push_back(std::move(entry));
                else
                    catalog.structs.push_back(std::move(entry));
            }
            for (const auto& definition : pdb.enums)
                catalog.enums.push_back({module.first, definition});
        }
    }
#endif
    if (context.publication && context.publication->snapshot) {
        const auto& snapshot = *context.publication->snapshot;
        catalog.functions.reserve(snapshot.functions.size());
        for (const auto& function : snapshot.functions) {
            function_entry_t entry;
            entry.address = function.start;
            entry.size = function.end.value >= function.start.value
                ? function.end.value - function.start.value : 0;
            entry.name = disasm_view::resolve_name(context, function.start);
            if (entry.name.empty()) {
                char generated[48]{};
                std::snprintf(generated, sizeof(generated), "sub_%llX",
                    static_cast<unsigned long long>(
                        disasm_view::runtime_address(context, function.start).value_or(
                            function.start.value)));
                entry.name = generated;
            }
            entry.provenance = provenance_name(function.provenance);
            catalog.functions.push_back(std::move(entry));
        }
    }
    if (context.publication && context.publication->search_index) {
        for (const auto& candidate : context.publication->search_index->types()) {
            typedef_entry_t entry;
            entry.address = candidate.address;
            entry.name = candidate.display_name;
            entry.canonical_type = candidate.canonical_type;
            entry.explicitly_unknown = candidate.explicitly_unknown;
            entry.confidence = candidate.confidence;
            catalog.typedefs.push_back(std::move(entry));
        }
    }
	for (auto& function : catalog.functions) {
		auto evidence = std::find_if(catalog.typedefs.begin(), catalog.typedefs.end(),
			[&](const typedef_entry_t& candidate) {
				return candidate.address == function.address && !candidate.explicitly_unknown &&
					!candidate.canonical_type.empty();
			});
		function.signature = evidence != catalog.typedefs.end()
			? evidence->canonical_type : "unknown " + function.name + "(unknown)";
	}
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    pdb_parser::pdb_info_t preview_pdb;
    pdb_parser::parse_pdb("AiDA_Target.pdb", {}, preview_pdb);
    for (const auto& definition : preview_pdb.structs) {
        struct_entry_t entry{"AiDA_Target", definition};
        if (definition.is_union)
            catalog.unions.push_back(std::move(entry));
        else
            catalog.structs.push_back(std::move(entry));
    }
    for (const auto& definition : preview_pdb.enums)
        catalog.enums.push_back({"AiDA_Target", definition});
    if (catalog.functions.empty()) {
        catalog.functions = {
            {{aida::analysis::address_space_id_t::relative_virtual, 0x1180}, "WinMain", "int WinMain(HINSTANCE, HINSTANCE, LPSTR, int)", 0x13A, "debug symbol"},
            {{aida::analysis::address_space_id_t::relative_virtual, 0x12C0}, "AnalyzeImage", "analysis_result_t AnalyzeImage(const image_t&)", 0x1D4, "debug symbol"},
            {{aida::analysis::address_space_id_t::relative_virtual, 0x14A0}, "DispatchCommand", "bool DispatchCommand(command_id_t, context_t*)", 0xF8, "recursive traversal"}
        };
    }
    if (catalog.typedefs.empty()) {
        catalog.typedefs = {
            {{aida::analysis::address_space_id_t::relative_virtual, 0x1180}, "image_base_t", "uintptr_t", false, 99},
            {{aida::analysis::address_space_id_t::relative_virtual, 0x12C0}, "analysis_callback_t", "analysis_result_t (*)(const image_t&)", false, 94},
            {{aida::analysis::address_space_id_t::relative_virtual, 0x14A0}, "command_flags_t", "std::uint32_t", false, 91},
            {{aida::analysis::address_space_id_t::relative_virtual, 0x1510}, "unresolved_dispatch_context", {}, true, 38}
        };
    }
#endif
    auto struct_order = [](const struct_entry_t& left, const struct_entry_t& right) {
        if (left.definition.name != right.definition.name)
            return left.definition.name < right.definition.name;
        return left.module < right.module;
    };
    std::sort(catalog.structs.begin(), catalog.structs.end(), struct_order);
    std::sort(catalog.unions.begin(), catalog.unions.end(), struct_order);
    std::sort(catalog.enums.begin(), catalog.enums.end(), [](const auto& left, const auto& right) {
        if (left.definition.name != right.definition.name)
            return left.definition.name < right.definition.name;
        return left.module < right.module;
    });
    return catalog;
}

inline void request_catalog(const disasm_view::workspace_context_t& context,
                            const std::shared_ptr<state_t>& state) {
    if (!context.publication || state->catalog_loading.exchange(true, std::memory_order_acq_rel))
        return;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->catalog && state->catalog_generation == context.publication->generation &&
            state->catalog_analysis_revision == context.publication->analysis_revision) {
            state->catalog_loading.store(false, std::memory_order_release);
            return;
        }
    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    auto catalog = std::make_shared<const catalog_t>(build_catalog(context));
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->catalog = std::move(catalog);
        state->catalog_generation = context.publication->generation;
        state->catalog_analysis_revision = context.publication->analysis_revision;
        state->visible_indices.reset();
        state->visible_catalog = nullptr;
        state->selected = -1;
        state->pdb_error.clear();
    }
    state->catalog_loading.store(false, std::memory_order_release);
    aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types,
        default_active_tab().load(std::memory_order_acquire),
        "catalog_ready", "Studio workspace fixture");
    return;
#else
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "types_hub";
    descriptor.label = "build_workspace_type_catalog";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, state](
        const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        if (!cancel.requested.load(std::memory_order_acquire)) {
            auto catalog = std::make_shared<const catalog_t>(build_catalog(context));
            std::lock_guard<std::mutex> lock(state->mutex);
            if (context.workspace->generation() == context.publication->generation) {
                state->catalog = std::move(catalog);
                state->catalog_generation = context.publication->generation;
                state->catalog_analysis_revision = context.publication->analysis_revision;
                state->visible_indices.reset();
                state->visible_catalog = nullptr;
                state->selected = -1;
            }
        }
        state->catalog_loading.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        state->catalog_loading.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(state->mutex);
        state->pdb_error = submitted.reject_reason;
    }
#endif
}

inline bool contains_case_insensitive(const std::string& text, const std::string& filter) {
    if (filter.empty())
        return true;
    return std::search(text.begin(), text.end(), filter.begin(), filter.end(),
        [](char left, char right) {
            return std::tolower(static_cast<unsigned char>(left)) ==
                   std::tolower(static_cast<unsigned char>(right));
        }) != text.end();
}

inline void request_visible_indices(
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
                                    const disasm_view::workspace_context_t&,
#else
                                    const disasm_view::workspace_context_t& context,
#endif
                                    const std::shared_ptr<state_t>& state,
                                    const std::shared_ptr<const catalog_t>& catalog,
                                    sub_tab_t tab, std::string filter) {
    if (!catalog)
        return;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->visible_indices && state->visible_catalog == catalog.get() &&
            state->visible_tab == tab && state->visible_filter == filter)
            return;
    }
    if (state->visible_loading.exchange(true, std::memory_order_acq_rel))
        return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    std::vector<std::size_t> visible;
    if (tab == sub_tab_t::structs || tab == sub_tab_t::unions) {
        const auto& entries = tab == sub_tab_t::structs ? catalog->structs : catalog->unions;
        for (std::size_t index = 0; index < entries.size(); ++index) {
            if (contains_case_insensitive(entries[index].definition.name, filter) ||
                contains_case_insensitive(entries[index].module, filter))
                visible.push_back(index);
        }
    } else if (tab == sub_tab_t::enums) {
        for (std::size_t index = 0; index < catalog->enums.size(); ++index) {
            if (contains_case_insensitive(catalog->enums[index].definition.name, filter))
                visible.push_back(index);
        }
    } else if (tab == sub_tab_t::functions) {
        for (std::size_t index = 0; index < catalog->functions.size(); ++index) {
            if (contains_case_insensitive(catalog->functions[index].name, filter))
                visible.push_back(index);
        }
    } else {
        for (std::size_t index = 0; index < catalog->typedefs.size(); ++index) {
            if (contains_case_insensitive(catalog->typedefs[index].name, filter) ||
                contains_case_insensitive(catalog->typedefs[index].canonical_type, filter))
                visible.push_back(index);
        }
    }
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->visible_indices =
            std::make_shared<const std::vector<std::size_t>>(std::move(visible));
        state->visible_catalog = catalog.get();
        state->visible_tab = tab;
        state->visible_filter = std::move(filter);
        state->selected = -1;
    }
    state->visible_loading.store(false, std::memory_order_release);
    return;
#else
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "types_hub";
    descriptor.label = "filter_workspace_type_catalog";
    descriptor.target_id = target_id.c_str();
    descriptor.generation = context.publication->generation;
    descriptor.cancellable_body = [context, state, catalog, tab, filter = std::move(filter)](
        const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        std::vector<std::size_t> visible;
        const auto cancelled = [&]() {
            return cancel.requested.load(std::memory_order_acquire) ||
                context.workspace->cancellation_token().stop_requested();
        };
        if (tab == sub_tab_t::structs || tab == sub_tab_t::unions) {
            const auto& entries = tab == sub_tab_t::structs ? catalog->structs : catalog->unions;
            visible.reserve(entries.size());
            for (std::size_t index = 0; index < entries.size() && !cancelled(); ++index) {
                if (contains_case_insensitive(entries[index].definition.name, filter) ||
                    contains_case_insensitive(entries[index].module, filter))
                    visible.push_back(index);
            }
        } else if (tab == sub_tab_t::enums) {
            visible.reserve(catalog->enums.size());
            for (std::size_t index = 0; index < catalog->enums.size() && !cancelled(); ++index) {
                if (contains_case_insensitive(catalog->enums[index].definition.name, filter))
                    visible.push_back(index);
            }
        } else if (tab == sub_tab_t::functions) {
            visible.reserve(catalog->functions.size());
            for (std::size_t index = 0; index < catalog->functions.size() && !cancelled(); ++index) {
                if (contains_case_insensitive(catalog->functions[index].name, filter))
                    visible.push_back(index);
            }
        } else {
            visible.reserve(catalog->typedefs.size());
            for (std::size_t index = 0; index < catalog->typedefs.size() && !cancelled(); ++index) {
                if (contains_case_insensitive(catalog->typedefs[index].name, filter) ||
                    contains_case_insensitive(catalog->typedefs[index].canonical_type, filter))
                    visible.push_back(index);
            }
        }
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->catalog.get() == catalog.get() && state->active == tab &&
                std::string(state->search.data()) == filter) {
                state->visible_indices =
                    std::make_shared<const std::vector<std::size_t>>(std::move(visible));
                state->visible_catalog = catalog.get();
                state->visible_tab = tab;
                state->visible_filter = filter;
                state->selected = -1;
            }
        }
        state->visible_loading.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted) {
        state->visible_loading.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lock(state->mutex);
        state->pdb_error = submitted.reject_reason;
    }
#endif
}

inline std::optional<std::uint64_t> parse_address(std::string text) {
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text.erase(0, 2);
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    return parsed.ec == std::errc() && parsed.ptr == text.data() + text.size()
        ? std::optional<std::uint64_t>(value) : std::nullopt;
}

inline void request_pdb_load(const disasm_view::workspace_context_t& context,
                             const std::shared_ptr<state_t>& state,
                             std::string path) {
    if (!context.workspace || !state || path.empty())
        return;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    auto catalog = std::make_shared<const catalog_t>(build_catalog(context));
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->catalog = std::move(catalog);
        state->visible_indices.reset();
        state->visible_catalog = nullptr;
        state->selected = -1;
        state->pdb_error.clear();
    }
    aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types,
        default_active_tab().load(std::memory_order_acquire), "load_pdb", path);
#else
    const auto accepted = analysis_session::approve_local_pdb(
        context.workspace, path, true, true);
    std::lock_guard<std::mutex> lock(state->mutex);
    state->pdb_error = accepted ? std::string() :
        accepted.error().stable_code() + ": " + accepted.error().message;
#endif
}

inline void set_sub_tab(const disasm_view::workspace_context_t& context, sub_tab_t tab) {
    const int index = static_cast<int>(tab);
    if (index < 0 || index >= static_cast<int>(sub_tab_t::COUNT))
        return;
    default_active_tab().store(index, std::memory_order_release);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::re_hubs::select(aida::preview::re_hubs::domain_t::types,
        index, sub_tab_label(tab));
#endif
    auto state = state_for(context);
    if (!state)
        return;
    std::lock_guard<std::mutex> lock(state->mutex);
    state->active = tab;
    state->selected = -1;
}

#if defined(AIDA_TYPES_HUB_VIEW_IMPLEMENTATION)
void set_sub_tab(sub_tab_t tab) {
    set_sub_tab(disasm_view::capture_selected_workspace(), tab);
}
#endif

#if defined(AIDA_TYPES_HUB_VIEW_IMPLEMENTATION)
bool stage_type_application(const disasm_view::workspace_context_t& context,
                                   const aida::analysis::address_t& address,
                                   std::string* error) {
    auto state = state_for(context);
    const auto runtime = disasm_view::runtime_address(context, address);
    if (!state || !runtime) {
        if (error) *error = "The selected address is not mapped in the active type workspace.";
        return false;
    }
    set_sub_tab(context, sub_tab_t::structs);
    std::lock_guard<std::mutex> lock(state->mutex);
    std::snprintf(state->apply_address.data(), state->apply_address.size(), "0x%llX",
        static_cast<unsigned long long>(*runtime));
    state->apply_type[0] = '\0';
    state->apply_status = "Enter a canonical type and review Apply before changing the overlay.";
    state->apply_error = false;
    if (error) error->clear();
    return true;
}
#endif

inline sub_tab_t active_sub_tab(const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (!state)
        return static_cast<sub_tab_t>(default_active_tab().load(std::memory_order_acquire));
    std::lock_guard<std::mutex> lock(state->mutex);
    return state->active;
}

inline sub_tab_t active_sub_tab() {
    return active_sub_tab(disasm_view::capture_selected_workspace());
}

inline std::string struct_to_ida_syntax(const pdb_parser::struct_def_t& definition) {
	constexpr std::size_t maximum_output = 64U * 1024U;
    std::string output = definition.is_union ? "union " : "struct ";
    output += definition.name + "\n{\n";
	if (output.size() > maximum_output)
		return {};
    std::uint64_t last_end = 0;
    int padding_index = 0;
    for (const auto& member : definition.members) {
        if (member.offset > last_end) {
            char padding[96]{};
            std::snprintf(padding, sizeof(padding), "  _BYTE pad_%d[%llu];\n",
                padding_index++, static_cast<unsigned long long>(member.offset - last_end));
            output += padding;
			if (output.size() > maximum_output)
				return {};
        }
        std::string type = member.type_name;
        if (type == "uint8_t" || type == "int8_t" || type == "char" || type == "BYTE")
            type = "_BYTE";
        else if (type == "uint16_t" || type == "int16_t" || type == "WORD" ||
                 type == "USHORT" || type == "short")
            type = "_WORD";
        else if (type == "uint32_t" || type == "int32_t" || type == "DWORD" ||
                 type == "ULONG" || type == "LONG" || type == "long")
            type = "_DWORD";
        else if (type == "uint64_t" || type == "int64_t" || type == "QWORD" ||
                 type == "ULONGLONG" || type == "__int64")
            type = "_QWORD";
        char line[256]{};
        if (member.bit_size >= 0) {
            std::snprintf(line, sizeof(line), "  %s %s : %d;\n",
                type.c_str(), member.name.c_str(), member.bit_size);
        } else if (member.is_array) {
            std::snprintf(line, sizeof(line), "  %s %s[%d];\n",
                type.c_str(), member.name.c_str(), member.array_count);
        } else {
            std::snprintf(line, sizeof(line), "  %s %s;\n",
                type.c_str(), member.name.c_str());
        }
        output += line;
		if (output.size() > maximum_output)
			return {};
        last_end = member.size > (std::numeric_limits<std::uint64_t>::max)() - member.offset
            ? (std::numeric_limits<std::uint64_t>::max)() : member.offset + member.size;
    }
    if (last_end < definition.size) {
        char padding[96]{};
        std::snprintf(padding, sizeof(padding), "  _BYTE pad_%d[%llu];\n", padding_index,
            static_cast<unsigned long long>(definition.size - last_end));
        output += padding;
		if (output.size() > maximum_output)
			return {};
    }
    output += "};\n";
	return output.size() <= maximum_output ? output : std::string{};
}

inline std::vector<type_reference_t> references_for_type(
    const catalog_t& catalog, const std::string& type_name) {
    std::vector<type_reference_t> references;
    if (type_name.empty())
        return references;
    for (const auto& function : catalog.functions) {
        if (function.signature.find(type_name) != std::string::npos)
            references.push_back({function.address, function.name + "  " + function.signature});
    }
    for (const auto& candidate : catalog.typedefs) {
        if (candidate.canonical_type.find(type_name) != std::string::npos)
            references.push_back({candidate.address,
                candidate.name + "  " + candidate.canonical_type});
    }
    std::sort(references.begin(), references.end(), [](const auto& left, const auto& right) {
        if (left.address != right.address)
            return left.address < right.address;
        return left.label < right.label;
    });
    references.erase(std::unique(references.begin(), references.end(),
        [](const auto& left, const auto& right) {
            return left.address == right.address && left.label == right.label;
        }), references.end());
    return references;
}

inline std::string enum_to_c(const pdb_parser::enum_def_t& definition) {
	constexpr std::size_t maximum_output = 64U * 1024U;
	if (definition.name.size() > maximum_output || definition.members.size() > 65536)
		return {};
	std::string declaration;
	const auto append = [&declaration](const std::string& value) {
		if (value.size() > maximum_output - declaration.size())
			return false;
		declaration.append(value);
		return true;
	};
	if (!append("enum ") || !append(definition.name) || !append(" {\n"))
		return {};
	for (const auto& member : definition.members) {
		if (!append("    ") || !append(member.name) || !append(" = ") ||
			!append(std::to_string(member.value)) || !append(",\n"))
			return {};
	}
	return append("};\n") ? declaration : std::string{};
}

inline std::string struct_to_c_bounded(const pdb_parser::struct_def_t& definition) {
	constexpr std::size_t maximum_output = 64U * 1024U;
	if (definition.members.size() > 65536 || definition.name.size() > maximum_output)
		return {};
	std::string declaration = definition.is_union ? "union " : "struct ";
	const auto append = [&declaration](const char* text, std::size_t length) {
		if (length > maximum_output - declaration.size())
			return false;
		declaration.append(text, length);
		return true;
	};
	if (!append(definition.name.data(), definition.name.size()) ||
		!append(" {\n", 3))
		return {};
	std::uint64_t last_end = 0;
	int padding_index = 0;
	for (const auto& member : definition.members) {
		char line[256]{};
		if (member.offset > last_end) {
			const int length = std::snprintf(line, sizeof(line),
				"    uint8_t _pad%d[%llu];\n", padding_index++,
				static_cast<unsigned long long>(member.offset - last_end));
			if (length < 0 || !append(line, (std::min)(
				static_cast<std::size_t>(length), sizeof(line) - 1)))
				return {};
		}
		int length = 0;
		if (member.bit_size >= 0)
			length = std::snprintf(line, sizeof(line), "    %s %s : %d;\n",
				member.type_name.c_str(), member.name.c_str(), member.bit_size);
		else if (member.is_array)
			length = std::snprintf(line, sizeof(line), "    %s %s[%d];\n",
				member.type_name.c_str(), member.name.c_str(), member.array_count);
		else
			length = std::snprintf(line, sizeof(line), "    %s %s;\n",
				member.type_name.c_str(), member.name.c_str());
		if (length < 0 || !append(line, (std::min)(
			static_cast<std::size_t>(length), sizeof(line) - 1)))
			return {};
		last_end = member.size > (std::numeric_limits<std::uint64_t>::max)() - member.offset
			? (std::numeric_limits<std::uint64_t>::max)() : member.offset + member.size;
	}
	if (last_end < definition.size) {
		char padding[96]{};
		const int length = std::snprintf(padding, sizeof(padding),
			"    uint8_t _pad%d[%llu];\n", padding_index,
			static_cast<unsigned long long>(definition.size - last_end));
		if (length < 0 || !append(padding, (std::min)(
			static_cast<std::size_t>(length), sizeof(padding) - 1)))
			return {};
	}
	char footer[96]{};
	const int footer_length = std::snprintf(footer, sizeof(footer),
		"}; // size: 0x%llX (%llu bytes)\n",
		static_cast<unsigned long long>(definition.size),
		static_cast<unsigned long long>(definition.size));
	if (footer_length < 0 || !append(footer, (std::min)(
		static_cast<std::size_t>(footer_length), sizeof(footer) - 1)))
		return {};
	return declaration;
}

inline aida::ui::action_handler_result_t stage_global_declaration_review(
	const disasm_view::workspace_context_t& context,
	const std::shared_ptr<state_t>& state, std::string name, std::string declaration) {
	if (!context.workspace || !context.publication || context.workspace->closing() ||
		context.workspace->closed())
		return aida::ui::action_handler_result_t::failed(
			"The type workspace is unavailable");
	if (name.empty() || name.size() > 256 || declaration.empty() ||
		declaration.size() > 64U * 1024U)
		return aida::ui::action_handler_result_t::failed(
			"The declaration is empty or exceeds the bounded 64 KiB review contract");
	std::lock_guard<std::mutex> lock(state->mutex);
	state->declaration_review_name = std::move(name);
	state->declaration_review_text =
		std::make_shared<const std::string>(std::move(declaration));
	state->declaration_review_workspace = context.workspace;
	state->declaration_review_publication = context.publication;
	state->declaration_review_workspace_id =
		context.workspace->identity().binary_id().to_hex();
	state->declaration_review_generation = context.publication->generation;
	state->declaration_review_analysis_revision = context.publication->analysis_revision;
	state->declaration_review_overlay_revision = context.workspace->overlay_revision();
	state->declaration_review_requested = true;
	state->apply_error = false;
	state->apply_status = "Review the global declaration before committing it to the reversible overlay.";
	return aida::ui::action_handler_result_t::completed();
}

inline void request_type_references(const disasm_view::workspace_context_t& context,
                                    const std::shared_ptr<state_t>& state,
                                    const std::shared_ptr<const catalog_t>& catalog,
                                    const std::string& type_name) {
    if (!context.workspace || context.workspace->closing() || context.workspace->closed() ||
        !state || !catalog || type_name.empty())
        return;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->reference_catalog == catalog.get() &&
            state->reference_type == type_name && state->references)
            return;
        if (state->reference_loading.load(std::memory_order_acquire))
            return;
        state->reference_loading.store(true, std::memory_order_release);
        state->reference_request_catalog = catalog.get();
        state->reference_request_type = type_name;
    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    auto references = std::make_shared<const std::vector<type_reference_t>>(
        references_for_type(*catalog, type_name));
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->reference_request_catalog == catalog.get() &&
            state->reference_request_type == type_name) {
            state->reference_catalog = catalog.get();
            state->reference_type = type_name;
            state->references = std::move(references);
        }
        state->reference_loading.store(false, std::memory_order_release);
    }
#else
    aida::infra::taskflow_runtime::task_descriptor_t descriptor;
    descriptor.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    descriptor.owner_subsystem = "types_hub";
    descriptor.label = "build_type_reference_index";
    const std::string target_id = context.workspace->identity().binary_id().to_hex();
    const std::uint64_t workspace_generation = context.workspace->generation();
    descriptor.target_id = target_id.c_str();
    descriptor.generation = workspace_generation;
    descriptor.cancellable_body = [context, state, catalog, type_name, workspace_generation](
        const aida::infra::taskflow_runtime::cancellation_token_t& cancel) {
        std::shared_ptr<const std::vector<type_reference_t>> references;
        if (!cancel.requested.load(std::memory_order_acquire) &&
            !context.workspace->cancellation_token().stop_requested())
            references = std::make_shared<const std::vector<type_reference_t>>(
                references_for_type(*catalog, type_name));
        std::lock_guard<std::mutex> lock(state->mutex);
        if (references && !context.workspace->closing() && !context.workspace->closed() &&
            context.workspace->generation() == workspace_generation &&
            state->reference_request_catalog == catalog.get() &&
            state->reference_request_type == type_name) {
            state->reference_catalog = catalog.get();
            state->reference_type = type_name;
            state->references = std::move(references);
        }
        state->reference_loading.store(false, std::memory_order_release);
    };
    const auto submitted = aida::infra::taskflow_runtime::submit(std::move(descriptor));
    if (!submitted.submitted)
        state->reference_loading.store(false, std::memory_order_release);
#endif
}

inline void publish_type_selection(const disasm_view::workspace_context_t& context,
                                   sub_tab_t tab, const std::string& module,
                                   const std::string& name,
                                   std::optional<aida::analysis::address_t> address = {}) {
    if (!context.workspace)
        return;
    aida::workbench::selection_context_t selection;
    selection.kind = aida::workbench::selection_kind_t::entity;
    selection.entity_key = "type." + std::to_string(static_cast<int>(tab)) + "." +
        module + "." + name;
    if (address) {
        selection.kind = aida::workbench::selection_kind_t::address;
        selection.has_address = true;
        selection.address = disasm_view::runtime_address(context, *address)
            .value_or(address->value);
        selection.extent = 1;
    }
    aida::workbench::document_local_cursor_t cursor;
    if (address) {
        cursor.has_position = true;
        cursor.position = selection.address;
    }
    aida::workbench::workbench_shell_workspace_context_t workbench;
    static_cast<void>(aida::workbench::workbench_shell_runtime_t::instance()
        .publish_selection(context.workspace, selection, cursor,
            aida::workbench::navigation_origin_t::navigator, workbench));
    if (address)
        disasm_view::select_address(*address, context, false);
}

inline void render_type_references(const disasm_view::workspace_context_t& context,
                                   const std::shared_ptr<const std::vector<type_reference_t>>& reference_handle,
                                   const std::string& type_name,
                                   float height) {
    static const std::vector<type_reference_t> empty_references;
    const auto& references = reference_handle ? *reference_handle : empty_references;
    ImGui::SeparatorText("References");
    if (references.empty()) {
        ImGui::TextDisabled("No indexed function signature or inferred type references this type.");
        return;
    }
    ImGui::TextDisabled("%zu indexed references", references.size());
    ImGui::BeginChild("##type_references", ImVec2(0.0f, (std::max)(72.0f, height)), true);
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>((std::min)(references.size(),
        static_cast<std::size_t>((std::numeric_limits<int>::max)()))));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& reference = references[static_cast<std::size_t>(row)];
            if (ImGui::Selectable(reference.label.c_str(), false,
                    ImGuiSelectableFlags_AllowDoubleClick)) {
                publish_type_selection(context, sub_tab_t::typedefs, "reference",
                    type_name, reference.address);
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    const auto runtime = disasm_view::runtime_address(context, reference.address)
                        .value_or(reference.address.value);
                    disasm_view::goto_address(runtime, context);
                    aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
                }
            }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
			const std::string reference_semantic_id = studio_type_entity_id(
				"reference", context, type_name + ":" +
				std::to_string(reference.address.value));
			aida::preview::semantics::register_last_item(
				reference_semantic_id, "type-reference-row");
#endif
        }
    }
    ImGui::EndChild();
}

inline std::string canonical_record_name(std::string name) {
    while (!name.empty() && std::isspace(static_cast<unsigned char>(name.back())))
        name.pop_back();
    while (!name.empty() && name.back() == '*') {
        name.pop_back();
        while (!name.empty() && std::isspace(static_cast<unsigned char>(name.back())))
            name.pop_back();
    }
    if (name.rfind("struct ", 0) == 0)
        name.erase(0, 7);
    else if (name.rfind("union ", 0) == 0)
        name.erase(0, 6);
    return name;
}

inline const pdb_parser::struct_def_t* catalog_record(const catalog_t& catalog,
                                                       const std::string& name) {
    const std::string canonical = canonical_record_name(name);
    for (const auto& entry : catalog.structs)
        if (entry.definition.name == canonical)
            return &entry.definition;
    for (const auto& entry : catalog.unions)
        if (entry.definition.name == canonical)
            return &entry.definition;
    return nullptr;
}

inline const pdb_parser::enum_def_t* catalog_enum(const catalog_t& catalog, const std::string& name) {
    const std::string canonical = canonical_record_name(name);
    for (const auto& entry : catalog.enums)
        if (entry.definition.name == canonical)
            return &entry.definition;
    return nullptr;
}

inline int send_to_dissector_recursive(const pdb_parser::struct_def_t& definition,
                                       const catalog_t* catalog,
                                       std::set<std::string>& importing,
									   bool strict_validation = false,
									   const std::string& root_source_name = {}) {
    int index = struct_dissector::structure_index_by_name(definition.name);
    if (index >= 0)
        return index;
    if (!importing.insert(definition.name).second || importing.size() > 256) {
        return -1;
    }
	const auto fail = [&] {
		importing.erase(definition.name);
		return -1;
	};
    if (catalog) {
		for (const auto& member : definition.members) {
            if (member.is_pointer)
                continue;
			if (!root_source_name.empty() &&
				canonical_record_name(member.type_name) ==
					canonical_record_name(root_source_name))
				continue;
			if (const auto* target = catalog_record(*catalog, member.type_name)) {
				if (send_to_dissector_recursive(*target, catalog, importing,
						strict_validation) < 0 && strict_validation)
					return fail();
			}
        }
    }
    index = struct_dissector::create_struct(definition.name);
    if (index < 0)
		return fail();
	if (!struct_dissector::set_structure_kind(index, definition.is_union
        ? struct_dissector::structure_kind_t::union_type
        : struct_dissector::structure_kind_t::structure) && strict_validation)
		return fail();
    for (const auto& member : definition.members) {
        if (member.offset > (std::numeric_limits<std::uint32_t>::max)() ||
			member.size > (std::numeric_limits<std::uint32_t>::max)()) {
			if (strict_validation)
				return fail();
            continue;
		}
        struct_dissector::field_def_t field;
        field.name = member.name.empty() ? "field_" + std::to_string(member.offset) : member.name;
        field.offset = static_cast<std::uint32_t>(member.offset);
        const std::uint32_t array_count = member.is_array && member.array_count > 0
            ? static_cast<std::uint32_t>(member.array_count) : 1u;
        field.array_count = array_count;
        field.size = static_cast<std::uint32_t>(member.size == 0 ? 1 :
            (member.size % array_count == 0 ? member.size / array_count : member.size));
        field.referenced_type_name = canonical_record_name(member.type_name);
        if (member.is_pointer)
            field.type = struct_dissector::field_type_t::pointer;
        else if (catalog && catalog_record(*catalog, member.type_name))
            field.type = struct_dissector::field_type_t::byte_array;
        else if (member.size == 1)
            field.type = struct_dissector::field_type_t::uint8;
        else if (member.size == 2)
            field.type = struct_dissector::field_type_t::uint16;
        else if (member.size == 4)
            field.type = struct_dissector::field_type_t::uint32;
        else if (member.size == 8)
            field.type = struct_dissector::field_type_t::uint64;
        else
            field.type = struct_dissector::field_type_t::byte_array;
        field.description = member.type_name;
        if (member.bit_offset >= 0 && member.bit_size > 0) {
            field.bit_offset = static_cast<std::uint16_t>((std::min)(member.bit_offset, 65535));
            field.bit_width = static_cast<std::uint16_t>((std::min)(member.bit_size, 65535));
        }
        const int field_index = struct_dissector::add_field(index, field);
        if (field_index < 0) {
			if (strict_validation)
				return fail();
            continue;
		}
        if (catalog) {
            if (const auto* target = catalog_record(*catalog, member.type_name)) {
				const int target_index = !root_source_name.empty() &&
					canonical_record_name(member.type_name) ==
						canonical_record_name(root_source_name)
					? index : struct_dissector::structure_index_by_name(target->name);
				if (target_index >= 0) {
					if (!struct_dissector::set_field_nested_target(index, field_index,
							target_index, member.is_pointer) && strict_validation)
						return fail();
				} else if (strict_validation && !member.is_pointer) {
					return fail();
				}
			} else if (const auto* source_enum = catalog_enum(*catalog, member.type_name)) {
				struct_dissector::enum_def_t enumeration;
				enumeration.name = source_enum->name;
				enumeration.values.reserve(source_enum->members.size());
				for (const auto& value : source_enum->members)
					enumeration.values.push_back({value.name, value.value});
				if (!struct_dissector::upsert_enum(enumeration) && strict_validation)
					return fail();
                if (!struct_dissector::set_field_enum_reference(index, field_index,
						canonical_record_name(member.type_name)) && strict_validation)
					return fail();
            }
        }
    }
    importing.erase(definition.name);
    return index;
}

inline bool send_to_dissector(const pdb_parser::struct_def_t& definition,
	const catalog_t* catalog = nullptr, bool* rollback_complete = nullptr) {
	if (rollback_complete)
		*rollback_complete = true;
	if (!struct_dissector::catalog_mutation_available())
		return false;
	auto rollback_state = struct_dissector::capture_catalog_transaction();
    std::set<std::string> importing;
	const int imported = send_to_dissector_recursive(definition, catalog, importing, true);
	if (imported >= 0) {
		const auto imported_revision = struct_dissector::catalog_schema_revision();
		return struct_dissector::request_save_schema_transactional(
			std::move(rollback_state), imported_revision);
	}
	const bool rolled_back = struct_dissector::rollback_catalog_transaction(
		std::move(rollback_state), struct_dissector::catalog_schema_revision());
	if (rollback_complete)
		*rollback_complete = rolled_back;
	return false;
}

inline void render_struct_detail(const disasm_view::workspace_context_t& context,
                                 const std::shared_ptr<const catalog_t>& catalog_handle,
                                 const std::shared_ptr<state_t>& state,
                                 const struct_entry_t& entry, float height) {
    const auto& catalog = *catalog_handle;
    const auto& definition = entry.definition;
    ImGui::Text("%s %s", definition.is_union ? "union" : "struct", definition.name.c_str());
    ImGui::TextDisabled("%s  size 0x%llX  %zu members", entry.module.c_str(),
        static_cast<unsigned long long>(definition.size), definition.members.size());
    if (ImGui::Button("Copy C")) {
		const std::string declaration = struct_to_c_bounded(definition);
		if (!declaration.empty())
			ImGui::SetClipboardText(declaration.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Copy IDA")) {
        const std::string declaration = struct_to_ida_syntax(definition);
		if (!declaration.empty() && declaration.size() <= 64U * 1024U)
			ImGui::SetClipboardText(declaration.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Open Dissector")) {
		bool rollback_complete = true;
		const bool imported = send_to_dissector(definition, catalog_handle.get(),
			&rollback_complete);
		{
			std::lock_guard<std::mutex> lock(state->mutex);
			state->apply_error = !imported;
			state->apply_status = imported
				? "Imported the editable type and queued durable catalog persistence."
				: rollback_complete
					? "The editable import failed or durable persistence was rejected; no mutation was retained."
					: "The editable import failed and exact catalog rollback was blocked; review the persistent diagnostic.";
		}
		if (imported)
			set_sub_tab(context, sub_tab_t::dissector);
	}
    ImGui::SameLine();
	if (ImGui::Button("Declare in overlay"))
		static_cast<void>(stage_global_declaration_review(context, state,
			definition.name, struct_to_c_bounded(definition)));
    ImGui::Separator();
    const float members_height = (std::max)(96.0f, height * 0.58f);
    ImGui::BeginChild("##type_members", ImVec2(0.0f, members_height), false);
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>((std::min)(definition.members.size(),
        static_cast<std::size_t>((std::numeric_limits<int>::max)()))));
    while (clipper.Step()) {
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
            const auto& member = definition.members[static_cast<std::size_t>(index)];
            ImGui::Text("+0x%04llX  %-28s  %s",
                static_cast<unsigned long long>(member.offset), member.name.c_str(),
                member.type_name.c_str());
        }
    }
    ImGui::EndChild();
    std::shared_ptr<const std::vector<type_reference_t>> references;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->reference_catalog == &catalog &&
            state->reference_type == definition.name)
            references = state->references;
    }
    if (!references)
        request_type_references(context, state, catalog_handle, definition.name);
    if (!references && state->reference_loading.load(std::memory_order_acquire))
        ImGui::TextDisabled("Indexing type references...");
    if (references)
        render_type_references(context, references, definition.name,
            height - members_height - 48.0f);
}

inline void render_enum_detail(const enum_entry_t& entry, float height,
	const std::shared_ptr<state_t>& state, std::uint64_t generation,
	std::uint64_t analysis_revision) {
    const auto& definition = entry.definition;
	const std::string identity = entry.module + ":" + definition.name;
	std::shared_ptr<const std::string> declaration;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		if (state->enum_declaration_cache_generation == generation &&
			state->enum_declaration_cache_analysis_revision == analysis_revision &&
			state->enum_declaration_cache_identity == identity)
			declaration = state->enum_declaration_cache;
	}
	if (!declaration) {
		declaration = std::make_shared<const std::string>(enum_to_c(definition));
		std::lock_guard<std::mutex> lock(state->mutex);
		state->enum_declaration_cache_generation = generation;
		state->enum_declaration_cache_analysis_revision = analysis_revision;
		state->enum_declaration_cache_identity = identity;
		state->enum_declaration_cache = declaration;
	}
    ImGui::Text("enum %s", definition.name.c_str());
    ImGui::TextDisabled("%s  %zu values", entry.module.c_str(), definition.members.size());
    ImGui::BeginDisabled(declaration->empty());
	const bool export_declaration = ImGui::Button("Export Declaration");
	ImGui::EndDisabled();
	if (export_declaration) {
        ImGui::SetClipboardText(declaration->c_str());
    }
	if (declaration->empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
		ImGui::SetTooltip("The enum declaration exceeds the bounded 64 KiB export limit");
    ImGui::Separator();
    ImGui::BeginChild("##enum_members", ImVec2(0.0f, height), false);
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>((std::min)(definition.members.size(),
        static_cast<std::size_t>((std::numeric_limits<int>::max)()))));
    while (clipper.Step()) {
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
            const auto& member = definition.members[static_cast<std::size_t>(index)];
            ImGui::Text("%-36s  %lld", member.name.c_str(),
                static_cast<long long>(member.value));
        }
    }
    ImGui::EndChild();
}

inline bool context_key_pressed() {
    const ImGuiIO& io = ImGui::GetIO();
    return ImGui::IsKeyPressed(ImGuiKey_Menu, false) ||
        (io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_F10, false));
}

inline bool catalog_context_is_current(const disasm_view::workspace_context_t& context,
                                       const state_t& state) {
    return context.publication && context.workspace &&
        !context.workspace->closing() && !context.workspace->closed() &&
        state.context_generation == context.publication->generation &&
        state.context_analysis_revision == context.publication->analysis_revision &&
        state.catalog_generation == state.context_generation &&
        state.catalog_analysis_revision == state.context_analysis_revision;
}

inline void render_catalog_context_menu(const disasm_view::workspace_context_t& context,
                                        const std::shared_ptr<state_t>& state,
                                        const std::shared_ptr<const catalog_t>& catalog_handle,
                                        const std::shared_ptr<const std::vector<std::size_t>>& visible_handle,
                                        bool requested,
                                        aida::ui::context_menu_open_origin_t origin) {
    static const std::vector<std::size_t> empty_visible;
    const auto& visible = visible_handle ? *visible_handle : empty_visible;
    int row = -1;
    sub_tab_t tab = sub_tab_t::structs;
    bool current = false;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        row = state->context_row;
        tab = state->context_tab;
        current = catalog_context_is_current(context, *state);
    }
    if (!requested || !catalog_handle || !current || row < 0 ||
        static_cast<std::size_t>(row) >= visible.size()) {
        aida::ui::application_ui::render_retained_entity_context_menu("types.catalog.entity");
        return;
    }
    const auto& catalog = *catalog_handle;
    const std::size_t index = visible[static_cast<std::size_t>(row)];
    aida::ui::application_ui::retained_entity_context_t retained;
    retained.owner_id = "types.catalog.entity";
    retained.entity_generation = context.publication ? context.publication->generation : 0;
    retained.active_view = aida::ui::stable_view_id_t(
        tab == sub_tab_t::structs ? "view.types.structures" :
        tab == sub_tab_t::unions ? "view.types.unions" :
        tab == sub_tab_t::enums ? "view.types.enums" :
        tab == sub_tab_t::functions ? "view.types.functions" :
        tab == sub_tab_t::inferred ? "view.types.inferred" : "view.types.typedefs");
    const auto publication = context.publication;
    const auto workspace = context.workspace;
	const std::string workspace_id = context.workspace
		? context.workspace->identity().binary_id().to_hex() : std::string{};
	const std::uint64_t workspace_generation = context.workspace
		? context.workspace->generation() : 0;
    const std::uint64_t analysis_revision = context.publication
        ? context.publication->analysis_revision : 0;
    retained.validate_identity = [publication, workspace, catalog_handle, visible_handle,
                                  index, row, tab, analysis_revision,
								  workspace_generation, workspace_id, state] {
		const auto selected = disasm_view::capture_selected_workspace();
        if (!publication || !workspace || workspace->closing() || workspace->closed() ||
			workspace->generation() != workspace_generation ||
			publication->generation != workspace_generation ||
			publication->analysis_revision != analysis_revision ||
			!selected.workspace || !selected.publication ||
			selected.workspace != workspace || selected.publication != publication ||
			selected.workspace->identity().binary_id().to_hex() != workspace_id ||
			selected.workspace->generation() != workspace_generation ||
			selected.publication->analysis_revision != analysis_revision)
            return aida::ui::capability_state_t::unavailable(
                "The analysis workspace changed; select the type again");
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->context_generation != publication->generation ||
            state->context_analysis_revision != publication->analysis_revision ||
            state->catalog_generation != state->context_generation ||
            state->catalog_analysis_revision != state->context_analysis_revision ||
            state->context_row != row || state->context_tab != tab ||
            state->catalog != catalog_handle || state->visible_indices != visible_handle ||
            !visible_handle || static_cast<std::size_t>(row) >= visible_handle->size() ||
            (*visible_handle)[static_cast<std::size_t>(row)] != index)
            return aida::ui::capability_state_t::unavailable(
                "The type catalog publication or filtered row changed; select the type again");
        return aida::ui::capability_state_t::available();
    };
    auto add_action = [&retained](const char* id, bool enabled, const char* reason,
                                  auto invoke) {
        aida::ui::application_ui::retained_entity_action_t action;
        action.action_id = id;
        action.capability = enabled ? aida::ui::capability_state_t::available()
            : aida::ui::capability_state_t::unavailable(reason);
        action.invoke = std::move(invoke);
        retained.actions.push_back(std::move(action));
    };
    if (tab == sub_tab_t::structs || tab == sub_tab_t::unions) {
        const auto& entry = tab == sub_tab_t::structs ? catalog.structs[index] : catalog.unions[index];
        retained.entity_id = (tab == sub_tab_t::structs ? "struct:" : "union:") +
            entry.module + ":" + entry.definition.name;
        const auto definition = entry.definition;
        const std::string name = definition.name;
        add_action("types.catalog.copy_name", true, "", [name] {
            ImGui::SetClipboardText(name.c_str());
            return aida::ui::action_handler_result_t::completed();
        });
		const std::string ida_declaration = struct_to_ida_syntax(definition);
		add_action("types.catalog.copy_ida_declaration",
			!ida_declaration.empty() && ida_declaration.size() <= 64U * 1024U,
			"The IDA declaration exceeds the bounded 64 KiB export limit",
			[ida_declaration] {
			ImGui::SetClipboardText(ida_declaration.c_str());
            return aida::ui::action_handler_result_t::completed();
        });
		const std::string c_declaration = struct_to_c_bounded(definition);
		const bool mutable_persistence_available =
			!struct_dissector::g_state.persistence_in_flight.load(std::memory_order_acquire);
		add_action("types.catalog.export_declaration",
			!c_declaration.empty() && c_declaration.size() <= 64U * 1024U,
			"The declaration is empty or exceeds the bounded 64 KiB export limit",
			[c_declaration] {
				ImGui::SetClipboardText(c_declaration.c_str());
				return aida::ui::action_handler_result_t::completed();
			});
		add_action("types.catalog.duplicate_to_editor", mutable_persistence_available &&
			definition.members.size() <= 65536,
			!mutable_persistence_available ? "Another mutable catalog operation is running"
				: "The type exceeds the mutable editor's bounded member limit",
			[definition, context, catalog_handle] {
				pdb_parser::struct_def_t duplicate = definition;
				auto rollback_state = struct_dissector::capture_catalog_transaction();
				std::string base = definition.name.empty() ? "anonymous_copy" : definition.name + "_copy";
				if (base.size() > 240) base.resize(240);
				{
					auto& editor = struct_dissector::g_state;
					std::lock_guard<std::mutex> lock(editor.mtx);
					if (editor.persistence_in_flight.load(std::memory_order_acquire))
						return aida::ui::action_handler_result_t::failed(
							"Another mutable catalog operation started before duplication");
					std::string candidate = base;
					for (std::size_t suffix = 2; suffix <= 1024 &&
						std::any_of(editor.structs.begin(), editor.structs.end(),
							[&](const auto& item) { return item.name == candidate; }); ++suffix)
						candidate = base + "_" + std::to_string(suffix);
					if (std::any_of(editor.structs.begin(), editor.structs.end(),
						[&](const auto& item) { return item.name == candidate; }))
						return aida::ui::action_handler_result_t::failed(
							"A bounded unique duplicate name could not be allocated");
					duplicate.name = std::move(candidate);
				}
				auto rollback = [&] {
					return struct_dissector::rollback_catalog_transaction(
						std::move(rollback_state), struct_dissector::catalog_schema_revision());
				};
				std::set<std::string> importing;
				const int created = send_to_dissector_recursive(duplicate,
					catalog_handle.get(), importing, true, definition.name);
				if (created < 0) {
					if (!rollback())
						return aida::ui::action_handler_result_t::failed(
							"Duplicate validation failed and exact catalog rollback was blocked");
					return aida::ui::action_handler_result_t::failed(
						"The duplicate failed mutable-catalog validation");
				}
				{
					auto& editor = struct_dissector::g_state;
					std::lock_guard<std::mutex> lock(editor.mtx);
					editor.active_struct = created;
				}
				if (!struct_dissector::request_save_schema()) {
					if (!rollback())
						return aida::ui::action_handler_result_t::failed(
							"Durable save was rejected and exact catalog rollback was blocked");
					return aida::ui::action_handler_result_t::failed(
						"The durable catalog save was not queued; all imported dependencies were rolled back");
				}
				struct_dissector_view::g_ui.selected_field = -1;
				struct_dissector_view::g_ui.editing_field = -1;
				set_sub_tab(context, sub_tab_t::dissector);
				return aida::ui::action_handler_result_t::completed(
					"Editable duplicate created; durable catalog save queued");
			});
		add_action("types.catalog.open_structure_editor", true, "", [definition, context, catalog_handle] {
			bool rollback_complete = true;
			if (!send_to_dissector(definition, catalog_handle.get(), &rollback_complete))
				return aida::ui::action_handler_result_t::failed(
					rollback_complete
						? "The editable import failed or durable persistence was rejected; no mutation was retained"
						: "The editable import failed and exact catalog rollback was blocked");
            set_sub_tab(context, sub_tab_t::dissector);
			return aida::ui::action_handler_result_t::completed(
				"Editable type imported; durable catalog save queued");
        });
		const bool global_promotion_available = !name.empty() && name.size() <= 256 &&
			!c_declaration.empty();
		add_action("types.catalog.promote_global", global_promotion_available,
			name.empty() || name.size() > 256
				? "The type name is empty or exceeds the bounded 256-byte review identity"
				: "The declaration is empty or exceeds the bounded 64 KiB review limit",
			[name, c_declaration, context, state] {
			return stage_global_declaration_review(context, state, name, c_declaration);
		});
        add_action("types.catalog.rename", false,
            "PDB catalog definitions are immutable; declare an edited overlay type instead",
            [] { return aida::ui::action_handler_result_t::completed(); });
        add_action("types.catalog.delete", false,
            "PDB catalog definitions cannot be deleted from the analysis workspace",
            [] { return aida::ui::action_handler_result_t::completed(); });
		aida::automation_ui::entity_evidence::snapshot_t evidence;
		evidence.workspace_id = context.workspace->identity().binary_id().to_hex();
		evidence.source_view_id = definition.is_union ? "view.types.unions" : "view.types.structures";
		evidence.source_kind = definition.is_union ? "type_union" : "type_structure";
		evidence.entity_id = retained.entity_id;
		evidence.display_label = (definition.is_union ? "union " : "struct ") + definition.name;
		evidence.excerpt = c_declaration;
		evidence.revision = analysis_revision;
		evidence.generation = retained.entity_generation;
		aida::automation_ui::entity_evidence::append_actions(retained, std::move(evidence),
			c_declaration.empty()
				? aida::ui::capability_state_t::unavailable(
					"The retained type has no bounded declaration evidence")
				: aida::ui::capability_state_t::available());
    } else if (tab == sub_tab_t::enums) {
        const auto& entry = catalog.enums[index];
        retained.entity_id = "enum:" + entry.module + ":" + entry.definition.name;
        const auto definition = entry.definition;
        const std::string name = definition.name;
        add_action("types.catalog.copy_name", true, "", [name] {
            ImGui::SetClipboardText(name.c_str());
            return aida::ui::action_handler_result_t::completed();
        });
        add_action("types.catalog.edit_enum", true, "", [definition, context] {
            struct_dissector::enum_def_t editable;
            bool existing = false;
            {
                auto& state = struct_dissector::g_state;
                std::lock_guard<std::mutex> lock(state.mtx);
                const auto found = std::find_if(state.enums.begin(), state.enums.end(),
                    [&](const auto& item) { return item.name == definition.name; });
                if (found != state.enums.end()) {
                    editable = *found;
                    existing = true;
                }
            }
            if (!existing) {
				if (!struct_dissector::catalog_mutation_available())
					return aida::ui::action_handler_result_t::failed(
						"Another mutable catalog operation is running");
				auto rollback_state = struct_dissector::capture_catalog_transaction();
				const auto import_base_revision = rollback_state.schema_revision;
                editable.name = definition.name;
                editable.underlying_type = struct_dissector::field_type_t::int64;
                editable.values.reserve(definition.members.size());
                for (const auto& member : definition.members)
                    editable.values.push_back({member.name, member.value});
				if (!struct_dissector::upsert_enum(editable)) {
					if (!struct_dissector::rollback_catalog_transaction(
							std::move(rollback_state), import_base_revision))
						return aida::ui::action_handler_result_t::failed(
							"The enum import failed and exact catalog rollback was blocked");
                    return aida::ui::action_handler_result_t::failed(
						"The enum could not be imported; no catalog mutation was retained");
				}
				const auto imported_revision = struct_dissector::catalog_schema_revision();
				if (!struct_dissector::request_save_schema_transactional(
						std::move(rollback_state), imported_revision)) {
					return aida::ui::action_handler_result_t::failed(
						"Durable enum import was rejected; the mutable catalog was restored");
				}
                auto& state = struct_dissector::g_state;
                std::lock_guard<std::mutex> lock(state.mtx);
                const auto found = std::find_if(state.enums.begin(), state.enums.end(),
                    [&](const auto& item) { return item.name == definition.name; });
                if (found == state.enums.end())
                    return aida::ui::action_handler_result_t::failed(
                        "The imported enum was not published to the mutable catalog");
                editable = *found;
            }
            struct_dissector_view::g_ui.selected_enum_id = editable.stable_id;
            std::strncpy(struct_dissector_view::g_ui.enum_name_buf,
                editable.name.c_str(), sizeof(struct_dissector_view::g_ui.enum_name_buf) - 1);
            struct_dissector_view::g_ui.enum_name_buf[
                sizeof(struct_dissector_view::g_ui.enum_name_buf) - 1] = '\0';
            std::string values;
            for (const auto& member : editable.values) {
                if (!values.empty()) values.push_back('\n');
                values += member.name + "=" + std::to_string(member.value);
            }
            std::strncpy(struct_dissector_view::g_ui.enum_values_buf, values.c_str(),
                sizeof(struct_dissector_view::g_ui.enum_values_buf) - 1);
            struct_dissector_view::g_ui.enum_values_buf[
                sizeof(struct_dissector_view::g_ui.enum_values_buf) - 1] = '\0';
            struct_dissector_view::g_ui.enum_underlying_type =
                static_cast<int>(editable.underlying_type);
            struct_dissector_view::g_ui.operation_error = false;
            struct_dissector_view::g_ui.operation_status = existing
                ? "Opened existing mutable enum unchanged; review replacements in Enum Manager"
                : "Imported enum into the mutable catalog";
            struct_dissector_view::g_ui.enum_popup_requested = true;
            set_sub_tab(context, sub_tab_t::dissector);
            return aida::ui::action_handler_result_t::completed();
        });
		const std::string enum_declaration = enum_to_c(definition);
		const bool mutable_persistence_available =
			!struct_dissector::g_state.persistence_in_flight.load(std::memory_order_acquire);
		add_action("types.catalog.export_declaration", !enum_declaration.empty(),
			"The enum declaration exceeds the bounded 64 KiB export limit",
			[enum_declaration] {
				ImGui::SetClipboardText(enum_declaration.c_str());
				return aida::ui::action_handler_result_t::completed();
			});
		add_action("types.catalog.duplicate_to_editor", mutable_persistence_available &&
			definition.members.size() <= 65536,
			!mutable_persistence_available ? "Another mutable catalog operation is running"
				: "The enum exceeds the mutable editor's bounded value limit", [definition, context] {
			struct_dissector::enum_def_t duplicate;
			duplicate.underlying_type = struct_dissector::field_type_t::int64;
			duplicate.values.reserve(definition.members.size());
			for (const auto& member : definition.members)
				duplicate.values.push_back({member.name, member.value});
			auto rollback_state = struct_dissector::capture_catalog_transaction();
			std::uint64_t before_revision = 0;
			{
				auto& editor = struct_dissector::g_state;
				std::lock_guard<std::mutex> lock(editor.mtx);
				if (editor.persistence_in_flight.load(std::memory_order_acquire))
					return aida::ui::action_handler_result_t::failed(
						"Another mutable catalog operation started before duplication");
				before_revision = editor.schema_revision;
				std::string base = definition.name.empty() ? "anonymous_enum_copy"
					: definition.name + "_copy";
				if (base.size() > 240) base.resize(240);
				duplicate.name = base;
				for (std::size_t suffix = 2; suffix <= 4096 &&
					std::any_of(editor.enums.begin(), editor.enums.end(),
						[&](const auto& item) { return item.name == duplicate.name; }); ++suffix)
					duplicate.name = base + "_" + std::to_string(suffix);
				if (std::any_of(editor.enums.begin(), editor.enums.end(),
					[&](const auto& item) { return item.name == duplicate.name; }))
					return aida::ui::action_handler_result_t::failed(
						"A bounded unique enum name could not be allocated");
			}
			if (!struct_dissector::upsert_enum_exact(duplicate, before_revision)) {
				if (!struct_dissector::rollback_catalog_transaction(
						std::move(rollback_state), before_revision))
					return aida::ui::action_handler_result_t::failed(
						"Enum duplication failed and exact catalog rollback was blocked");
				return aida::ui::action_handler_result_t::failed(
					"The enum catalog changed or duplication failed; no mutation was retained");
			}
			std::uint64_t created_revision = 0;
			{
				auto& editor = struct_dissector::g_state;
				std::lock_guard<std::mutex> lock(editor.mtx);
				created_revision = editor.schema_revision;
			}
			if (!struct_dissector::request_save_schema()) {
				if (!struct_dissector::rollback_catalog_transaction(
						std::move(rollback_state), created_revision))
					return aida::ui::action_handler_result_t::failed(
						"The durable save was rejected and exact enum rollback was blocked");
				return aida::ui::action_handler_result_t::failed(
					"The durable catalog save was not queued; the duplicate was rolled back");
			}
			set_sub_tab(context, sub_tab_t::dissector);
			return aida::ui::action_handler_result_t::completed(
				"Editable enum duplicate created; durable catalog save queued");
		});
		const bool global_enum_promotion_available = !definition.name.empty() &&
			definition.name.size() <= 256 && !enum_declaration.empty();
		add_action("types.catalog.promote_global", global_enum_promotion_available,
			definition.name.empty() || definition.name.size() > 256
				? "The enum name is empty or exceeds the bounded 256-byte review identity"
				: "The enum declaration exceeds the bounded review limit",
			[definition, enum_declaration, context, state] {
				return stage_global_declaration_review(context, state, definition.name,
					enum_declaration);
			});
		aida::automation_ui::entity_evidence::snapshot_t evidence;
		evidence.workspace_id = context.workspace->identity().binary_id().to_hex();
		evidence.source_view_id = "view.types.enums";
		evidence.source_kind = "type_enum";
		evidence.entity_id = retained.entity_id;
		evidence.display_label = "enum " + definition.name;
		evidence.excerpt = enum_declaration;
		evidence.revision = analysis_revision;
		evidence.generation = retained.entity_generation;
		aida::automation_ui::entity_evidence::append_actions(retained, std::move(evidence),
			enum_declaration.empty()
				? aida::ui::capability_state_t::unavailable(
					"The enum declaration exceeds the bounded evidence contract")
				: aida::ui::capability_state_t::available());
    } else if (tab == sub_tab_t::functions) {
        const auto& entry = catalog.functions[index];
        const auto address = disasm_view::runtime_address(context, entry.address).value_or(entry.address.value);
        retained.entity_id = "function:" + std::to_string(entry.address.value) + ":" + entry.name;
        add_action("types.catalog.function.follow_disassembly", address != 0,
            "The function has no concrete address", [address, context] {
            disasm_view::goto_address(address, context);
            aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
            return aida::ui::action_handler_result_t::completed();
        });
        add_action("types.catalog.function.open_pseudocode", address != 0,
            "The function has no concrete address", [address, context] {
            pseudocode_view::request_decompile(context, address, false);
            aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.pseudocode"));
            return aida::ui::action_handler_result_t::completed();
        });
        const std::string name = entry.name;
        const std::string signature = entry.signature;
        add_action("types.catalog.copy_name", true, "", [name] {
            ImGui::SetClipboardText(name.c_str());
            return aida::ui::action_handler_result_t::completed();
        });
        add_action("types.catalog.function.copy_signature", !signature.empty(),
            "The retained function has no signature", [signature] {
            ImGui::SetClipboardText(signature.c_str());
            return aida::ui::action_handler_result_t::completed();
        });
        add_action("types.catalog.function.copy_address", address != 0,
            "The function has no concrete address", [address] {
            char text[32]{};
            std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(address));
            ImGui::SetClipboardText(text);
            return aida::ui::action_handler_result_t::completed();
        });
        add_action("types.catalog.function.retype", false,
            "Use the reversible type overlay at a concrete function address",
            [] { return aida::ui::action_handler_result_t::completed(); });
		aida::automation_ui::entity_evidence::snapshot_t evidence;
		evidence.workspace_id = context.workspace->identity().binary_id().to_hex();
		evidence.source_view_id = "view.types.functions";
		evidence.source_kind = "typed_function";
		evidence.entity_id = retained.entity_id;
		evidence.display_label = name;
		evidence.excerpt = signature.empty() ? name : signature;
		evidence.address = address;
		evidence.revision = analysis_revision;
		evidence.generation = retained.entity_generation;
		aida::automation_ui::entity_evidence::append_actions(retained, std::move(evidence));
    } else {
        const auto& entry = catalog.typedefs[index];
        retained.entity_id = (tab == sub_tab_t::typedefs ? "typedef:" : "inferred:") +
            entry.name + ":" + std::to_string(entry.address.value);
        const std::string name = entry.name;
        const std::string canonical = entry.canonical_type;
        add_action("types.catalog.copy_name", true, "", [name] {
            ImGui::SetClipboardText(name.c_str());
            return aida::ui::action_handler_result_t::completed();
        });
        add_action("types.catalog.copy_canonical_type",
            !entry.explicitly_unknown && !canonical.empty(),
            "The retained type is explicitly unknown or has no canonical spelling", [canonical] {
            ImGui::SetClipboardText(canonical.c_str());
            return aida::ui::action_handler_result_t::completed();
        });
        const auto address = entry.address.value != 0
            ? disasm_view::runtime_address(context, entry.address).value_or(entry.address.value) : 0;
        add_action("types.catalog.evidence.follow_disassembly", address != 0,
            "The retained type has no evidence address", [address, context] {
            disasm_view::goto_address(address, context);
            aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
            return aida::ui::action_handler_result_t::completed();
        });
		const std::string alias_declaration = !entry.explicitly_unknown && !name.empty() &&
			!canonical.empty() ? "using " + name + " = " + canonical + ";\n" : std::string{};
		add_action("types.catalog.export_declaration", !alias_declaration.empty() &&
			alias_declaration.size() <= 64U * 1024U,
			"The retained type cannot produce a bounded declaration", [alias_declaration] {
				ImGui::SetClipboardText(alias_declaration.c_str());
				return aida::ui::action_handler_result_t::completed();
			});
		add_action("types.catalog.promote_global", !alias_declaration.empty() &&
			alias_declaration.size() <= 64U * 1024U,
			"The retained type is unknown or cannot produce a bounded declaration",
			[context, state, name, alias_declaration] {
				return stage_global_declaration_review(context, state, name, alias_declaration);
			});
		aida::automation_ui::entity_evidence::snapshot_t evidence;
		evidence.workspace_id = context.workspace->identity().binary_id().to_hex();
		evidence.source_view_id = tab == sub_tab_t::typedefs
			? "view.types.typedefs" : "view.types.inferred";
		evidence.source_kind = tab == sub_tab_t::typedefs ? "type_alias" : "inferred_type";
		evidence.entity_id = retained.entity_id;
		evidence.display_label = name;
		evidence.excerpt = alias_declaration.empty()
			? name + ": unknown type evidence" : alias_declaration;
		evidence.address = address;
		evidence.revision = analysis_revision;
		evidence.generation = retained.entity_generation;
		aida::automation_ui::entity_evidence::append_actions(retained, std::move(evidence));
    }
    aida::ui::application_ui::open_retained_entity_context_menu(
        std::move(retained), origin);
    aida::ui::application_ui::render_retained_entity_context_menu("types.catalog.entity");
}

inline void render_declaration_review(const disasm_view::workspace_context_t& context,
	const std::shared_ptr<state_t>& state) {
	bool open = false;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		if (state->declaration_review_requested) {
			state->declaration_review_requested = false;
			open = true;
		}
	}
	if (open)
		aida::ui::design::open_dialog("dialog.types.global_declaration_review",
			"Review Global Type Declaration");
	if (!aida::ui::design::begin_dialog("dialog.types.global_declaration_review",
			"Review Global Type Declaration", ImVec2(720.0f, 560.0f),
			ImVec2(460.0f, 320.0f)))
		return;
	std::string name;
	std::shared_ptr<const std::string> declaration;
	std::shared_ptr<aida::analysis::analysis_workspace_t> review_workspace;
	std::shared_ptr<const aida::analysis::analysis_publication_t> review_publication;
	std::string workspace_id;
	std::uint64_t generation = 0;
	std::uint64_t analysis_revision = 0;
	std::uint64_t overlay_revision = 0;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		name = state->declaration_review_name;
		declaration = state->declaration_review_text;
		review_workspace = state->declaration_review_workspace.lock();
		review_publication = state->declaration_review_publication;
		workspace_id = state->declaration_review_workspace_id;
		generation = state->declaration_review_generation;
		analysis_revision = state->declaration_review_analysis_revision;
		overlay_revision = state->declaration_review_overlay_revision;
	}
	const bool current = declaration && context.workspace && context.publication &&
		!context.workspace->closing() && !context.workspace->closed() &&
		context.workspace == review_workspace && context.publication == review_publication &&
		context.workspace->identity().binary_id().to_hex() == workspace_id &&
		context.publication->generation == generation &&
		context.publication->analysis_revision == analysis_revision &&
		context.workspace->overlay_revision() == overlay_revision;
	const float footer_height = aida::ui::design::dialog_footer_reserve_height(
		"Commit to Overlay", "Cancel");
	if (aida::ui::design::begin_dialog_body(
			"types_global_declaration_review_body", footer_height)) {
		ImGui::Text("Global declaration: %s", name.c_str());
		ImGui::TextDisabled("Workspace generation %llu  analysis revision %llu  overlay revision %llu",
			static_cast<unsigned long long>(generation),
			static_cast<unsigned long long>(analysis_revision),
			static_cast<unsigned long long>(overlay_revision));
		ImGui::Separator();
		ImGui::TextUnformatted(declaration ? declaration->c_str() : "");
		if (!current) {
			ImGui::Spacing();
			aida::ui::inline_notice("types_global_declaration_review_stale",
				"Review is stale",
				"The workspace, analysis, or overlay revision changed. Cancel and select the type again.",
				aida::ui::status_kind_t::warning);
		}
	}
	aida::ui::design::end_dialog_body();
	const auto footer = aida::ui::design::dialog_footer(
		"types_global_declaration_review_footer", "Commit to Overlay",
		current, false, "Cancel");
	if (footer.confirmed) {
		const bool queued = disasm_view::queue_type_declaration(context, *declaration);
		std::lock_guard<std::mutex> lock(state->mutex);
		state->apply_error = !queued;
		state->apply_pending = queued;
		state->apply_generation = generation;
		state->apply_expected_overlay_revision = overlay_revision;
		state->apply_status = queued
			? "Queued global declaration; waiting for the reversible overlay revision to commit."
			: "The overlay authority rejected the global declaration; no change was claimed.";
		if (queued) {
			state->declaration_review_text.reset();
			state->declaration_review_publication.reset();
			state->declaration_review_workspace.reset();
			ImGui::CloseCurrentPopup();
		}
	}
	if (footer.cancelled) {
		std::lock_guard<std::mutex> lock(state->mutex);
		state->declaration_review_text.reset();
		state->declaration_review_name.clear();
		state->declaration_review_publication.reset();
		state->declaration_review_workspace.reset();
		state->declaration_review_workspace_id.clear();
		ImGui::CloseCurrentPopup();
	}
	ImGui::EndPopup();
}

inline void render(float, float, float width, float height,
                   float alpha, float, float, float,
                   const disasm_view::workspace_context_t& context) {
    if (!context) {
        ImGui::BeginChild("##types_no_workspace", ImVec2(width, height), false);
        ImGui::TextUnformatted("No analysis workspace is selected.");
        ImGui::EndChild();
        return;
    }
    auto state = state_for(context);
	render_declaration_review(context, state);
    request_catalog(context, state);
    if (state->apply_pending) {
        const auto mutation = disasm_view::mutation_state(context);
        if (!context.workspace || context.workspace->generation() != state->apply_generation) {
            state->apply_pending = false;
            state->apply_error = true;
            state->apply_status = "The analysis generation changed before the type application committed.";
        } else if (mutation.overlay_revision > state->apply_expected_overlay_revision) {
            state->apply_pending = false;
            state->apply_error = false;
            state->apply_status = "Committed to the reversible type overlay and published to analysis views.";
        } else if (mutation.pending == 0 && !mutation.error.empty()) {
            state->apply_pending = false;
            state->apply_error = true;
            state->apply_status = mutation.error;
        }
    }
    std::shared_ptr<const catalog_t> catalog_handle;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        catalog_handle = state->catalog;
    }
    static const catalog_t empty_catalog;
    const auto& catalog = catalog_handle ? *catalog_handle : empty_catalog;
    const std::string id = context.workspace->identity().binary_id().to_hex();
    ImGui::PushID(id.c_str());
    ImGui::BeginChild("##workspace_types", ImVec2(width, height), false);
    const auto& theme = aida::ui::resolved();
    ImGui::PushStyleColor(ImGuiCol_Text, aida::ui::with_alpha(theme.text_primary, alpha));
    const char* tabs[] = {"Structures", "Unions", "Enums", "Typedefs", "Functions",
        "Inferred", "Dissector"};
    sub_tab_t active = sub_tab_t::structs;
    int selected = -1;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        active = state->active;
        selected = state->selected;
    }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    aida::preview::re_hubs::rendered(aida::preview::re_hubs::domain_t::types,
        static_cast<int>(active), sub_tab_label(active));
#endif
    for (int index = 0; index < static_cast<int>(sub_tab_t::COUNT); ++index) {
        if (index != 0)
            ImGui::SameLine();
        if (ImGui::Selectable(tabs[index], static_cast<int>(active) == index, 0,
                ImVec2(0.0f, ImGui::GetFrameHeight()))) {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->active = static_cast<sub_tab_t>(index);
            state->selected = -1;
            default_active_tab().store(index, std::memory_order_release);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            aida::preview::re_hubs::select(aida::preview::re_hubs::domain_t::types,
                index, tabs[index]);
#endif
            active = state->active;
            selected = -1;
        }
    }
    ImGui::SameLine();
    const bool can_load_pdb = context.workspace->target_kind() ==
        aida::analysis::target_kind_t::static_file &&
        !context.workspace->closing() && !context.workspace->closed();
    ImGui::BeginDisabled(!can_load_pdb);
    if (ImGui::Button("Load PDB...")) {
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        state->pdb_dialog_open = true;
        ImGui::OpenPopup("Select PDB file##types_hub_view");
#else
        std::array<char, 32768> path{};
        if (win32_dialog::show_open_file_dialog(g_hwnd, "Select PDB file",
                "Program Database (*.pdb)\0*.pdb\0All files (*.*)\0*.*\0\0",
                path.data(), path.size(), "types_hub_view"))
            request_pdb_load(context, state, path.data());
#endif
    }
    ImGui::EndDisabled();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (state->pdb_dialog_open)
        ImGui::OpenPopup("Select PDB file##types_hub_view");
    if (aida::ui::design::begin_dialog_exact("Select PDB file##types_hub_view",
            ImVec2(580.0f, 300.0f), ImVec2(360.0f, 240.0f))) {
        const float footer_height = aida::ui::design::dialog_footer_reserve_height(
            "Open", "Cancel");
        aida::ui::design::begin_dialog_body("types_hub_pdb_body", footer_height);
        ImGui::TextUnformatted("Program Database (*.pdb)");
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        const bool submitted = ImGui::InputText("##pdb_path",
            state->pdb_dialog_path.data(), state->pdb_dialog_path.size(),
            ImGuiInputTextFlags_EnterReturnsTrue);
        aida::ui::design::end_dialog_body();
        const auto footer = aida::ui::design::dialog_footer("types_hub_pdb_footer",
            "Open", state->pdb_dialog_path[0] != '\0', false, "Cancel");
        if (footer.confirmed ||
            (submitted && state->pdb_dialog_path[0] != '\0')) {
            request_pdb_load(context, state, state->pdb_dialog_path.data());
            state->pdb_dialog_open = false;
            ImGui::CloseCurrentPopup();
        }
        if (footer.cancelled) {
            state->pdb_dialog_open = false;
            aida::preview::re_hubs::action(aida::preview::re_hubs::domain_t::types,
                static_cast<int>(active), "cancel_pdb_dialog");
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    const auto pdb_prompt = analysis_session::pdb_prompt_snapshot(context.workspace);
    if (pdb_prompt && pdb_prompt.value().loading) {
        const float progress = pdb_prompt.value().bytes_total != 0
            ? static_cast<float>((std::min)(1.0,
                static_cast<double>(pdb_prompt.value().bytes_received) /
                static_cast<double>(pdb_prompt.value().bytes_total)))
            : static_cast<float>((std::clamp)(pdb_prompt.value().progress_percent,
                0, 100)) / 100.0f;
        ImGui::ProgressBar(progress, ImVec2(220.0f, 0.0f), "Loading PDB");
        ImGui::SameLine();
        if (ImGui::Button("Cancel PDB")) {
            const auto cancelled = analysis_session::cancel_pdb(context.workspace);
            if (!cancelled) {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->pdb_error = cancelled.error().stable_code() + ": " +
                    cancelled.error().message;
            }
        }
    }
    std::string pdb_error;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        pdb_error = state->pdb_error;
    }
    if (!pdb_error.empty())
        ImGui::TextWrapped("%s", pdb_error.c_str());
    else if (pdb_prompt && pdb_prompt.value().failed) {
        ImGui::PushStyleColor(ImGuiCol_Text,
            ImGui::ColorConvertU32ToFloat4(theme.error));
        ImGui::TextWrapped("PDB load failed: %s", pdb_prompt.value().status.c_str());
        ImGui::PopStyleColor();
    }
    else if (pdb_prompt && pdb_prompt.value().loading)
        ImGui::TextWrapped("%s", pdb_prompt.value().status.c_str());
#endif
    if (context.publication) {
        ImGui::TextDisabled("Static analysis workspace  |  generation %llu  |  revision %llu",
            static_cast<unsigned long long>(context.publication->generation),
            static_cast<unsigned long long>(context.publication->analysis_revision));
    } else {
        ImGui::TextDisabled("Static analysis workspace  |  catalog publication pending");
    }
    if (active == sub_tab_t::inferred || active == sub_tab_t::dissector) {
        ImGui::Separator();
        const float content_y = ImGui::GetCursorPosY();
        const float content_height = (std::max)(80.0f, height - content_y);
        if (active == sub_tab_t::inferred)
            struct_recon_view::render(0.0f, content_y, width, content_height,
                alpha, 0.0f, 0.0f, 0.0f);
        else
            struct_dissector_view::render(0.0f, content_y, width, content_height,
                alpha, 0.0f, 0.0f, 0.0f);
        ImGui::PopStyleColor();
        ImGui::EndChild();
        ImGui::PopID();
        return;
    }
    ImGui::SetNextItemWidth(360.0f);
    std::array<char, 256> search_input{};
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        search_input = state->search;
    }
    ImGui::InputTextWithHint("##type_search", "Filter names and canonical types",
        search_input.data(), search_input.size());
    const std::string filter(search_input.data());
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->search = search_input;
    }
    const float list_width = (std::max)(280.0f, width * 0.38f);
    const float content_height = (std::max)(80.0f, height - 108.0f);
    request_visible_indices(context, state, catalog_handle, active, filter);
    std::shared_ptr<const std::vector<std::size_t>> visible_handle;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->visible_catalog == catalog_handle.get() && state->visible_tab == active &&
            state->visible_filter == filter)
            visible_handle = state->visible_indices;
    }
    static const std::vector<std::size_t> empty_visible;
    const auto& visible = visible_handle ? *visible_handle : empty_visible;
    int context_request_row = -1;
    bool pointer_context_requested = false;
    ImGui::BeginChild("##type_list", ImVec2(list_width, content_height), true);
    if (state->visible_loading.load(std::memory_order_acquire))
        ImGui::TextUnformatted("Filtering type catalog...");
    if (active == sub_tab_t::structs || active == sub_tab_t::unions) {
        const auto& entries = active == sub_tab_t::structs ? catalog.structs : catalog.unions;
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>((std::min)(visible.size(),
            static_cast<std::size_t>((std::numeric_limits<int>::max)()))));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& entry = entries[visible[static_cast<std::size_t>(row)]];
                if (ImGui::Selectable(entry.definition.name.c_str(), selected == row)) {
                    {
                        std::lock_guard<std::mutex> lock(state->mutex);
                        state->selected = row;
                        state->list_focused = true;
                    }
                    selected = row;
                    publish_type_selection(context, active, entry.module,
                        entry.definition.name);
                }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				const std::string catalog_semantic_id = studio_type_entity_id(
					"catalog", context,
					std::to_string(static_cast<int>(active)) + ":" + entry.module + ":" +
					entry.definition.name);
				aida::preview::semantics::register_last_item(
					catalog_semantic_id, "type-row");
#endif
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    selected = row;
                    context_request_row = row;
                    pointer_context_requested = true;
                }
            }
        }
    } else if (active == sub_tab_t::enums) {
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>((std::min)(visible.size(),
            static_cast<std::size_t>((std::numeric_limits<int>::max)()))));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& entry = catalog.enums[visible[static_cast<std::size_t>(row)]];
                if (ImGui::Selectable(entry.definition.name.c_str(), selected == row)) {
                    {
                        std::lock_guard<std::mutex> lock(state->mutex);
                        state->selected = row;
                        state->list_focused = true;
                    }
                    selected = row;
                    publish_type_selection(context, active, entry.module,
                        entry.definition.name);
                }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				const std::string catalog_semantic_id = studio_type_entity_id(
					"catalog", context,
					std::to_string(static_cast<int>(active)) + ":" + entry.module + ":" +
					entry.definition.name);
				aida::preview::semantics::register_last_item(
					catalog_semantic_id, "type-row");
#endif
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    selected = row;
                    context_request_row = row;
                    pointer_context_requested = true;
                }
            }
        }
    } else if (active == sub_tab_t::functions) {
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>((std::min)(visible.size(),
            static_cast<std::size_t>((std::numeric_limits<int>::max)()))));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& entry = catalog.functions[visible[static_cast<std::size_t>(row)]];
                if (ImGui::Selectable(entry.name.c_str(), selected == row,
                        ImGuiSelectableFlags_AllowDoubleClick)) {
                    {
                        std::lock_guard<std::mutex> lock(state->mutex);
                        state->selected = row;
                        state->list_focused = true;
                    }
                    selected = row;
                    publish_type_selection(context, active, "analysis",
                        entry.name, entry.address);
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                        const auto address = disasm_view::runtime_address(context, entry.address).value_or(
                            entry.address.value);
                        disasm_view::goto_address(address, context);
                        aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
                    }
                }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				const std::string catalog_semantic_id = studio_type_entity_id(
					"catalog", context,
					std::to_string(static_cast<int>(active)) + ":" +
					std::to_string(entry.address.value) + ":" + entry.name);
				aida::preview::semantics::register_last_item(
					catalog_semantic_id, "type-row");
#endif
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    selected = row;
                    context_request_row = row;
                    pointer_context_requested = true;
                }
            }
        }
    } else {
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>((std::min)(visible.size(),
            static_cast<std::size_t>((std::numeric_limits<int>::max)()))));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& entry = catalog.typedefs[visible[static_cast<std::size_t>(row)]];
                const std::string label = entry.name + "  " +
                    (entry.explicitly_unknown ? "<unknown>" : entry.canonical_type);
                if (ImGui::Selectable(label.c_str(), selected == row)) {
                    {
                        std::lock_guard<std::mutex> lock(state->mutex);
                        state->selected = row;
                        state->list_focused = true;
                    }
                    selected = row;
                    publish_type_selection(context, active, "analysis",
                        entry.name, entry.address.value != 0
                            ? std::optional<aida::analysis::address_t>(entry.address)
                            : std::nullopt);
                }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
				const std::string catalog_semantic_id = studio_type_entity_id(
					"catalog", context,
					std::to_string(static_cast<int>(active)) + ":" + entry.name + ":" +
					std::to_string(entry.address.value));
				aida::preview::semantics::register_last_item(
					catalog_semantic_id, "type-row");
#endif
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    selected = row;
                    context_request_row = row;
                    pointer_context_requested = true;
                }
            }
        }
    }
    ImGui::EndChild();
    {
        bool list_focused = false;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            list_focused = state->list_focused;
        }
        if (context_request_row < 0 && list_focused && selected >= 0 && context_key_pressed())
            context_request_row = selected;
        if (context_request_row >= 0) {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->selected = context_request_row;
            state->context_row = context_request_row;
            state->context_tab = active;
            state->context_generation = context.publication ? context.publication->generation : 0;
            state->context_analysis_revision = context.publication ? context.publication->analysis_revision : 0;
            state->list_focused = true;
            selected = context_request_row;
        }
    }
    render_catalog_context_menu(context, state, catalog_handle, visible_handle,
        context_request_row >= 0, pointer_context_requested
            ? aida::ui::context_menu_open_origin_t::pointer
            : ImGui::IsKeyPressed(ImGuiKey_Menu, false)
            ? aida::ui::context_menu_open_origin_t::menu_key
            : aida::ui::context_menu_open_origin_t::shift_f10);
    ImGui::SameLine();
    ImGui::BeginChild("##type_detail", ImVec2(0.0f, content_height), true);
    if (selected >= 0 && static_cast<std::size_t>(selected) < visible.size()) {
        const std::size_t index = visible[static_cast<std::size_t>(selected)];
        if (active == sub_tab_t::structs)
            render_struct_detail(context, catalog_handle, state, catalog.structs[index], content_height - 80.0f);
        else if (active == sub_tab_t::unions)
            render_struct_detail(context, catalog_handle, state, catalog.unions[index], content_height - 80.0f);
        else if (active == sub_tab_t::enums)
			render_enum_detail(catalog.enums[index], content_height - 80.0f,
				state, context.publication ? context.publication->generation : 0,
				context.publication ? context.publication->analysis_revision : 0);
        else if (active == sub_tab_t::functions) {
            const auto& entry = catalog.functions[index];
            const auto address = disasm_view::runtime_address(context, entry.address).value_or(
                entry.address.value);
            ImGui::TextUnformatted(entry.name.c_str());
            ImGui::TextDisabled("0x%016llX  size 0x%llX  %s",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(entry.size), entry.provenance.c_str());
            if (ImGui::Button("Copy name"))
                ImGui::SetClipboardText(entry.name.c_str());
            ImGui::SameLine();
            if (ImGui::Button("Copy signature"))
                ImGui::SetClipboardText(entry.signature.c_str());
            ImGui::SameLine();
            if (ImGui::Button("Copy RVA")) {
                char value[32]{};
                std::snprintf(value, sizeof(value), "0x%llX",
                    static_cast<unsigned long long>(entry.address.value));
                ImGui::SetClipboardText(value);
            }
            if (ImGui::Button("Jump")) {
                disasm_view::goto_address(address, context);
                aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
            }
            ImGui::SameLine();
            if (ImGui::Button("Decompile")) {
                pseudocode_view::request_decompile(context, address, false);
                aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.pseudocode"));
            }
        } else {
            const auto& entry = catalog.typedefs[index];
            ImGui::TextUnformatted(entry.name.c_str());
            ImGui::TextWrapped("%s", entry.explicitly_unknown ?
                "Unknown: evidence is insufficient for a sound type." : entry.canonical_type.c_str());
            ImGui::TextDisabled("confidence %u", static_cast<unsigned>(entry.confidence));
        }
    } else {
        ImGui::TextUnformatted("Select an item to inspect its target-bound evidence.");
    }
    ImGui::Separator();
    ImGui::TextUnformatted("Apply type through reversible overlay");
    ImGui::SetNextItemWidth(180.0f);
    ImGui::InputTextWithHint("##apply_type_address", "Address",
        state->apply_address.data(), state->apply_address.size());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(320.0f);
    ImGui::InputTextWithHint("##apply_type_text", "Canonical type",
        state->apply_type.data(), state->apply_type.size());
    ImGui::SameLine();
    if (ImGui::Button("Apply")) {
        state->apply_error = true;
        const std::string canonical_type(state->apply_type.data());
        if (!context.workspace || context.workspace->closing() || context.workspace->closed()) {
            state->apply_status = "Workspace changed; reopen the target before applying a type.";
        } else if (canonical_type.empty()) {
            state->apply_status = "Enter a canonical type before applying.";
        } else if (const auto address = parse_address(state->apply_address.data())) {
            if (const auto typed = disasm_view::typed_address(context, *address)) {
                if (disasm_view::queue_type_application(context, *typed, canonical_type)) {
                    state->apply_error = false;
                    state->apply_pending = true;
                    state->apply_generation = context.workspace->generation();
                    state->apply_expected_overlay_revision = context.workspace->overlay_revision();
                    state->apply_status = "Queued; waiting for the overlay revision to commit.";
                } else {
                    state->apply_status = "The overlay rejected the type application; no change was claimed.";
                }
            } else {
                state->apply_status = "Address is outside the current workspace mapping.";
            }
        } else {
            state->apply_status = "Address is not a valid hexadecimal or decimal value.";
        }
    }
    if (!state->apply_status.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text,
            ImGui::ColorConvertU32ToFloat4(state->apply_error ? theme.error : theme.success));
        ImGui::TextWrapped("%s", state->apply_status.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::EndChild();
    ImGui::PopID();
}

inline void render(float pos_x, float pos_y, float width, float height,
                   float alpha, float accent_r, float accent_g, float accent_b) {
    render(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b,
        disasm_view::capture_selected_workspace());
}

inline void render_subview(sub_tab_t tab, float pos_x, float pos_y,
                           float width, float height, float alpha,
                           float accent_r, float accent_g, float accent_b,
                           const disasm_view::workspace_context_t& context) {
    auto state = state_for(context);
    if (state) {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->active != tab) {
            state->active = tab;
            state->selected = -1;
        }
    }
    default_active_tab().store(static_cast<int>(tab), std::memory_order_release);
    render(pos_x, pos_y, width, height, alpha, accent_r, accent_g, accent_b, context);
}

#if defined(AIDA_TYPES_HUB_VIEW_IMPLEMENTATION)
void render_subview(sub_tab_t tab, float pos_x, float pos_y,
                           float width, float height, float alpha,
                           float accent_r, float accent_g, float accent_b) {
    render_subview(tab, pos_x, pos_y, width, height, alpha,
        accent_r, accent_g, accent_b, disasm_view::capture_selected_workspace());
}
#endif

}
