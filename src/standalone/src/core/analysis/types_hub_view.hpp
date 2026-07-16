#pragma once

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
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../infra/taskflow_runtime.hpp"
#endif
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../session/analysis_session.hpp"
#endif
#include "../ui/theme.hpp"
#include "../ui/application_view_registry.hpp"
#include "../workbench/workbench_shell_integration.hpp"
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include "../../helpers/win32_dialog.hpp"
#endif
#include "imgui/imgui.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
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

enum class sub_tab_t : int {
    structs = 0,
    unions = 1,
    enums = 2,
    typedefs = 3,
    functions = 4,
    inferred = 5,
    dissector = 6,
    COUNT = 7
};

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
    const struct catalog_t* reference_catalog = nullptr;
    std::string reference_type;
    std::shared_ptr<const std::vector<type_reference_t>> references;
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

inline void set_sub_tab(sub_tab_t tab) {
    set_sub_tab(disasm_view::capture_selected_workspace(), tab);
}

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
    std::string output = definition.is_union ? "union " : "struct ";
    output += definition.name + "\n{\n";
    std::uint64_t last_end = 0;
    int padding_index = 0;
    for (const auto& member : definition.members) {
        if (member.offset > last_end) {
            char padding[96]{};
            std::snprintf(padding, sizeof(padding), "  _BYTE pad_%d[%llu];\n",
                padding_index++, static_cast<unsigned long long>(member.offset - last_end));
            output += padding;
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
        last_end = member.size > (std::numeric_limits<std::uint64_t>::max)() - member.offset
            ? (std::numeric_limits<std::uint64_t>::max)() : member.offset + member.size;
    }
    if (last_end < definition.size) {
        char padding[96]{};
        std::snprintf(padding, sizeof(padding), "  _BYTE pad_%d[%llu];\n", padding_index,
            static_cast<unsigned long long>(definition.size - last_end));
        output += padding;
    }
    output += "};\n";
    return output;
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
        }
    }
    ImGui::EndChild();
}

inline void send_to_dissector(const pdb_parser::struct_def_t& definition) {
    const int index = struct_dissector::create_struct(definition.name);
    for (const auto& member : definition.members) {
        if (member.offset > (std::numeric_limits<std::uint32_t>::max)() ||
            member.size > (std::numeric_limits<std::uint32_t>::max)())
            continue;
        struct_dissector::field_def_t field;
        field.name = member.name.empty() ? "field_" + std::to_string(member.offset) : member.name;
        field.offset = static_cast<std::uint32_t>(member.offset);
        field.size = static_cast<std::uint32_t>(member.size == 0 ? 1 : member.size);
        if (member.is_pointer)
            field.type = struct_dissector::field_type_t::pointer;
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
        struct_dissector::add_field(index, field);
    }
}

inline void render_struct_detail(const disasm_view::workspace_context_t& context,
                                 const catalog_t& catalog,
                                 const std::shared_ptr<state_t>& state,
                                 const struct_entry_t& entry, float height) {
    const auto& definition = entry.definition;
    ImGui::Text("%s %s", definition.is_union ? "union" : "struct", definition.name.c_str());
    ImGui::TextDisabled("%s  size 0x%llX  %zu members", entry.module.c_str(),
        static_cast<unsigned long long>(definition.size), definition.members.size());
    if (ImGui::Button("Copy C")) {
        const std::string declaration = pdb_parser::struct_to_cpp(definition);
        ImGui::SetClipboardText(declaration.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Copy IDA")) {
        const std::string declaration = struct_to_ida_syntax(definition);
        ImGui::SetClipboardText(declaration.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("To Dissector"))
        send_to_dissector(definition);
    ImGui::SameLine();
    if (ImGui::Button("Open Dissector"))
        set_sub_tab(context, sub_tab_t::dissector);
    ImGui::SameLine();
    if (ImGui::Button("Declare in overlay"))
        disasm_view::queue_type_declaration(context, pdb_parser::struct_to_cpp(definition));
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
    if (!references) {
        auto computed = std::make_shared<const std::vector<type_reference_t>>(
            references_for_type(catalog, definition.name));
        std::lock_guard<std::mutex> lock(state->mutex);
        state->reference_catalog = &catalog;
        state->reference_type = definition.name;
        state->references = computed;
        references = std::move(computed);
    }
    render_type_references(context, references, definition.name,
        height - members_height - 48.0f);
}

inline void render_enum_detail(const enum_entry_t& entry, float height) {
    const auto& definition = entry.definition;
    ImGui::Text("enum %s", definition.name.c_str());
    ImGui::TextDisabled("%s  %zu values", entry.module.c_str(), definition.members.size());
    const bool copy_c = ImGui::Button("Copy C");
    ImGui::SameLine();
    const bool copy_ida = ImGui::Button("Copy IDA");
    if (copy_c || copy_ida) {
        std::string declaration = "enum " + definition.name + " {\n";
        for (const auto& member : definition.members) {
            char line[256]{};
            std::snprintf(line, sizeof(line), "    %s = 0x%llX,\n", member.name.c_str(),
                static_cast<unsigned long long>(member.value));
            declaration += line;
        }
        declaration += "};\n";
        ImGui::SetClipboardText(declaration.c_str());
    }
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

inline void unavailable_context_item(const char* label, const char* reason) {
    ImGui::MenuItem(label, nullptr, false, false);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("%s", reason);
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
                                        const catalog_t& catalog,
                                        const std::vector<std::size_t>& visible) {
    if (!ImGui::BeginPopup("##types_catalog_context"))
        return;
    int row = -1;
    sub_tab_t tab = sub_tab_t::structs;
    bool current = false;
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        row = state->context_row;
        tab = state->context_tab;
        current = catalog_context_is_current(context, *state);
    }
    if (!current || row < 0 || static_cast<std::size_t>(row) >= visible.size()) {
        ImGui::TextDisabled("Selection is stale");
        ImGui::Separator();
        unavailable_context_item("Copy name", "The analysis publication changed; select the item again.");
        unavailable_context_item("Open", "The analysis publication changed; select the item again.");
        ImGui::EndPopup();
        return;
    }
    const std::size_t index = visible[static_cast<std::size_t>(row)];
    if (tab == sub_tab_t::structs || tab == sub_tab_t::unions) {
        const auto& entry = tab == sub_tab_t::structs ? catalog.structs[index] : catalog.unions[index];
        ImGui::TextDisabled("PDB %s  |  %s", tab == sub_tab_t::structs ? "structure" : "union",
            entry.module.c_str());
        ImGui::Separator();
        if (ImGui::MenuItem("Copy name", "Ctrl+C"))
            ImGui::SetClipboardText(entry.definition.name.c_str());
        if (ImGui::MenuItem("Copy C declaration")) {
            const std::string text = pdb_parser::struct_to_cpp(entry.definition);
            ImGui::SetClipboardText(text.c_str());
        }
        if (ImGui::MenuItem("Copy IDA-style declaration")) {
            const std::string text = struct_to_ida_syntax(entry.definition);
            ImGui::SetClipboardText(text.c_str());
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Open in Structure Editor")) {
            send_to_dissector(entry.definition);
            set_sub_tab(context, sub_tab_t::dissector);
        }
        if (ImGui::MenuItem("Declare in reversible overlay"))
            disasm_view::queue_type_declaration(context, pdb_parser::struct_to_cpp(entry.definition));
        ImGui::Separator();
        unavailable_context_item("Rename type...", "PDB catalog definitions are immutable; declare an edited overlay type instead.");
        unavailable_context_item("Delete type", "PDB catalog definitions cannot be deleted from the analysis workspace.");
    } else if (tab == sub_tab_t::enums) {
        const auto& entry = catalog.enums[index];
        ImGui::TextDisabled("PDB enum  |  %s", entry.module.c_str());
        ImGui::Separator();
        if (ImGui::MenuItem("Copy name", "Ctrl+C"))
            ImGui::SetClipboardText(entry.definition.name.c_str());
        if (ImGui::MenuItem("Copy C declaration")) {
            std::string declaration = "enum " + entry.definition.name + " {\n";
            for (const auto& member : entry.definition.members) {
                declaration += "    " + member.name + " = " + std::to_string(member.value) + ",\n";
            }
            declaration += "};\n";
            ImGui::SetClipboardText(declaration.c_str());
        }
        unavailable_context_item("Edit enum...", "The catalog has no mutable enum backend; create an overlay declaration instead.");
    } else if (tab == sub_tab_t::functions) {
        const auto& entry = catalog.functions[index];
        const auto address = disasm_view::runtime_address(context, entry.address).value_or(entry.address.value);
        ImGui::TextDisabled("Static function  |  %s", entry.provenance.c_str());
        ImGui::Separator();
        if (ImGui::MenuItem("Jump to disassembly", "Enter")) {
            disasm_view::goto_address(address, context);
            aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
        }
        if (ImGui::MenuItem("Open pseudocode")) {
            pseudocode_view::request_decompile(context, address, false);
            aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.pseudocode"));
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Copy name", "Ctrl+C"))
            ImGui::SetClipboardText(entry.name.c_str());
        if (ImGui::MenuItem("Copy signature", nullptr, false, !entry.signature.empty()))
            ImGui::SetClipboardText(entry.signature.c_str());
        if (ImGui::MenuItem("Copy address")) {
            char text[32]{};
            std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(address));
            ImGui::SetClipboardText(text);
        }
        unavailable_context_item("Retype function...", "Use the reversible type overlay at a concrete function address.");
    } else {
        const auto& entry = catalog.typedefs[index];
        ImGui::TextDisabled("%s type evidence  |  confidence %u",
            tab == sub_tab_t::typedefs ? "Catalog" : "Inferred",
            static_cast<unsigned>(entry.confidence));
        ImGui::Separator();
        if (ImGui::MenuItem("Copy name", "Ctrl+C"))
            ImGui::SetClipboardText(entry.name.c_str());
        if (ImGui::MenuItem("Copy canonical type", nullptr, false,
                !entry.explicitly_unknown && !entry.canonical_type.empty()))
            ImGui::SetClipboardText(entry.canonical_type.c_str());
        if (entry.address.value != 0 && ImGui::MenuItem("Jump to evidence address", "Enter")) {
            const auto address = disasm_view::runtime_address(context, entry.address).value_or(entry.address.value);
            disasm_view::goto_address(address, context);
            aida::ui::application_views::open_or_focus(aida::ui::stable_view_id_t("document.disassembly"));
        }
        unavailable_context_item("Promote globally", "No global type-propagation backend is exposed; apply a reversible overlay at a concrete address.");
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
    if (ImGui::BeginPopupModal("Select PDB file##types_hub_view", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Program Database (*.pdb)");
        ImGui::SetNextItemWidth(460.0f);
        ImGui::InputText("##pdb_path", state->pdb_dialog_path.data(),
            state->pdb_dialog_path.size());
        if (ImGui::Button("Open", ImVec2(96.0f, 0.0f))) {
            request_pdb_load(context, state, state->pdb_dialog_path.data());
            state->pdb_dialog_open = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(96.0f, 0.0f))) {
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
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    selected = row;
                    context_request_row = row;
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
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    selected = row;
                    context_request_row = row;
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
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    selected = row;
                    context_request_row = row;
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
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                    selected = row;
                    context_request_row = row;
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
            ImGui::OpenPopup("##types_catalog_context");
        }
    }
    render_catalog_context_menu(context, state, catalog, visible);
    ImGui::SameLine();
    ImGui::BeginChild("##type_detail", ImVec2(0.0f, content_height), true);
    if (selected >= 0 && static_cast<std::size_t>(selected) < visible.size()) {
        const std::size_t index = visible[static_cast<std::size_t>(selected)];
        if (active == sub_tab_t::structs)
            render_struct_detail(context, catalog, state, catalog.structs[index], content_height - 80.0f);
        else if (active == sub_tab_t::unions)
            render_struct_detail(context, catalog, state, catalog.unions[index], content_height - 80.0f);
        else if (active == sub_tab_t::enums)
            render_enum_detail(catalog.enums[index], content_height - 80.0f);
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

inline void render_subview(sub_tab_t tab, float pos_x, float pos_y,
                           float width, float height, float alpha,
                           float accent_r, float accent_g, float accent_b) {
    render_subview(tab, pos_x, pos_y, width, height, alpha,
        accent_r, accent_g, accent_b, disasm_view::capture_selected_workspace());
}

}
