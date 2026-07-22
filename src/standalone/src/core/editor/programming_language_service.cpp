#include "programming_language_service.hpp"

#include "code_editor.hpp"
#include "../infra/executor.hpp"
#include "../ui/application_view_registry.hpp"
#include "../ui/task_center.hpp"
#include "../ui/ui_thread_dispatcher.hpp"
#include "../settings/standalone_settings.hpp"
#include "../../helpers/globals.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <utility>

namespace aida::editor::language_service {
namespace {

std::filesystem::path path_from_utf8(std::string_view value)
{
#if defined(__cpp_char8_t)
    const auto* begin = reinterpret_cast<const char8_t*>(value.data());
    return std::filesystem::path(std::u8string(begin, begin + value.size()));
#else
    return std::filesystem::u8path(value.begin(), value.end());
#endif
}

std::string path_to_utf8(const std::filesystem::path& value)
{
    const auto encoded = value.generic_u8string();
#if defined(__cpp_char8_t)
    return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
#else
    return encoded;
#endif
}

constexpr std::size_t k_capability_count = 15;
constexpr std::size_t k_maximum_query_results = 4096;
constexpr std::size_t k_maximum_document_snapshot_bytes = 1024U * 1024U;
constexpr std::size_t k_maximum_result_text_bytes = 64U * 1024U;

std::size_t slot_index(capability_kind_t kind) noexcept
{
    return static_cast<std::size_t>(kind);
}

const char* capability_action_id(capability_kind_t kind) noexcept
{
    switch (kind) {
    case capability_kind_t::completion: return "programming.language.completion";
    case capability_kind_t::hover: return "programming.language.hover";
    case capability_kind_t::signature_help: return "programming.language.signature_help";
    case capability_kind_t::document_symbols: return "programming.language.document_symbols";
    case capability_kind_t::workspace_symbols: return "programming.language.workspace_symbols";
    case capability_kind_t::diagnostics: return "programming.language.diagnostics";
    case capability_kind_t::definition: return "programming.language.definition";
    case capability_kind_t::declaration: return "programming.language.declaration";
    case capability_kind_t::implementation: return "programming.language.implementation";
    case capability_kind_t::type_definition: return "programming.language.type_definition";
    case capability_kind_t::references: return "programming.language.references";
    case capability_kind_t::semantic_rename: return "programming.language.rename";
    case capability_kind_t::formatting: return "programming.language.format";
    case capability_kind_t::range_formatting: return "programming.language.format_selection";
    case capability_kind_t::code_actions: return "programming.language.code_actions";
    }
    return "programming.language.query";
}

std::string normalized_path(std::string value)
{
    std::replace(value.begin(), value.end(), '\\', '/');
    while (value.size() > 1 && value.back() == '/')
        value.pop_back();
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char byte) {
        return static_cast<char>(std::tolower(byte));
    });
    return value;
}

std::string display_path(const std::string& root, const std::string& relative)
{
    if (relative.empty())
        return {};
    const std::filesystem::path path(relative);
    if (path.is_absolute() || root.empty())
        return path.lexically_normal().string();
    return (std::filesystem::path(root) / path).lexically_normal().string();
}

std::string extension_for(const std::string& path)
{
    std::string extension = std::filesystem::path(path).extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(),
        [](unsigned char byte) { return static_cast<char>(std::tolower(byte)); });
    return extension;
}

bool c_family_document(const document_context_t& document)
{
    const std::string extension = extension_for(document.file_path);
    return extension == ".c" || extension == ".cpp" || extension == ".cc" ||
        extension == ".cxx" || extension == ".h" || extension == ".hpp" ||
        extension == ".hxx";
}

bool indexed_text_document(const document_context_t& document)
{
    return code_index::is_indexable_extension(extension_for(document.file_path));
}

bool valid_provider_identity(std::string_view identity)
{
    if (identity.empty() || identity.size() > 128)
        return false;
    return std::all_of(identity.begin(), identity.end(), [](unsigned char value) {
        return std::isalnum(value) || value == '.' || value == '_' || value == '-';
    });
}

bool valid_query_context(const query_t& query, std::string& reason)
{
    if (query.document.bounded_text_snapshot &&
        query.document.bounded_text_snapshot->size() >
            k_maximum_document_snapshot_bytes) {
        reason = "The immutable document snapshot exceeds the 1 MiB provider handoff bound";
        return false;
    }
    if (query.text.size() > k_maximum_result_text_bytes ||
        query.replacement_text.size() > k_maximum_result_text_bytes ||
        query.directory.size() > 4096) {
        reason = "The language query exceeds its bounded text or path contract";
        return false;
    }
    return true;
}

void bound_text(std::string& value, bool& truncated)
{
    if (value.size() <= k_maximum_result_text_bytes)
        return;
    value.resize(k_maximum_result_text_bytes);
    truncated = true;
}

template <typename Value>
void bound_vector(std::vector<Value>& values, std::size_t maximum, bool& truncated)
{
    if (values.size() <= maximum)
        return;
    values.resize(maximum);
    truncated = true;
}

void normalize_provider_result(const query_t& query, const provider_t& provider,
    query_result_t& result)
{
    const std::size_t maximum = (std::min)(k_maximum_query_results,
        (std::max)(std::size_t{1}, query.maximum_results));
    result.kind = query.kind;
    result.provider_id = provider.identity();
    result.provider_name = provider.display_name();
    result.provider_generation = provider.generation();
    result.document_id = query.document.document_id;
    result.document_revision = query.document.revision;
    result.document_path = query.document.file_path;
    result.query_text = query.text;
    bound_vector(result.locations, maximum, result.truncated);
    bound_vector(result.symbols, maximum, result.truncated);
    bound_vector(result.completions, maximum, result.truncated);
    bound_vector(result.information, maximum, result.truncated);
    bound_vector(result.diagnostics, maximum, result.truncated);
    bound_vector(result.proposed_edits, maximum, result.truncated);
    bound_vector(result.code_actions, maximum, result.truncated);
    bound_text(result.status, result.truncated);
    bound_text(result.root_path, result.truncated);
    bound_text(result.query_text, result.truncated);
    bound_text(result.document_path, result.truncated);
    for (auto& location : result.locations) {
        bound_text(location.file_path, result.truncated);
        bound_text(location.preview, result.truncated);
    }
    for (auto& symbol : result.symbols) {
        bound_text(symbol.name, result.truncated);
        bound_text(symbol.kind, result.truncated);
        bound_text(symbol.detail, result.truncated);
        bound_text(symbol.location.file_path, result.truncated);
        bound_text(symbol.location.preview, result.truncated);
    }
    for (auto& completion : result.completions) {
        bound_text(completion.label, result.truncated);
        bound_text(completion.insertion_text, result.truncated);
        bound_text(completion.detail, result.truncated);
        bound_text(completion.kind, result.truncated);
        bound_text(completion.sort_key, result.truncated);
    }
    for (auto& information : result.information) {
        bound_text(information.label, result.truncated);
        bound_text(information.content, result.truncated);
        bound_text(information.language, result.truncated);
    }
    for (auto& diagnostic : result.diagnostics) {
        bound_text(diagnostic.location.file_path, result.truncated);
        bound_text(diagnostic.location.preview, result.truncated);
        bound_text(diagnostic.severity, result.truncated);
        bound_text(diagnostic.message, result.truncated);
        bound_text(diagnostic.source, result.truncated);
    }
    for (auto& edit : result.proposed_edits) {
        bound_text(edit.file_path, result.truncated);
        bound_text(edit.expected_text, result.truncated);
        bound_text(edit.replacement_text, result.truncated);
    }
    for (auto& action : result.code_actions) {
        bound_text(action.id, result.truncated);
        bound_text(action.title, result.truncated);
        bound_text(action.detail, result.truncated);
        bound_text(action.kind, result.truncated);
        bound_text(action.disabled_reason, result.truncated);
        bound_vector(action.proposed_edits, maximum, result.truncated);
        for (auto& edit : action.proposed_edits) {
            bound_text(edit.file_path, result.truncated);
            bound_text(edit.expected_text, result.truncated);
            bound_text(edit.replacement_text, result.truncated);
        }
    }
    if (result.state == result_state_t::loading) {
        result.state = result_state_t::error;
        result.status = "The language provider returned a non-terminal loading result";
    }
    if (result.state == result_state_t::unavailable ||
        result.state == result_state_t::cancelled ||
        result.state == result_state_t::error) {
        result.locations.clear();
        result.symbols.clear();
        result.completions.clear();
        result.information.clear();
        result.diagnostics.clear();
        result.proposed_edits.clear();
        result.code_actions.clear();
    }
    const bool has_payload = !result.locations.empty() || !result.symbols.empty() ||
        !result.completions.empty() || !result.information.empty() ||
        !result.diagnostics.empty() || !result.proposed_edits.empty() ||
        !result.code_actions.empty();
    if (result.state == result_state_t::ready && !has_payload) {
        result.state = result_state_t::empty;
        if (result.status.empty())
            result.status = "The language provider returned no results";
    } else if (result.state == result_state_t::empty && has_payload) {
        result.state = result_state_t::ready;
    }
}

struct provider_publication_t {
    std::uint64_t generation = 0;
    std::vector<std::shared_ptr<const provider_t>> providers;
};

struct query_task_lifecycle_t {
    std::mutex mutex;
    std::condition_variable condition;
    unsigned admission = 0;
    bool cancellation_pending = false;
    std::string task_center_id;
    std::atomic<bool> terminal_published{false};
};

struct request_slot_t {
    std::mutex mutex;
    std::atomic<std::uint64_t> generation{0};
    std::atomic<std::uint64_t> task_id{0};
    std::shared_ptr<std::atomic<bool>> cancelled;
    std::shared_ptr<std::atomic<bool>> dispatch_failed;
    std::shared_ptr<const query_result_t> publication;
    std::shared_ptr<const query_result_t> terminal_failure;
    std::shared_ptr<query_task_lifecycle_t> task_lifecycle;
};

void publish_query_task_terminal(const std::shared_ptr<query_task_lifecycle_t>& lifecycle,
    result_state_t result_state, const std::string& summary) noexcept
{
    try {
        if (!lifecycle)
            return;
        std::string task_center_id;
        {
            std::lock_guard<std::mutex> lock(lifecycle->mutex);
            if (lifecycle->admission != 1U || lifecycle->task_center_id.empty()) {
                if (result_state == result_state_t::cancelled)
                    lifecycle->cancellation_pending = true;
                return;
            }
            task_center_id = lifecycle->task_center_id;
        }
        bool expected = false;
        if (!lifecycle->terminal_published.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel, std::memory_order_acquire))
            return;
        ui::task_center::task_state_t task_state = ui::task_center::task_state_t::failed;
        float progress = -1.0f;
        std::string stage = "Language query failed";
        switch (result_state) {
        case result_state_t::ready:
            task_state = ui::task_center::task_state_t::completed;
            progress = 1.0f;
            stage = "Results ready";
            break;
        case result_state_t::empty:
            task_state = ui::task_center::task_state_t::completed;
            progress = 1.0f;
            stage = "Query completed with no matches";
            break;
        case result_state_t::unavailable:
            task_state = ui::task_center::task_state_t::completed;
            progress = 1.0f;
            stage = "Provider reported the capability unavailable";
            break;
        case result_state_t::cancelled:
            task_state = ui::task_center::task_state_t::cancelled;
            stage = "Language query cancelled";
            break;
        case result_state_t::error:
            break;
        case result_state_t::loading:
            task_state = ui::task_center::task_state_t::interrupted;
            stage = "Language query ended without a terminal provider result";
            break;
        }
        static_cast<void>(ui::task_center::update_task(task_center_id,
            task_state, progress, std::move(stage), summary));
    } catch (...) {
    }
}

class query_task_terminal_guard_t {
public:
    explicit query_task_terminal_guard_t(std::shared_ptr<query_task_lifecycle_t> lifecycle)
        : lifecycle_(std::move(lifecycle)) {}

    ~query_task_terminal_guard_t()
    {
        publish_query_task_terminal(lifecycle_, state_, summary_);
    }

    void set(result_state_t state, std::string summary)
    {
        state_ = state;
        summary_ = std::move(summary);
    }

private:
    std::shared_ptr<query_task_lifecycle_t> lifecycle_;
    result_state_t state_ = result_state_t::error;
    std::string summary_ = "Language query execution failed before publishing a provider result";
};

struct service_state_t {
    service_state_t()
    {
        auto publication = std::make_shared<provider_publication_t>();
        publication->generation = 1;
        providers = std::move(publication);
    }

    std::mutex configuration_mutex;
    std::mutex provider_mutex;
    std::string workspace_root;
    std::shared_ptr<code_index::manager_t> manager;
    std::shared_ptr<const code_index::published_index_t> preview_index;
    std::shared_ptr<const code_index::published_index_t> retained_index;
    std::shared_ptr<const std::string> index_ownership_failure;
    std::shared_ptr<const provider_publication_t> providers;
    std::atomic<std::uint64_t> provider_generation{1};
    std::atomic<bool> provider_refresh_pending{false};
    std::atomic<std::uint64_t> next_request_id{1};
    std::atomic<std::uint64_t> workspace_epoch{1};
    std::array<request_slot_t, k_capability_count> requests;
    std::uint64_t outline_document_id = 0;
    std::uint64_t outline_index_generation = 0;
    std::uint64_t outline_provider_registry_generation = 0;
};

service_state_t& state()
{
    static service_state_t value;
    return value;
}

std::shared_ptr<const code_index::published_index_t> current_index()
{
    auto& store = state();
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    return std::atomic_load_explicit(&store.preview_index, std::memory_order_acquire);
#else
    if (std::atomic_load_explicit(&store.index_ownership_failure,
            std::memory_order_acquire))
        return std::atomic_load_explicit(&store.retained_index,
            std::memory_order_acquire);
    std::shared_ptr<code_index::manager_t> manager;
    {
        std::unique_lock<std::mutex> lock(store.configuration_mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return std::atomic_load_explicit(&store.retained_index,
                std::memory_order_acquire);
        manager = store.manager;
    }
    const auto current = manager ? manager->snapshot() : nullptr;
    if (current) {
        std::atomic_store_explicit(&store.retained_index, current,
            std::memory_order_release);
        return current;
    }
    return std::atomic_load_explicit(&store.retained_index,
        std::memory_order_acquire);
#endif
}

class workspace_text_index_provider_t final : public provider_t {
public:
    workspace_text_index_provider_t(std::uint64_t generation,
        std::function<std::shared_ptr<const code_index::published_index_t>()> snapshot)
        : generation_(generation), snapshot_(std::move(snapshot)) {}

    std::string identity() const override { return "workspace-text-index"; }
    std::string display_name() const override { return "Workspace Text Index"; }
    std::uint64_t generation() const noexcept override { return generation_; }

    bool accepts(const document_context_t& document) const override
    {
        return document.file_path.empty() || indexed_text_document(document);
    }

    capability_t capability(capability_kind_t kind,
        const document_context_t& document) const override
    {
        switch (kind) {
        case capability_kind_t::completion:
            return {false, "Workspace Text Index does not provide completion; AI ghost completion is a separate reviewed AI feature"};
        case capability_kind_t::hover:
            return {false, "Workspace Text Index does not provide semantic hover information"};
        case capability_kind_t::signature_help:
            return {false, "Workspace Text Index does not provide signature help"};
        case capability_kind_t::diagnostics:
            return {false, "Workspace Text Index does not generate compiler or language diagnostics"};
        case capability_kind_t::declaration:
            return {false, "Workspace Text Index cannot distinguish declarations from definitions; register a semantic language provider"};
        case capability_kind_t::implementation:
            return {false, "Workspace Text Index cannot prove implementation ownership; register a semantic language provider"};
        case capability_kind_t::type_definition:
            return {false, "Workspace Text Index does not resolve semantic type definitions; register a semantic language provider"};
        case capability_kind_t::semantic_rename:
            return {false, "Workspace Text Index cannot prove semantic rename safety; use explicit text edits or a registered semantic provider"};
        case capability_kind_t::formatting:
            return {false, "Workspace Text Index does not provide document formatting"};
        case capability_kind_t::range_formatting:
            return {false, "Workspace Text Index does not provide selection formatting"};
        case capability_kind_t::code_actions:
            return {false, "Workspace Text Index does not provide code actions"};
        default:
            break;
        }
        const auto publication = snapshot_();
        if (!publication || !publication->index)
            return {false, "Workspace Text Index has no published generation; rebuild the workspace index"};
        if ((kind == capability_kind_t::document_symbols ||
             kind == capability_kind_t::workspace_symbols ||
             kind == capability_kind_t::definition) &&
            kind != capability_kind_t::workspace_symbols &&
            !c_family_document(document))
            return {false, "Workspace Text Index extracts symbols only from bounded C and C++ source files"};
        if (kind == capability_kind_t::references && !document.file_path.empty() &&
            !indexed_text_document(document))
            return {false, "Lexical references are available only for indexed text file extensions"};
        return {true, {}};
    }

    query_result_t execute(const query_t& query,
        const std::atomic<bool>& cancelled) const override
    {
        query_result_t output;
        output.kind = query.kind;
        output.provider_id = identity();
        output.provider_name = display_name();
        output.provider_generation = generation_;
        output.document_id = query.document.document_id;
        output.document_revision = query.document.revision;
        output.query_text = query.text;
        const auto publication = snapshot_();
        if (!publication || !publication->index) {
            output.state = result_state_t::unavailable;
            output.status = "Workspace Text Index has no published generation";
            return output;
        }
        output.root_path = publication->root_path;
        output.index_generation = publication->generation;
        output.truncated = publication->truncated || publication->skipped_files != 0;
        const capability_t available = capability(query.kind, query.document);
        if (!available.available) {
            output.state = result_state_t::unavailable;
            output.status = available.reason;
            return output;
        }
        const std::size_t maximum = (std::min)(k_maximum_query_results,
            (std::max)(std::size_t{1}, query.maximum_results));
        if (query.kind == capability_kind_t::document_symbols ||
            query.kind == capability_kind_t::workspace_symbols ||
            query.kind == capability_kind_t::definition) {
            if (!publication->symbols) {
                output.state = result_state_t::empty;
                output.status = "This index generation contains no C or C++ symbols";
                return output;
            }
            const std::string active = normalized_path(query.document.file_path);
            const std::string normalized_root = normalized_path(publication->root_path);
            std::string relative_active = active;
            const bool active_in_root = active == normalized_root ||
                (active.size() > normalized_root.size() &&
                 active.compare(0, normalized_root.size(), normalized_root) == 0 &&
                 active[normalized_root.size()] == '/');
            if (!normalized_root.empty() && active_in_root) {
                relative_active = active.substr(normalized_root.size());
                while (!relative_active.empty() && relative_active.front() == '/')
                    relative_active.erase(relative_active.begin());
            }
            for (const auto& source : *publication->symbols) {
                if (cancelled.load(std::memory_order_acquire)) {
                    output.state = result_state_t::cancelled;
                    output.status = "Language query was cancelled";
                    return output;
                }
                if (query.kind == capability_kind_t::document_symbols &&
                    normalized_path(source.file_path) != relative_active)
                    continue;
                if (query.kind == capability_kind_t::definition &&
                    source.symbol_name != query.text)
                    continue;
                if (query.kind == capability_kind_t::workspace_symbols &&
                    !query.text.empty()) {
                    std::string name = source.symbol_name;
                    std::string needle = query.text;
                    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char byte) {
                        return static_cast<char>(std::tolower(byte));
                    });
                    std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char byte) {
                        return static_cast<char>(std::tolower(byte));
                    });
                    if (name.find(needle) == std::string::npos)
                        continue;
                }
                symbol_t symbol;
                symbol.name = source.symbol_name;
                symbol.kind = source.symbol_type;
                symbol.detail = source.content_snippet;
                symbol.location.root_path = publication->root_path;
                symbol.location.file_path = display_path(publication->root_path,
                    source.file_path);
                symbol.location.line = source.line_number;
                symbol.location.column = source.column_number;
                symbol.location.match_length = static_cast<int>(source.symbol_name.size());
                symbol.location.preview = source.content_snippet;
                output.symbols.push_back(std::move(symbol));
                if (output.symbols.size() >= maximum) {
                    output.truncated = true;
                    break;
                }
            }
        } else if (query.kind == capability_kind_t::references) {
            if (query.text.empty()) {
                output.state = result_state_t::unavailable;
                output.status = "Select or place the caret on an identifier before finding lexical references";
                return output;
            }
            std::string directory_prefix = query.directory;
            if (!directory_prefix.empty()) {
                std::filesystem::path directory_path(directory_prefix);
                if (directory_path.is_absolute()) {
                    const std::string root_key = normalized_path(publication->root_path);
                    const std::string directory_key = normalized_path(
                        directory_path.lexically_normal().string());
                    if (root_key.empty()) {
                        output.state = result_state_t::unavailable;
                        output.status = "The published workspace index has no root identity";
                        return output;
                    }
                    const bool exact_root = directory_key == root_key;
                    const bool child = directory_key.size() > root_key.size() &&
                        directory_key.compare(0, root_key.size(), root_key) == 0 &&
                        directory_key[root_key.size()] == '/';
                    if (!exact_root && !child) {
                        output.state = result_state_t::unavailable;
                        output.status = "The requested search directory is outside the indexed workspace root";
                        return output;
                    }
                    directory_prefix = exact_root ? std::string{} :
                        directory_key.substr(root_key.size() + 1);
                } else {
                    if (directory_path.has_root_name() || directory_path.has_root_directory()) {
                        output.state = result_state_t::unavailable;
                        output.status = "The requested relative search directory has an invalid root component";
                        return output;
                    }
                    directory_prefix = directory_path.lexically_normal().generic_string();
                    if (directory_prefix == ".")
                        directory_prefix.clear();
                    if (directory_prefix == ".." ||
                        directory_prefix.compare(0, 3, "../") == 0) {
                        output.state = result_state_t::unavailable;
                        output.status = "The requested search directory escapes the indexed workspace root";
                        return output;
                    }
                }
            }
            const std::size_t requested = maximum < k_maximum_query_results ? maximum + 1 : maximum;
            const auto matches = publication->index->lexical_search(query.text, requested,
                directory_prefix, &cancelled);
            for (std::size_t index = 0; index < matches.size() && index < maximum; ++index) {
                location_t location;
                location.root_path = publication->root_path;
                location.file_path = display_path(publication->root_path,
                    matches[index].file_path);
                location.line = matches[index].line_number;
                location.column = matches[index].column_number;
                location.match_length = matches[index].match_length;
                location.preview = matches[index].content;
                output.locations.push_back(std::move(location));
            }
            output.truncated = output.truncated || matches.size() > maximum;
        }
        if (cancelled.load(std::memory_order_acquire)) {
            output.state = result_state_t::cancelled;
            output.status = "Language query was cancelled";
        } else if (output.locations.empty() && output.symbols.empty() &&
                   output.completions.empty() && output.information.empty() &&
                   output.diagnostics.empty() && output.proposed_edits.empty() &&
                   output.code_actions.empty()) {
            output.state = result_state_t::empty;
            output.status = query.kind == capability_kind_t::references
                ? "No bounded lexical references matched the query"
                : "No C or C++ symbols matched the query";
        } else {
            output.state = result_state_t::ready;
            output.status = output.truncated
                ? "Results are bounded or workspace files were skipped"
                : "Results are ready";
        }
        return output;
    }

private:
    std::uint64_t generation_ = 0;
    std::function<std::shared_ptr<const code_index::published_index_t>()> snapshot_;
};

void publish_provider_snapshot(std::vector<std::shared_ptr<const provider_t>> providers)
{
    auto publication = std::make_shared<provider_publication_t>();
    publication->generation = state().provider_generation.fetch_add(1,
        std::memory_order_acq_rel) + 1;
    publication->providers = std::move(providers);
    const std::shared_ptr<const provider_publication_t> published = publication;
    std::atomic_store_explicit(&state().providers,
        published,
        std::memory_order_release);
    for (auto& slot : state().requests) {
        const auto result = std::atomic_load_explicit(&slot.publication,
            std::memory_order_acquire);
        if (!result || result->provider_id.empty())
            continue;
        const bool current = std::any_of(published->providers.begin(),
            published->providers.end(), [&](const auto& provider) {
                return provider->identity() == result->provider_id &&
                    provider->generation() == result->provider_generation;
            });
        if (current)
            continue;
        const auto cancelled = std::atomic_load_explicit(&slot.cancelled,
            std::memory_order_acquire);
        if (cancelled)
            cancelled->store(true, std::memory_order_release);
        const std::uint64_t task_id = slot.task_id.load(std::memory_order_acquire);
        if (task_id != 0)
            static_cast<void>(aida::infra::executor::cancel(task_id));
        publish_query_task_terminal(std::atomic_load_explicit(&slot.task_lifecycle,
            std::memory_order_acquire), result_state_t::cancelled,
            "Language query was cancelled because its provider was replaced or removed");
    }
}

bool replace_workspace_provider(const std::string& workspace_root)
{
    std::unique_lock<std::mutex> lock(state().provider_mutex, std::try_to_lock);
    if (!lock.owns_lock())
        return false;
    const auto current = std::atomic_load_explicit(&state().providers,
        std::memory_order_acquire);
    auto providers = current ? current->providers
        : std::vector<std::shared_ptr<const provider_t>>{};
    providers.erase(std::remove_if(providers.begin(), providers.end(),
        [](const auto& provider) {
            return provider->identity() == "workspace-text-index";
        }), providers.end());
    if (!workspace_root.empty()) {
        const std::uint64_t generation = state().provider_generation.fetch_add(1,
            std::memory_order_acq_rel) + 1;
        providers.insert(providers.begin(),
            std::make_shared<workspace_text_index_provider_t>(generation,
                [] { return current_index(); }));
    }
    publish_provider_snapshot(std::move(providers));
    return true;
}

std::shared_ptr<const query_result_t> loading_result(const query_t& query,
    const provider_t& provider, std::uint64_t request_id, std::uint64_t generation)
{
    auto output = std::make_shared<query_result_t>();
    output->state = result_state_t::loading;
    output->kind = query.kind;
    output->request_id = request_id;
    output->request_generation = generation;
    output->provider_id = provider.identity();
    output->provider_name = provider.display_name();
    output->provider_generation = provider.generation();
    output->document_id = query.document.document_id;
    output->document_revision = query.document.revision;
    output->document_path = query.document.file_path;
    output->query_text = query.text;
    output->status = "Querying " + provider.display_name();
    return output;
}

std::shared_ptr<const code_index::published_index_t> preview_fixture(
    const std::string& workspace_root)
{
    auto index = std::make_shared<code_index::bm25_index_t>();
    index->add_document("sample.cpp", 1,
        "namespace aida {\nclass WorkspaceFixture {\npublic:\n    void analyze();\n};\n}\n");
    index->add_document("sample.cpp", 7,
        "void aida::WorkspaceFixture::analyze() {\n    analyze();\n}\n");
    index->build();
    const std::string content =
        "namespace aida {\nclass WorkspaceFixture {\npublic:\n    void analyze();\n};\n}\n"
        "void aida::WorkspaceFixture::analyze() {\n    analyze();\n}\n";
    auto symbols = std::make_shared<std::vector<code_index::symbol_t>>(
        code_index::extract_symbols_cpp("sample.cpp", content));
    auto publication = std::make_shared<code_index::published_index_t>();
    publication->generation = 1;
    publication->root_path = workspace_root;
    publication->index = std::move(index);
    publication->symbols = std::move(symbols);
    publication->file_paths = std::make_shared<const std::vector<std::string>>(
        std::vector<std::string>{"sample.cpp"});
    publication->indexed_files = 1;
    publication->indexed_bytes = content.size();
    return publication;
}

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
bool register_index_task(const std::shared_ptr<code_index::manager_t>& manager,
    std::uint64_t task_id, const std::string& workspace_root)
{
    if (!manager || task_id == 0)
        return false;
    ui::task_center::task_registration_t registration;
    registration.id = "programming.workspace-index." + std::to_string(task_id);
    registration.owner = "programming.language-service";
    registration.owner_view = "view.programming.outline";
    registration.owner_action = "programming.index.rebuild";
    registration.project = workspace_root;
    registration.label = "Build Workspace Text Index";
    registration.stage = "Enumerating bounded text files and extracting C/C++ symbols";
    registration.affected_entity = "workspace-text-index";
    registration.cancellation_is_safe = true;
    registration.callbacks.cancel = [task_id] {
        return aida::infra::executor::cancel(task_id);
    };
    if (ui::task_center::try_register_executor_job(task_id, std::move(registration)))
        return true;
    manager->stop_indexing();
    auto failure = std::make_shared<const std::string>(
        "Task Center rejected Workspace Text Index ownership; indexing was cancelled");
    std::atomic_store_explicit(&state().index_ownership_failure,
        std::move(failure), std::memory_order_release);
    return false;
}
#endif

}

std::string capability_name(capability_kind_t kind)
{
    switch (kind) {
    case capability_kind_t::completion: return "Completion";
    case capability_kind_t::hover: return "Hover";
    case capability_kind_t::signature_help: return "Signature Help";
    case capability_kind_t::document_symbols: return "Document Symbols";
    case capability_kind_t::workspace_symbols: return "Workspace Symbols";
    case capability_kind_t::diagnostics: return "Language Diagnostics";
    case capability_kind_t::definition: return "Go to Definition";
    case capability_kind_t::declaration: return "Go to Declaration";
    case capability_kind_t::implementation: return "Go to Implementation";
    case capability_kind_t::type_definition: return "Go to Type Definition";
    case capability_kind_t::references: return "Find References";
    case capability_kind_t::semantic_rename: return "Semantic Rename";
    case capability_kind_t::formatting: return "Format Document";
    case capability_kind_t::range_formatting: return "Format Selection";
    case capability_kind_t::code_actions: return "Code Actions";
    }
    return "Language Capability";
}

bool register_or_replace_provider(std::shared_ptr<const provider_t> provider)
{
    if (!provider)
        return false;
    const std::string identity = provider->identity();
    const std::string display_name = provider->display_name();
    if (!valid_provider_identity(identity) || identity == "workspace-text-index" ||
        display_name.empty() || display_name.size() > 256 || provider->generation() == 0)
        return false;
    std::unique_lock<std::mutex> registry_lock(state().provider_mutex,
        std::try_to_lock);
    if (!registry_lock.owns_lock())
        return false;
    const auto current = std::atomic_load_explicit(&state().providers,
        std::memory_order_acquire);
    std::vector<std::shared_ptr<const provider_t>> providers = current
        ? current->providers : std::vector<std::shared_ptr<const provider_t>>{};
    const auto found = std::find_if(providers.begin(), providers.end(),
        [&](const auto& candidate) { return candidate->identity() == identity; });
    if (found != providers.end()) {
        if ((*found)->generation() >= provider->generation())
            return false;
        *found = std::move(provider);
    } else {
        providers.push_back(std::move(provider));
    }
    publish_provider_snapshot(std::move(providers));
    return true;
}

bool unregister_provider(std::string_view identity, std::uint64_t generation)
{
    if (!valid_provider_identity(identity) || identity == "workspace-text-index" ||
        generation == 0)
        return false;
    std::unique_lock<std::mutex> registry_lock(state().provider_mutex,
        std::try_to_lock);
    if (!registry_lock.owns_lock())
        return false;
    const auto current = std::atomic_load_explicit(&state().providers,
        std::memory_order_acquire);
    if (!current)
        return false;
    auto providers = current->providers;
    const auto found = std::find_if(providers.begin(), providers.end(),
        [&](const auto& provider) { return provider->identity() == identity; });
    if (found == providers.end() || (*found)->generation() != generation)
        return false;
    providers.erase(found);
    publish_provider_snapshot(std::move(providers));
    return true;
}

std::vector<provider_descriptor_t> provider_snapshot()
{
    const auto current = std::atomic_load_explicit(&state().providers,
        std::memory_order_acquire);
    std::vector<provider_descriptor_t> output;
    if (!current)
        return output;
    output.reserve(current->providers.size());
    for (const auto& provider : current->providers)
        output.push_back({provider->identity(), provider->display_name(), provider->generation()});
    return output;
}

std::uint64_t provider_registry_generation()
{
    const auto current = std::atomic_load_explicit(&state().providers,
        std::memory_order_acquire);
    return current ? current->generation : 0;
}

std::shared_ptr<const provider_t> provider_for(const document_context_t& document)
{
    const auto current = std::atomic_load_explicit(&state().providers,
        std::memory_order_acquire);
    if (!current)
        return {};
    for (auto iter = current->providers.rbegin(); iter != current->providers.rend(); ++iter)
        if ((*iter)->accepts(document))
            return *iter;
    return {};
}

std::shared_ptr<const provider_t> provider_for(capability_kind_t kind,
    const document_context_t& document)
{
    const auto current = std::atomic_load_explicit(&state().providers,
        std::memory_order_acquire);
    if (!current)
        return {};
    for (auto iter = current->providers.rbegin(); iter != current->providers.rend(); ++iter) {
        if ((*iter)->accepts(document) && (*iter)->capability(kind, document).available)
            return *iter;
    }
    return {};
}

capability_t capability(capability_kind_t kind, const document_context_t& document)
{
    const auto current = std::atomic_load_explicit(&state().providers,
        std::memory_order_acquire);
    if (!current)
        return {false, "No language provider is registered for Plain Text or this file extension"};
    capability_t accepted_reason;
    bool accepted = false;
    for (auto iter = current->providers.rbegin(); iter != current->providers.rend(); ++iter) {
        if (!(*iter)->accepts(document))
            continue;
        accepted = true;
        const capability_t candidate = (*iter)->capability(kind, document);
        if (candidate.available)
            return candidate;
        if (accepted_reason.reason.empty())
            accepted_reason = candidate;
    }
    return accepted ? accepted_reason : capability_t{false,
        "No language provider is registered for Plain Text or this file extension"};
}

void synchronize_workspace(std::string workspace_root)
{
    workspace_root = std::filesystem::path(workspace_root).lexically_normal().string();
    auto& store = state();
    std::shared_ptr<code_index::manager_t> previous;
    std::shared_ptr<code_index::manager_t> manager;
    bool unchanged = false;
    {
        std::unique_lock<std::mutex> lock(store.configuration_mutex,
            std::try_to_lock);
        if (!lock.owns_lock())
            return;
        const auto preview_publication = std::atomic_load_explicit(
            &store.preview_index, std::memory_order_acquire);
        if (normalized_path(store.workspace_root) == normalized_path(workspace_root) &&
            (workspace_root.empty() || store.manager || preview_publication)) {
            unchanged = true;
        } else {
            previous = std::move(store.manager);
            store.workspace_root = workspace_root;
            std::atomic_store_explicit(&store.retained_index,
                std::shared_ptr<const code_index::published_index_t>{},
                std::memory_order_release);
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
            std::atomic_store_explicit(&store.preview_index,
                workspace_root.empty() ?
                    std::shared_ptr<const code_index::published_index_t>{} :
                    preview_fixture(workspace_root),
                std::memory_order_release);
#else
            std::atomic_store_explicit(&store.preview_index,
                std::shared_ptr<const code_index::published_index_t>{},
                std::memory_order_release);
            if (!workspace_root.empty()) {
                manager = std::make_shared<code_index::manager_t>(workspace_root);
                store.manager = manager;
            }
#endif
        }
    }
    if (unchanged) {
        if (store.provider_refresh_pending.load(std::memory_order_acquire) &&
            replace_workspace_provider(workspace_root))
            store.provider_refresh_pending.store(false, std::memory_order_release);
        return;
    }
    if (previous)
        previous->stop_indexing();
    store.workspace_epoch.fetch_add(1, std::memory_order_acq_rel);
    for (auto& request : store.requests) {
        const auto cancelled = std::atomic_load_explicit(&request.cancelled,
            std::memory_order_acquire);
        if (cancelled)
            cancelled->store(true, std::memory_order_release);
        const std::uint64_t task_id = request.task_id.load(std::memory_order_acquire);
        if (task_id != 0)
            static_cast<void>(aida::infra::executor::cancel(task_id));
        publish_query_task_terminal(std::atomic_load_explicit(&request.task_lifecycle,
            std::memory_order_acquire), result_state_t::cancelled,
            "Language query was cancelled because the workspace root changed");
    }
    std::atomic_store_explicit(&store.index_ownership_failure,
        std::shared_ptr<const std::string>{}, std::memory_order_release);
    store.provider_refresh_pending.store(
        !replace_workspace_provider(workspace_root), std::memory_order_release);
#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (manager) {
        const std::uint64_t task_id = manager->start_indexing();
        static_cast<void>(register_index_task(manager, task_id, workspace_root));
    }
#endif
}

request_result_t rebuild_workspace_index()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    return {true, 1, {}};
#else
    std::shared_ptr<code_index::manager_t> previous;
    std::shared_ptr<code_index::manager_t> replacement;
    std::string workspace_root;
    {
        std::unique_lock<std::mutex> lock(state().configuration_mutex,
            std::try_to_lock);
        if (!lock.owns_lock())
            return {false, 0, "Workspace index configuration is busy; retry without blocking the UI"};
        if (state().workspace_root.empty())
            return {false, 0, "Open a workspace before rebuilding Workspace Text Index"};
        workspace_root = state().workspace_root;
        previous = std::move(state().manager);
        if (previous) {
            const auto publication = previous->snapshot();
            if (publication)
                std::atomic_store_explicit(&state().retained_index, publication,
                    std::memory_order_release);
        }
        replacement = std::make_shared<code_index::manager_t>(workspace_root);
        state().manager = replacement;
    }
    if (previous)
        previous->stop_indexing();
    std::atomic_store_explicit(&state().index_ownership_failure,
        std::shared_ptr<const std::string>{}, std::memory_order_release);
    const std::uint64_t task_id = replacement->start_indexing();
    if (task_id == 0)
        return {false, 0, replacement->status_detail()};
    if (!register_index_task(replacement, task_id, workspace_root))
        return {false, 0, "Task Center rejected Workspace Text Index ownership; indexing was cancelled"};
    return {true, task_id, {}};
#endif
}

bool cancel_workspace_index()
{
    std::shared_ptr<code_index::manager_t> manager;
    {
        std::unique_lock<std::mutex> lock(state().configuration_mutex,
            std::try_to_lock);
        if (!lock.owns_lock())
            return false;
        manager = state().manager;
    }
    if (!manager || !manager->running())
        return false;
    manager->stop_indexing();
    return true;
}

std::shared_ptr<const code_index::published_index_t> workspace_index_snapshot()
{
    return current_index();
}

code_index::index_state_t workspace_index_state()
{
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    return current_index() ? code_index::index_state_t::idle : code_index::index_state_t::standby;
#else
    std::shared_ptr<code_index::manager_t> manager;
    {
        std::unique_lock<std::mutex> lock(state().configuration_mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return code_index::index_state_t::indexing;
        manager = state().manager;
    }
    return manager ? manager->state() : code_index::index_state_t::standby;
#endif
}

std::string workspace_index_status()
{
    const auto ownership_failure = std::atomic_load_explicit(
        &state().index_ownership_failure, std::memory_order_acquire);
    if (ownership_failure)
        return *ownership_failure;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    return current_index() ? "Deterministic Studio provider fixture is ready" : "No preview workspace";
#else
    std::shared_ptr<code_index::manager_t> manager;
    {
        std::unique_lock<std::mutex> lock(state().configuration_mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return "Workspace index configuration is being updated";
        manager = state().manager;
    }
    return manager ? manager->status_detail() : "Open a workspace to build Workspace Text Index";
#endif
}

std::uint64_t workspace_index_task_id()
{
    std::shared_ptr<code_index::manager_t> manager;
    {
        std::unique_lock<std::mutex> lock(state().configuration_mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return 0;
        manager = state().manager;
    }
    return manager ? manager->task_id() : 0;
}

request_result_t request(query_t query)
{
    std::string validation_reason;
    if (!valid_query_context(query, validation_reason))
        return {false, 0, std::move(validation_reason)};
    const capability_t available = capability(query.kind, query.document);
    if (!available.available)
        return {false, 0, available.reason};
    const auto provider = provider_for(query.kind, query.document);
    if (!provider)
        return {false, 0, "No capable language provider remained available for this request"};
    query.maximum_results = (std::min)(k_maximum_query_results,
        (std::max)(std::size_t{1}, query.maximum_results));
    const capability_kind_t requested_kind = query.kind;
    const std::string requested_file = query.document.file_path;
    const std::uint64_t workspace_epoch = state().workspace_epoch.load(
        std::memory_order_acquire);
    const std::uint64_t request_id = state().next_request_id.fetch_add(1,
        std::memory_order_acq_rel);
    request_slot_t& slot = state().requests[slot_index(query.kind)];
    std::uint64_t generation = 0;
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
    auto dispatch_failed = std::make_shared<std::atomic<bool>>(false);
    auto task_lifecycle = std::make_shared<query_task_lifecycle_t>();
    std::shared_ptr<query_task_lifecycle_t> previous_task_lifecycle;
    {
        std::unique_lock<std::mutex> lock(slot.mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return {false, 0, "Language query state is being published; retry without blocking the UI"};
        const auto previous_cancelled = std::atomic_load_explicit(&slot.cancelled,
            std::memory_order_acquire);
        previous_task_lifecycle = std::atomic_load_explicit(&slot.task_lifecycle,
            std::memory_order_acquire);
        if (previous_cancelled)
            previous_cancelled->store(true, std::memory_order_release);
        const std::uint64_t previous_task = slot.task_id.load(std::memory_order_acquire);
        if (previous_task != 0)
            static_cast<void>(aida::infra::executor::cancel(previous_task));
        generation = slot.generation.fetch_add(1, std::memory_order_acq_rel) + 1;
        std::atomic_store_explicit(&slot.cancelled, cancelled,
            std::memory_order_release);
        std::atomic_store_explicit(&slot.dispatch_failed, dispatch_failed,
            std::memory_order_release);
        std::atomic_store_explicit(&slot.terminal_failure,
            std::shared_ptr<const query_result_t>{}, std::memory_order_release);
        std::atomic_store_explicit(&slot.task_lifecycle, task_lifecycle,
            std::memory_order_release);
        slot.task_id.store(0, std::memory_order_release);
        std::atomic_store_explicit(&slot.publication,
            loading_result(query, *provider, request_id, generation),
            std::memory_order_release);
    }
    if (previous_task_lifecycle) {
        publish_query_task_terminal(previous_task_lifecycle, result_state_t::cancelled,
            "Language query was superseded by a newer request for the same capability");
    }
    aida::infra::executor::submission_t submission;
    submission.owner_subsystem = "programming.language-service";
    submission.label = "programming.language-service.query";
    submission.thread_class = "bounded_query";
    submission.domain = aida::infra::executor::domain_t::feature_worker;
    submission.priority = 3;
    submission.generation = generation;
    submission.cancel_hook = [cancelled, task_lifecycle] {
        cancelled->store(true, std::memory_order_release);
        bool publish_terminal = false;
        {
            std::lock_guard<std::mutex> lock(task_lifecycle->mutex);
            task_lifecycle->cancellation_pending = true;
            publish_terminal = task_lifecycle->admission == 1U;
        }
        if (publish_terminal) {
            publish_query_task_terminal(task_lifecycle, result_state_t::cancelled,
                "Language query was cancelled by the executor");
        }
    };
    submission.body = [provider, query = std::move(query), cancelled,
        request_id, generation, workspace_epoch, task_lifecycle]() mutable {
        {
            std::unique_lock<std::mutex> lock(task_lifecycle->mutex);
            task_lifecycle->condition.wait(lock, [&task_lifecycle] {
                return task_lifecycle->admission != 0;
            });
            if (task_lifecycle->admission != 1U)
                return;
        }
        static_cast<void>(ui::task_center::update_task(task_lifecycle->task_center_id,
            ui::task_center::task_state_t::running, -1.0f,
            "Executing bounded provider query"));
        query_task_terminal_guard_t terminal(task_lifecycle);
        query_result_t result;
        try {
            result = provider->execute(query, *cancelled);
        } catch (const std::exception& exception) {
            result.state = result_state_t::error;
            result.kind = query.kind;
            result.status = std::string("Language provider failed: ") + exception.what();
        } catch (...) {
            result.state = result_state_t::error;
            result.kind = query.kind;
            result.status = "Language provider failed with an unknown exception";
        }
        if (cancelled->load(std::memory_order_acquire)) {
            result.state = result_state_t::cancelled;
            result.status = "Language query was cancelled";
            result.locations.clear();
            result.symbols.clear();
            result.completions.clear();
            result.information.clear();
            result.diagnostics.clear();
            result.proposed_edits.clear();
            result.code_actions.clear();
        }
        normalize_provider_result(query, *provider, result);
        result.request_id = request_id;
        result.request_generation = generation;
        if (state().workspace_epoch.load(std::memory_order_acquire) !=
            workspace_epoch) {
            result.state = result_state_t::cancelled;
            result.status = "Language query was cancelled because the workspace root changed";
            result.locations.clear();
            result.symbols.clear();
            result.completions.clear();
            result.information.clear();
            result.diagnostics.clear();
            result.proposed_edits.clear();
            result.code_actions.clear();
        }
        auto publication = std::make_shared<query_result_t>(std::move(result));
        bool published = false;
        {
            request_slot_t& target = state().requests[slot_index(query.kind)];
            std::lock_guard<std::mutex> lock(target.mutex);
            if (target.generation.load(std::memory_order_acquire) != generation ||
                std::atomic_load_explicit(&target.cancelled,
                    std::memory_order_acquire) != cancelled ||
                std::atomic_load_explicit(&target.terminal_failure,
                    std::memory_order_acquire)) {
                terminal.set(result_state_t::cancelled,
                    "Language query was superseded before its provider result could be published");
                return;
            }
            target.task_id.store(0, std::memory_order_release);
            std::atomic_store_explicit(&target.publication,
                std::shared_ptr<const query_result_t>(publication),
                std::memory_order_release);
            published = true;
        }
        terminal.set(publication->state, publication->status);
        if (published && query.kind == capability_kind_t::definition &&
            publication->state == result_state_t::ready &&
            publication->symbols.size() == 1) {
            const location_t location = publication->symbols.front().location;
            const std::uint64_t provider_generation = publication->provider_generation;
            const std::uint64_t index_generation = publication->index_generation;
            const bool posted = aida::ui_thread::post([location, request_id, generation,
                provider_generation, index_generation] {
                const auto current = aida::editor::language_service::result(
                    capability_kind_t::definition);
                if (!current || current->state != result_state_t::ready ||
                    current->request_id != request_id ||
                    current->request_generation != generation ||
                    current->provider_generation != provider_generation ||
                    current->index_generation != index_generation)
                    return;
                static_cast<void>(open_location(location));
            }, "programming.language-service", "definition.navigate", "completion");
            if (!posted) {
                auto failure = std::make_shared<query_result_t>(*publication);
                failure->status = "Definition resolved, but UI navigation dispatch was rejected; open the retained result manually";
                request_slot_t& target = state().requests[slot_index(query.kind)];
                std::lock_guard<std::mutex> lock(target.mutex);
                if (target.generation.load(std::memory_order_acquire) == generation &&
                    std::atomic_load_explicit(&target.cancelled,
                        std::memory_order_acquire) == cancelled)
                    std::atomic_store_explicit(&target.publication,
                        std::shared_ptr<const query_result_t>(std::move(failure)),
                        std::memory_order_release);
            }
        }
    };
    aida::infra::executor::submit_result_t submitted;
    try {
        submitted = aida::infra::executor::submit(std::move(submission));
    } catch (const std::exception& exception) {
        submitted.submitted = false;
        submitted.reject_reason = std::string("Language query submission failed: ") +
            exception.what();
    } catch (...) {
        submitted.submitted = false;
        submitted.reject_reason = "Language query submission failed with an unknown exception";
    }
    if (!submitted.submitted) {
        {
            std::lock_guard<std::mutex> lock(task_lifecycle->mutex);
            task_lifecycle->admission = 2U;
        }
        task_lifecycle->condition.notify_one();
        dispatch_failed->store(true, std::memory_order_release);
        const std::string rejection_reason = submitted.reject_reason.empty()
            ? "The language query executor rejected the request"
            : "The language query executor rejected the request: " + submitted.reject_reason;
        auto failure = std::make_shared<query_result_t>();
        failure->state = result_state_t::error;
        failure->kind = requested_kind;
        failure->request_id = request_id;
        failure->request_generation = generation;
        failure->provider_id = provider->identity();
        failure->provider_name = provider->display_name();
        failure->provider_generation = provider->generation();
        failure->status = rejection_reason;
        std::lock_guard<std::mutex> slot_lock(slot.mutex);
        if (slot.generation.load(std::memory_order_acquire) == generation &&
            std::atomic_load_explicit(&slot.task_lifecycle,
                std::memory_order_acquire) == task_lifecycle) {
            std::atomic_store_explicit(&slot.terminal_failure,
                std::shared_ptr<const query_result_t>(std::move(failure)),
                std::memory_order_release);
            std::atomic_store_explicit(&slot.task_lifecycle,
                std::shared_ptr<query_task_lifecycle_t>{}, std::memory_order_release);
        }
        return {false, 0, rejection_reason};
    }
    {
        std::lock_guard<std::mutex> lock(slot.mutex);
        if (slot.generation.load(std::memory_order_acquire) == generation &&
            std::atomic_load_explicit(&slot.task_lifecycle,
                std::memory_order_acquire) == task_lifecycle) {
            const auto publication = std::atomic_load_explicit(&slot.publication,
                std::memory_order_acquire);
            if (publication && publication->state == result_state_t::loading)
                slot.task_id.store(submitted.task_id, std::memory_order_release);
        }
    }
    bool task_registered = false;
    try {
        ui::task_center::task_registration_t registration;
        registration.id = "programming.language-query." + std::to_string(submitted.task_id);
        registration.owner = "programming.language-service";
        registration.owner_view = requested_kind == capability_kind_t::document_symbols ||
            requested_kind == capability_kind_t::workspace_symbols
            ? "view.programming.outline" : "view.programming.references";
        registration.owner_action = capability_action_id(requested_kind);
        registration.label = capability_name(requested_kind);
        registration.stage = "Querying " + provider->display_name();
        registration.affected_entity = requested_file;
        registration.cancellation_is_safe = true;
        registration.callbacks.cancel = [requested_kind, task_id = submitted.task_id,
            task_lifecycle] {
            const bool owner_cancelled = cancel_request(requested_kind);
            const bool executor_cancelled = aida::infra::executor::cancel(task_id);
            if (owner_cancelled || executor_cancelled) {
                publish_query_task_terminal(task_lifecycle, result_state_t::cancelled,
                    "Language query cancellation was accepted by its owner");
            }
            return owner_cancelled || executor_cancelled;
        };
        task_lifecycle->task_center_id = registration.id;
        task_registered = ui::task_center::try_register_executor_job(submitted.task_id,
            std::move(registration));
    } catch (...) {
        task_registered = false;
    }
    bool publish_pending_cancellation = false;
    {
        std::lock_guard<std::mutex> lock(task_lifecycle->mutex);
        task_lifecycle->admission = task_registered ? 1U : 2U;
        publish_pending_cancellation = task_registered &&
            task_lifecycle->cancellation_pending;
    }
    task_lifecycle->condition.notify_one();
    if (publish_pending_cancellation) {
        publish_query_task_terminal(task_lifecycle, result_state_t::cancelled,
            "Language query was cancelled before its owner completed admission");
    }
    if (!task_registered) {
        dispatch_failed->store(true, std::memory_order_release);
        cancelled->store(true, std::memory_order_release);
        static_cast<void>(aida::infra::executor::cancel(submitted.task_id));
        auto failure = std::make_shared<query_result_t>();
        failure->state = result_state_t::error;
        failure->kind = requested_kind;
        failure->request_id = request_id;
        failure->request_generation = generation;
        failure->provider_id = provider->identity();
        failure->provider_name = provider->display_name();
        failure->provider_generation = provider->generation();
        failure->status = "Task Center rejected language-query ownership; the executor job was cancelled";
        std::lock_guard<std::mutex> slot_lock(slot.mutex);
        if (slot.generation.load(std::memory_order_acquire) == generation &&
            std::atomic_load_explicit(&slot.task_lifecycle,
                std::memory_order_acquire) == task_lifecycle) {
            slot.task_id.store(0, std::memory_order_release);
            std::atomic_store_explicit(&slot.terminal_failure,
                std::shared_ptr<const query_result_t>(std::move(failure)),
                std::memory_order_release);
            std::atomic_store_explicit(&slot.task_lifecycle,
                std::shared_ptr<query_task_lifecycle_t>{}, std::memory_order_release);
        }
        return {false, 0, "Task Center rejected language-query ownership"};
    }
    return {true, request_id, {}};
}

bool cancel_request(capability_kind_t kind)
{
    request_slot_t& slot = state().requests[slot_index(kind)];
    std::unique_lock<std::mutex> lock(slot.mutex, std::try_to_lock);
    if (!lock.owns_lock())
        return false;
    const auto cancelled = std::atomic_load_explicit(&slot.cancelled,
        std::memory_order_acquire);
    if (!cancelled || cancelled->load(std::memory_order_acquire))
        return false;
    cancelled->store(true, std::memory_order_release);
    const std::uint64_t task_id = slot.task_id.load(std::memory_order_acquire);
    const auto task_lifecycle = std::atomic_load_explicit(&slot.task_lifecycle,
        std::memory_order_acquire);
    if (task_id != 0)
        static_cast<void>(aida::infra::executor::cancel(task_id));
    slot.generation.fetch_add(1, std::memory_order_acq_rel);
    slot.task_id.store(0, std::memory_order_release);
    const auto publication = std::atomic_load_explicit(&slot.publication,
        std::memory_order_acquire);
    if (publication && publication->state == result_state_t::loading) {
        auto cancelled_result = std::make_shared<query_result_t>(*publication);
        cancelled_result->state = result_state_t::cancelled;
        cancelled_result->status = "Language query was cancelled; the previous provider publication was not applied";
        std::atomic_store_explicit(&slot.publication,
            std::shared_ptr<const query_result_t>(std::move(cancelled_result)),
            std::memory_order_release);
    }
    lock.unlock();
    publish_query_task_terminal(task_lifecycle, result_state_t::cancelled,
        "Language query cancellation was accepted by its owner");
    return true;
}

query_snapshot_t result(capability_kind_t kind)
{
    request_slot_t& slot = state().requests[slot_index(kind)];
    const auto terminal_failure = std::atomic_load_explicit(&slot.terminal_failure,
        std::memory_order_acquire);
    if (terminal_failure)
        return terminal_failure;
    const auto publication = std::atomic_load_explicit(&slot.publication,
        std::memory_order_acquire);
    const auto cancelled = std::atomic_load_explicit(&slot.cancelled,
        std::memory_order_acquire);
    if (publication && publication->state == result_state_t::loading &&
        cancelled && cancelled->load(std::memory_order_acquire)) {
        auto cancelled_result = std::make_shared<query_result_t>(*publication);
        cancelled_result->state = result_state_t::cancelled;
        cancelled_result->status = "Language query cancellation was requested";
        return cancelled_result;
    }
    const auto dispatch_failed = std::atomic_load_explicit(&slot.dispatch_failed,
        std::memory_order_acquire);
    if (publication && publication->state == result_state_t::loading &&
        dispatch_failed && dispatch_failed->load(std::memory_order_acquire)) {
        auto failure = std::make_shared<query_result_t>(*publication);
        failure->state = result_state_t::error;
        failure->status = "Language query dispatch failed before Task Center-owned execution could continue";
        return failure;
    }
    if (!publication)
        return {};
    const auto providers = std::atomic_load_explicit(&state().providers,
        std::memory_order_acquire);
    const bool provider_is_current = providers && std::any_of(
        providers->providers.begin(), providers->providers.end(),
        [&](const auto& provider) {
            return provider->identity() == publication->provider_id &&
                provider->generation() == publication->provider_generation;
        });
    const auto index = publication->provider_id == "workspace-text-index"
        ? current_index() : nullptr;
    const bool index_is_current = !index || publication->index_generation == 0 ||
        (publication->index_generation == index->generation &&
         normalized_path(publication->root_path) == normalized_path(index->root_path));
    if (!provider_is_current || !index_is_current) {
        auto unavailable = std::make_shared<query_result_t>(*publication);
        unavailable->state = result_state_t::unavailable;
        unavailable->status = !provider_is_current
            ? "The result provider was replaced or unregistered; run the query again"
            : "The Workspace Text Index published a newer generation; run the query again";
        unavailable->locations.clear();
        unavailable->symbols.clear();
        unavailable->completions.clear();
        unavailable->information.clear();
        unavailable->diagnostics.clear();
        unavailable->proposed_edits.clear();
        unavailable->code_actions.clear();
        return unavailable;
    }
    return publication;
}

query_result_t execute_worker_query(query_t query,
    const std::atomic<bool>& cancelled)
{
    if (aida::infra::executor::is_ui_thread()) {
        query_result_t output;
        output.kind = query.kind;
        output.state = result_state_t::unavailable;
        output.status = "Worker-only language query was rejected on the UI thread";
        return output;
    }
    std::string validation_reason;
    if (!valid_query_context(query, validation_reason)) {
        query_result_t output;
        output.kind = query.kind;
        output.state = result_state_t::unavailable;
        output.status = std::move(validation_reason);
        return output;
    }
    const capability_t available = capability(query.kind, query.document);
    if (!available.available) {
        query_result_t output;
        output.kind = query.kind;
        output.state = result_state_t::unavailable;
        output.status = available.reason;
        return output;
    }
    const auto provider = provider_for(query.kind, query.document);
    if (!provider) {
        query_result_t output;
        output.kind = query.kind;
        output.state = result_state_t::unavailable;
        output.status = "No capable language provider remained available for this request";
        return output;
    }
    query_result_t output;
    try {
        output = provider->execute(query, cancelled);
    } catch (const std::exception& exception) {
        output.kind = query.kind;
        output.state = result_state_t::error;
        output.status = std::string("Language provider failed: ") + exception.what();
    } catch (...) {
        output.kind = query.kind;
        output.state = result_state_t::error;
        output.status = "Language provider failed with an unknown exception";
    }
    if (cancelled.load(std::memory_order_acquire)) {
        output.state = result_state_t::cancelled;
        output.status = "Language query was cancelled";
        output.locations.clear();
        output.symbols.clear();
        output.completions.clear();
        output.information.clear();
        output.diagnostics.clear();
        output.proposed_edits.clear();
        output.code_actions.clear();
    }
    normalize_provider_result(query, *provider, output);
    return output;
}

document_context_t active_document_context()
{
    document_context_t output;
    const auto document = code_editor_widget::document_state();
    output.document_id = code_editor_widget::active_document_id();
    output.revision = code_editor_widget::document_revision();
    output.file_path = document.filepath;
    output.language_id = document.language.empty() ? "Plain Text" : document.language;
    output.position = {document.caret_line, document.caret_column};
    return output;
}

std::string active_query_text()
{
    return code_editor_widget::caret_identifier();
}

namespace {

std::string resolved_location_path(const location_t& location)
{
    if (location.file_path.empty())
        return {};
    std::filesystem::path path;
    try {
        path = path_from_utf8(location.file_path);
    } catch (...) {
        return {};
    }
    if (path.is_relative()) {
        if (location.root_path.empty())
            return {};
        try {
            path = path_from_utf8(location.root_path) / path;
        } catch (...) {
            return {};
        }
    }
    path = path.lexically_normal();
    if (!location.root_path.empty()) {
        std::string root;
        std::string candidate;
        try {
            root = normalized_path(path_to_utf8(
                path_from_utf8(location.root_path).lexically_normal()));
            candidate = normalized_path(path_to_utf8(path));
        } catch (...) {
            return {};
        }
        const bool in_root = candidate == root ||
            (candidate.size() > root.size() &&
             candidate.compare(0, root.size(), root) == 0 &&
             candidate[root.size()] == '/');
        if (root.empty() || !in_root)
            return {};
    }
    try {
        return path_to_utf8(path);
    } catch (...) {
        return {};
    }
}

}

bool open_location(const location_t& location, bool open_to_side)
{
    const std::string resolved_path = resolved_location_path(location);
    if (resolved_path.empty())
        return false;
    std::string filename;
    try {
        filename = path_to_utf8(path_from_utf8(resolved_path).filename());
    } catch (...) {
        return false;
    }
    if (!file_tabs::request_document_open(resolved_path, filename,
            (std::max)(0, location.line - 1), (std::max)(0, location.column - 1)))
        return false;
    if (open_to_side && file_tabs::create_group_for_tab(file_tabs::active_tab) == 0)
        return false;
    static_cast<void>(ui::application_views::open_or_focus(
        ui::stable_view_id_t("document.code")));
    return true;
}

bool send_location_to_ai(const location_t& location, std::string_view provenance)
{
    const std::string resolved_path = resolved_location_path(location);
    if (resolved_path.empty())
        return false;
    std::ostringstream payload;
    payload << "Programming evidence from " << provenance << "\n"
        << resolved_path << ':' << location.line << ':' << location.column << '\n';
    if (!location.preview.empty())
        payload << location.preview.substr(0, 2048);
    chat_inject::post(payload.str());
    static_cast<void>(ui::application_views::open_or_focus(
        ui::stable_view_id_t("view.ai_chat")));
    return true;
}

void begin_frame()
{
    std::string root = g_sa_settings.workspace.root_path.empty()
        ? file_browser::current_dir : g_sa_settings.workspace.root_path;
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
    if (root.empty())
        root = "C:/AiDA/Preview";
#endif
    synchronize_workspace(std::move(root));
    const document_context_t document = active_document_context();
    const auto publication = workspace_index_snapshot();
    if (document.document_id == 0 || !publication)
        return;
    auto& store = state();
    const std::uint64_t registry_generation = provider_registry_generation();
    if (store.outline_document_id == document.document_id &&
        store.outline_index_generation == publication->generation &&
        store.outline_provider_registry_generation == registry_generation)
        return;
    const capability_t available = capability(capability_kind_t::document_symbols,
        document);
    if (!available.available) {
        store.outline_document_id = document.document_id;
        store.outline_index_generation = publication->generation;
        store.outline_provider_registry_generation = registry_generation;
        return;
    }
    query_t outline;
    outline.kind = capability_kind_t::document_symbols;
    outline.document = document;
    outline.maximum_results = 4096;
    const auto requested = request(std::move(outline));
    if (requested.accepted ||
        requested.reason.find("retry without blocking the UI") == std::string::npos) {
        store.outline_document_id = document.document_id;
        store.outline_index_generation = publication->generation;
        store.outline_provider_registry_generation = registry_generation;
    }
}

void shutdown() noexcept
{
    for (std::size_t index = 0; index < k_capability_count; ++index) {
        request_slot_t& slot = state().requests[index];
        std::lock_guard<std::mutex> lock(slot.mutex);
        const auto cancelled = std::atomic_load_explicit(&slot.cancelled,
            std::memory_order_acquire);
        if (cancelled)
            cancelled->store(true, std::memory_order_release);
        const std::uint64_t task_id = slot.task_id.load(std::memory_order_acquire);
        if (task_id != 0)
            static_cast<void>(aida::infra::executor::cancel(task_id));
        slot.task_id.store(0, std::memory_order_release);
        publish_query_task_terminal(std::atomic_load_explicit(&slot.task_lifecycle,
            std::memory_order_acquire), result_state_t::cancelled,
            "Language query was cancelled during language-service shutdown");
    }
    std::shared_ptr<code_index::manager_t> manager;
    {
        std::lock_guard<std::mutex> lock(state().configuration_mutex);
        manager = std::move(state().manager);
        std::atomic_store_explicit(&state().preview_index,
            std::shared_ptr<const code_index::published_index_t>{},
            std::memory_order_release);
        std::atomic_store_explicit(&state().retained_index,
            std::shared_ptr<const code_index::published_index_t>{},
            std::memory_order_release);
        state().workspace_root.clear();
    }
    if (manager)
        manager->stop_indexing();
}

}
