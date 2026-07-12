#include "document_registry.h"

#include <algorithm>
#include <limits>
#include <unordered_set>
#include <utility>

namespace aida {
namespace workbench {
namespace {

workbench_error_t error(workbench_error_code_t code, std::uint64_t subject = 0) noexcept
{
    return {code, subject};
}

bool document_less(const document_persistence_dto_t& lhs,
                   const document_persistence_dto_t& rhs)
{
    if (document_identity_less(lhs.identity, rhs.identity))
        return true;
    if (document_identity_less(rhs.identity, lhs.identity))
        return false;
    return lhs.id < rhs.id;
}

bool valid_document_record(const document_persistence_dto_t& document,
                           workspace_id_t workspace)
{
    return document.id.valid() && document.identity.workspace == workspace &&
           document.identity.provider_key.size() <= k_max_document_key_bytes &&
           document.title.size() <= k_max_document_title_bytes &&
           document.state_token.size() <= k_max_panel_state_bytes &&
           validate_document_identity(document.identity).ok() &&
           validate_document_local_state(document.local_state).ok();
}

workbench_error_t next_document_id(const std::vector<document_persistence_dto_t>& documents,
                                   document_id_t& output) noexcept
{
    std::uint64_t maximum = 0;
    for (const auto& document : documents)
        maximum = (std::max)(maximum, document.id.value);
    if (maximum == (std::numeric_limits<std::uint64_t>::max)())
        return error(workbench_error_code_t::revision_overflow, maximum);
    output = {maximum + 1U};
    return {};
}

}

document_registry_t::document_registry_t(workspace_id_t workspace)
    : workspace_(workspace)
{
}

workbench_error_t document_registry_t::restore(
    const std::vector<document_persistence_dto_t>& documents)
{
    if (!workspace_.valid() || documents.size() > k_max_documents_per_workspace)
        return error(workbench_error_code_t::invalid_workspace, workspace_.value);

    std::unordered_set<std::uint64_t> ids;
    std::vector<document_identity_t> identities;
    ids.reserve(documents.size());
    identities.reserve(documents.size());
    for (const auto& document : documents) {
        if (!valid_document_record(document, workspace_))
            return error(workbench_error_code_t::invalid_document, document.id.value);
        if (!ids.insert(document.id.value).second)
            return error(workbench_error_code_t::duplicate_identifier, document.id.value);
        for (const auto& identity : identities) {
            if (document_identity_equal(identity, document.identity))
                return error(workbench_error_code_t::duplicate_identifier, document.id.value);
        }
        identities.push_back(document.identity);
    }

    documents_ = documents;
    std::sort(documents_.begin(), documents_.end(), document_less);
    return {};
}

const std::vector<document_persistence_dto_t>& document_registry_t::documents() const noexcept
{
    return documents_;
}

bool document_registry_t::empty() const noexcept
{
    return documents_.empty();
}

workbench_error_t document_registry_t::find(document_id_t id,
                                             document_persistence_dto_t& output) const
{
    if (!id.valid())
        return error(workbench_error_code_t::invalid_document);
    const auto found = std::find_if(documents_.begin(), documents_.end(), [id](const auto& document) {
        return document.id == id;
    });
    if (found == documents_.end())
        return error(workbench_error_code_t::invalid_document, id.value);
    output = *found;
    return {};
}

workbench_error_t document_registry_t::find(const document_identity_t& identity,
                                             document_persistence_dto_t& output) const
{
    const auto identity_result = validate_document_identity(identity);
    if (!identity_result)
        return identity_result;
    if (identity.workspace != workspace_)
        return error(workbench_error_code_t::workspace_mismatch, identity.workspace.value);
    const auto found = std::find_if(documents_.begin(), documents_.end(), [&identity](const auto& document) {
        return document_identity_equal(document.identity, identity);
    });
    if (found == documents_.end())
        return error(workbench_error_code_t::invalid_document);
    output = *found;
    return {};
}

workbench_error_t document_registry_t::open(const document_descriptor_t& descriptor,
                                             document_id_t& output, bool& already_open)
{
    output = {};
    already_open = false;
    const auto identity_result = validate_document_identity(descriptor.identity);
    if (!identity_result)
        return identity_result;
    if (descriptor.identity.workspace != workspace_)
        return error(workbench_error_code_t::workspace_mismatch, descriptor.identity.workspace.value);
    if (!descriptor.can_open || descriptor.title.size() > k_max_document_title_bytes)
        return error(workbench_error_code_t::adapter_rejected);

    document_persistence_dto_t existing;
    if (find(descriptor.identity, existing).ok()) {
        output = existing.id;
        already_open = true;
        return {};
    }
    if (documents_.size() >= k_max_documents_per_workspace)
        return error(workbench_error_code_t::invalid_persistence);

    document_id_t next;
    const auto next_result = next_document_id(documents_, next);
    if (!next_result)
        return next_result;
    document_persistence_dto_t opened;
    opened.id = next;
    opened.identity = descriptor.identity;
    opened.title = descriptor.title;
    documents_.push_back(std::move(opened));
    std::sort(documents_.begin(), documents_.end(), document_less);
    output = next;
    return {};
}

workbench_error_t document_registry_t::close(document_id_t id,
                                              document_persistence_dto_t& output)
{
    output = {};
    if (!id.valid())
        return error(workbench_error_code_t::invalid_document);
    const auto found = std::find_if(documents_.begin(), documents_.end(), [id](const auto& document) {
        return document.id == id;
    });
    if (found == documents_.end())
        return error(workbench_error_code_t::invalid_document, id.value);
    output = *found;
    documents_.erase(found);
    return {};
}

workbench_error_t reconcile_document_registry(document_registry_t& registry,
                                              const document_catalog_adapter_t& catalog,
                                              missing_document_policy_t policy,
                                              std::vector<document_id_t>& omitted)
{
    omitted.clear();
    std::vector<document_persistence_dto_t> retained;
    retained.reserve(registry.documents().size());
    for (const auto& document : registry.documents()) {
        document_descriptor_t descriptor;
        const auto describe_result = catalog.describe(document.identity, descriptor);
        const bool exact_identity = describe_result.ok() &&
            document_identity_equal(descriptor.identity, document.identity);
        if (!exact_identity || !descriptor.can_open) {
            if (policy == missing_document_policy_t::reject)
                return error(workbench_error_code_t::adapter_rejected, document.id.value);
            omitted.push_back(document.id);
            continue;
        }
        auto refreshed = document;
        if (!descriptor.title.empty())
            refreshed.title = descriptor.title;
        if (refreshed.title.size() > k_max_document_title_bytes)
            return error(workbench_error_code_t::adapter_rejected, document.id.value);
        retained.push_back(std::move(refreshed));
    }
    return registry.restore(retained);
}

}
}
