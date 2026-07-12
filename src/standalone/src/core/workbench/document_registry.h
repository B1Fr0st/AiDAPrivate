#pragma once

#include "workbench_contracts.h"

#include <vector>

namespace aida {
namespace workbench {

enum class missing_document_policy_t : std::uint8_t {
    reject = 0,
    omit = 1
};

class document_registry_t {
public:
    explicit document_registry_t(workspace_id_t workspace = {});

    workbench_error_t restore(const std::vector<document_persistence_dto_t>& documents);
    const std::vector<document_persistence_dto_t>& documents() const noexcept;
    bool empty() const noexcept;

    workbench_error_t find(document_id_t id, document_persistence_dto_t& output) const;
    workbench_error_t find(const document_identity_t& identity,
                           document_persistence_dto_t& output) const;
    workbench_error_t open(const document_descriptor_t& descriptor, document_id_t& output,
                           bool& already_open);
    workbench_error_t close(document_id_t id, document_persistence_dto_t& output);

private:
    workspace_id_t workspace_;
    std::vector<document_persistence_dto_t> documents_;
};

workbench_error_t reconcile_document_registry(document_registry_t& registry,
                                              const document_catalog_adapter_t& catalog,
                                              missing_document_policy_t policy,
                                              std::vector<document_id_t>& omitted);

}
}
