#pragma once

#include "network_preview_adapter.hpp"
#include "../core/infra/executor.hpp"
#include "../core/network/executor_status.hpp"

#include <cstring>

namespace aida::manual_map_tls {
inline bool ensure_current_thread() { return true; }
}

namespace aida::preview::network {

inline void executor_receipt_observer(const infra::executor::submission_t& submission) {
    if (!submission.owner_subsystem ||
        (std::strncmp(submission.owner_subsystem, "network.", 8) != 0 &&
         std::strncmp(submission.owner_subsystem, "burp.", 5) != 0))
        return;
    record_receipt(
        submission.label ? submission.label : "Preview action",
        infra::executor::domain_name(submission.domain));
}

inline const bool executor_receipt_observer_registered = [] {
    infra::executor::set_preview_submission_observer(&executor_receipt_observer);
    return true;
}();

}
