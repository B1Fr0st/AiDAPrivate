#include "anti_tamper_integrity_harness.hpp"

#include "../../../../src/core/anti-tamper/re_detection_engine.hpp"

namespace aida::c03::security
{
bool run_passive_probe_policy_cases(std::string& failure)
{
    using anti_tamper::re_detect::detail::external_probe_owner_is_hostile;
    if (!record_policy_case(external_probe_owner_is_hostile(false, false, true),
        "foreign_known_probe_owner_not_classified", failure)) {
        return false;
    }
    if (!record_policy_case(!external_probe_owner_is_hostile(true, false, true)
        && !external_probe_owner_is_hostile(false, true, true)
        && !external_probe_owner_is_hostile(false, false, false),
        "trusted_or_unknown_probe_owner_misclassified", failure)) {
        return false;
    }
    return true;
}
}
