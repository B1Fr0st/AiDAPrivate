#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "burp_events.hpp"

namespace aida {
namespace burp {
namespace bambda {

struct bambda_program_t
{
    bool                  valid = false;
    std::string           error;
    std::string           source;
    std::shared_ptr<void> ast;
};

struct row_view_t
{
    std::function<std::optional<std::string>(const std::string& path)> get_string;
    std::function<std::optional<int64_t>(const std::string& path)>     get_number;
};

bambda_program_t compile(const std::string& source);
bool             evaluate(const bambda_program_t& p, const row_view_t& row);

row_view_t      make_provider_for_exchange(const exchange_observed_t& e);
std::string     bambda_help_text();
std::string     last_error();

}
}
}
