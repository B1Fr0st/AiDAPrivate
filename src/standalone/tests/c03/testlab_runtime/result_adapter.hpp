#pragma once

#include "../assertion_telemetry/assertion_telemetry.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace aida::analysis::c03_test::testlab_runtime {

struct adapter_control_t {
	std::uintptr_t result_handle = 0;
	std::string entry_id;
	std::string source_target;
	std::string build_identity;
	std::vector<std::string> forwarded_arguments;
};

using adapted_entry_t = std::function<int(const std::vector<std::string>&)>;

bool parse_adapter_control(int argc, char** argv, adapter_control_t& control, std::string& error);
bool write_result_envelope(const adapter_control_t& control, int exit_code,
	std::uint64_t elapsed_us, const assertion_telemetry::assertion_report_t& report,
	std::string& error);
int run_adapted_entry(int argc, char** argv, const adapted_entry_t& entry);

}
