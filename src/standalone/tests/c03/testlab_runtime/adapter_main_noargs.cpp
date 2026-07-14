#include "result_adapter.hpp"

extern int aida_c03_harness_entry();

int main(int argc, char** argv) {
	return aida::analysis::c03_test::testlab_runtime::run_adapted_entry(argc, argv,
		[](const std::vector<std::string>&) { return aida_c03_harness_entry(); });
}
