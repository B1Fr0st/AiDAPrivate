#include "result_adapter.hpp"

#include <vector>

extern int aida_c03_harness_entry(int, char**);

int main(int argc, char** argv) {
	return aida::analysis::c03_test::testlab_runtime::run_adapted_entry(argc, argv,
		[](const std::vector<std::string>& arguments) {
			std::vector<std::string> storage;
			storage.reserve(arguments.size() + 1);
			storage.emplace_back("aida-c03-harness");
			storage.insert(storage.end(), arguments.begin(), arguments.end());
			std::vector<char*> pointers;
			pointers.reserve(storage.size() + 1);
			for (auto& value : storage) pointers.push_back(value.data());
			pointers.push_back(nullptr);
			return aida_c03_harness_entry(static_cast<int>(storage.size()), pointers.data());
		});
}
