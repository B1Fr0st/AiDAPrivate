#include "test_lab.hpp"

#include <mutex>
#include <string>
#include <vector>

namespace test_lab {

	namespace {

		std::mutex& registry_mutex() {
			static std::mutex m;
			return m;
		}

		std::vector<feature_t>& registry_storage() {
			static std::vector<feature_t> v;
			return v;
		}

		std::string& last_error_storage() {
			static std::string s;
			return s;
		}

	}

	bool register_feature(const feature_t& f) {
		if (f.name == nullptr || f.name[0] == '\0' ||
			f.category == nullptr || f.category[0] == '\0' ||
			f.run == nullptr) {
			std::lock_guard<std::mutex> lk(registry_mutex());
			last_error_storage() = "register_feature: missing required field (name/category/run)";
			return false;
		}
		std::lock_guard<std::mutex> lk(registry_mutex());
		registry_storage().push_back(f);
		return true;
	}

	const std::vector<feature_t>& all_features() {
		return registry_storage();
	}

	const std::string& last_error() {
		return last_error_storage();
	}

	registrar_t::registrar_t(const feature_t& f) noexcept {
		register_feature(f);
	}

}
