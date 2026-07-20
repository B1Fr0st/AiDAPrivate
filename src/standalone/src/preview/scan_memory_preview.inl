inline std::vector<std::uint8_t> parse_value(const std::string& text, value_type_t type, bool hex)
{
	std::vector<std::uint8_t> bytes;
	if (type == value_type_t::string_ascii) return {text.begin(), text.end()};
	if (type == value_type_t::string_utf16) {
		for (char raw_character : text) {
			const auto character = static_cast<unsigned char>(raw_character);
			bytes.push_back(character);
			bytes.push_back(0);
		}
		return bytes;
	}
	if (type == value_type_t::byte_array) {
		std::string token;
		for (char character : text) {
			if (std::isxdigit(static_cast<unsigned char>(character))) token.push_back(character);
			if (token.size() == 2) {
				bytes.push_back(static_cast<std::uint8_t>(std::strtoul(token.c_str(), nullptr, 16)));
				token.clear();
			}
		}
		return bytes;
	}
	if (type == value_type_t::float_val) {
		const float value = std::strtof(text.c_str(), nullptr);
		bytes.resize(sizeof(value));
		std::memcpy(bytes.data(), &value, sizeof(value));
		return bytes;
	}
	if (type == value_type_t::double_val) {
		const double value = std::strtod(text.c_str(), nullptr);
		bytes.resize(sizeof(value));
		std::memcpy(bytes.data(), &value, sizeof(value));
		return bytes;
	}
	const std::uint64_t value = std::strtoull(text.empty() ? "0" : text.c_str(), nullptr, hex ? 16 : 10);
	const std::size_t size = value_type_size(type);
	bytes.resize(size);
	std::memcpy(bytes.data(), &value, size);
	return bytes;
}

inline std::string format_value(const std::vector<std::uint8_t>& bytes, value_type_t type)
{
	if (type == value_type_t::string_ascii) return {bytes.begin(), bytes.end()};
	if (type == value_type_t::string_utf16) {
		std::string text;
		for (std::size_t index = 0; index + 1 < bytes.size(); index += 2)
			if (bytes[index]) text.push_back(static_cast<char>(bytes[index]));
		return text;
	}
	if (type == value_type_t::byte_array) {
		std::string text;
		for (std::size_t index = 0; index < bytes.size(); ++index) {
			char buffer[4]{};
			std::snprintf(buffer, sizeof(buffer), "%02X", bytes[index]);
			if (index) text.push_back(' ');
			text += buffer;
		}
		return text;
	}
	char buffer[64]{};
	if (type == value_type_t::float_val && bytes.size() >= sizeof(float)) {
		float value = 0.f;
		std::memcpy(&value, bytes.data(), sizeof(value));
		std::snprintf(buffer, sizeof(buffer), "%.4f", value);
	} else if (type == value_type_t::double_val && bytes.size() >= sizeof(double)) {
		double value = 0.0;
		std::memcpy(&value, bytes.data(), sizeof(value));
		std::snprintf(buffer, sizeof(buffer), "%.6f", value);
	} else {
		std::uint64_t value = 0;
		std::memcpy(&value, bytes.data(), (std::min)(bytes.size(), sizeof(value)));
		std::snprintf(buffer, sizeof(buffer), "%llu", static_cast<unsigned long long>(value));
	}
	return buffer;
}

inline std::uint64_t observe_target_binding(std::uint32_t pid)
{
	const std::uint32_t previous = g_state.observed_target_pid.exchange(pid, std::memory_order_acq_rel);
	g_state.observed_target_creation_time_100ns.store(pid == 0 ? 0 : 1,
		std::memory_order_release);
	if (previous != pid)
		return g_state.target_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
	return g_state.target_epoch.load(std::memory_order_acquire);
}

inline bool target_binding_current(std::uint32_t pid, std::uint64_t epoch)
{
	return pid != 0 && g_state.observed_target_pid.load(std::memory_order_acquire) == pid &&
		g_state.target_epoch.load(std::memory_order_acquire) == epoch;
}

inline bool validate_target_binding(std::uint32_t pid, std::uint64_t epoch,
	std::uint64_t process_creation_time_100ns)
{
	return process_creation_time_100ns == 1 && target_binding_current(pid, epoch);
}

inline bool first_scan(const scan_config_t& config)
{
	g_state.config = config;
	g_state.scan_target_pid = 6420;
	g_state.scan_target_epoch = observe_target_binding(g_state.scan_target_pid);
	g_state.scanning.store(true);
	g_state.scan_progress.store(.25f);
	std::vector<scan_result_t> results;
	const auto base_value = parse_value(config.value_text.empty() ? "1337" : config.value_text,
		config.value_type, config.hex_input);
	for (std::size_t index = 0; index < 64; ++index) {
		scan_result_t result;
		result.address = 0x00007FF7A4C42000ULL + index * 0x18ULL;
		result.current_value = base_value;
		if (!result.current_value.empty()) result.current_value[0] = static_cast<std::uint8_t>(result.current_value[0] + index % 7);
		result.previous_value = result.current_value;
		result.module_name = "sample.exe";
		result.module_offset = result.address - 0x00007FF7A4C00000ULL;
		results.push_back(std::move(result));
	}
	{
		std::lock_guard<std::mutex> lock(g_state.results_mutex);
		g_state.results = std::move(results);
		g_state.total_found = g_state.results.size();
		g_state.scan_history.clear();
	}
	g_state.has_initial_scan = true;
	g_state.scan_count = 1;
	g_state.scan_progress.store(1.f);
	g_state.scanning.store(false);
	g_state.scan_thread_done.store(true);
	return true;
}

inline bool next_scan(scan_mode_t mode, const std::string&, const std::string& = "")
{
	if (!g_state.has_initial_scan) return false;
	std::lock_guard<std::mutex> lock(g_state.results_mutex);
	g_state.scan_history.push_back(g_state.results);
	std::vector<scan_result_t> filtered;
	for (std::size_t index = 0; index < g_state.results.size(); ++index) {
		if ((index + static_cast<std::size_t>(mode)) % 3 != 0) filtered.push_back(g_state.results[index]);
	}
	g_state.results = std::move(filtered);
	g_state.total_found = g_state.results.size();
	++g_state.scan_count;
	g_state.config.scan_mode = mode;
	g_state.scan_progress.store(1.f);
	return true;
}

inline bool cancel_scan()
{
	bool expected = true;
	return g_state.scanning.compare_exchange_strong(expected, false,
		std::memory_order_acq_rel, std::memory_order_acquire);
}

inline void undo_scan()
{
	std::lock_guard<std::mutex> lock(g_state.results_mutex);
	if (g_state.scan_history.empty()) return;
	g_state.results = std::move(g_state.scan_history.back());
	g_state.scan_history.pop_back();
	g_state.total_found = g_state.results.size();
	if (g_state.scan_count > 1) --g_state.scan_count;
}

inline void reset_scan()
{
	std::lock_guard<std::mutex> lock(g_state.results_mutex);
	g_state.results.clear();
	g_state.scan_history.clear();
	g_state.total_found = 0;
	g_state.has_initial_scan = false;
	g_state.scan_count = 0;
}

inline void add_address(std::uint64_t address, const std::string& description, value_type_t type)
{
	std::lock_guard<std::mutex> lock(g_state.address_mutex);
	for (const auto& entry : g_state.address_list) if (entry.address == address) return;
	address_entry_t entry;
	entry.address = address;
	entry.description = description;
	entry.value_type = type;
	entry.last_value = parse_value("1337", type, false);
	g_state.address_list.push_back(std::move(entry));
}

inline void remove_address(std::size_t index)
{
	std::lock_guard<std::mutex> lock(g_state.address_mutex);
	if (index < g_state.address_list.size())
		g_state.address_list.erase(g_state.address_list.begin() + static_cast<decltype(g_state.address_list)::difference_type>(index));
}

inline void freeze_address(std::size_t index, bool enabled)
{
	std::lock_guard<std::mutex> lock(g_state.address_mutex);
	if (index >= g_state.address_list.size()) return;
	auto& entry = g_state.address_list[index];
	entry.frozen = enabled;
	entry.freeze_value = enabled ? entry.last_value : std::vector<std::uint8_t>{};
}

inline void write_value(std::uint64_t address, value_type_t type, const std::string& text, bool hex = false)
{
	std::lock_guard<std::mutex> lock(g_state.address_mutex);
	for (auto& entry : g_state.address_list)
		if (entry.address == address) entry.last_value = parse_value(text, type, hex);
}

inline std::string read_value_string(std::uint64_t address, value_type_t type)
{
	std::lock_guard<std::mutex> lock(g_state.address_mutex);
	for (const auto& entry : g_state.address_list)
		if (entry.address == address) return format_value(entry.last_value, type);
	return {};
}

inline void refresh_address_list()
{
	std::lock_guard<std::mutex> lock(g_state.address_mutex);
	for (std::size_t index = 0; index < g_state.address_list.size(); ++index) {
		auto& entry = g_state.address_list[index];
		if (!entry.frozen && !entry.last_value.empty()) entry.last_value[0] = static_cast<std::uint8_t>(entry.last_value[0] + (index % 2));
	}
}

inline void initialize() {}
inline void shutdown() {}
inline bool start_pointer_scan(std::uint64_t, int, int, std::uint64_t = 0, std::uint64_t = 0) { return true; }
inline void cancel_pointer_scan() {}

inline void configure_preview_fixture(aida::preview::fixture_state_t state, std::size_t cardinality)
{
	if (state == aida::preview::fixture_state_t::empty ||
		state == aida::preview::fixture_state_t::disconnected) {
		reset_scan();
		g_state.scan_target_pid = 0;
		g_state.scanning.store(false, std::memory_order_release);
		return;
	}
	scan_config_t config;
	config.value_type = value_type_t::int32_val;
	config.value_text = "1337";
	first_scan(config);
	const std::size_t bounded = (std::min<std::size_t>)(cardinality, 10000U);
	if (bounded > g_state.results.size()) {
		std::lock_guard<std::mutex> lock(g_state.results_mutex);
		const auto value = parse_value("1337", value_type_t::int32_val, false);
		g_state.results.reserve(bounded);
		for (std::size_t index = g_state.results.size(); index < bounded; ++index) {
			scan_result_t result;
			result.address = 0x00007FF7A5000000ULL + static_cast<std::uint64_t>(index) * 0x10ULL;
			result.current_value = value;
			result.previous_value = value;
			result.module_name = "sample.exe";
			result.module_offset = result.address - 0x00007FF7A4C00000ULL;
			g_state.results.push_back(std::move(result));
		}
		g_state.total_found = g_state.results.size();
	}
	if (state == aida::preview::fixture_state_t::loading) {
		g_state.scanning.store(true, std::memory_order_release);
		g_state.scan_progress.store(0.42f, std::memory_order_release);
	} else if (state == aida::preview::fixture_state_t::cancellation_requested) {
		g_state.scanning.store(true, std::memory_order_release);
		g_state.scan_progress.store(0.68f, std::memory_order_release);
	} else {
		g_state.scanning.store(false, std::memory_order_release);
		g_state.scan_progress.store(1.0f, std::memory_order_release);
	}
}
