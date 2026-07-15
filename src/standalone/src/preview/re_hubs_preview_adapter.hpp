#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace aida::preview::re_hubs {

enum class domain_t : std::uint8_t {
	scan,
	types,
	analysis,
	symbolic,
	protection
};

struct receipt_t {
	domain_t domain = domain_t::scan;
	int index = 0;
	std::string action;
	std::string detail;
	std::uint64_t sequence = 0;
};

inline std::vector<receipt_t>& receipts()
{
	static std::vector<receipt_t> value;
	return value;
}

inline std::uint64_t& next_sequence()
{
	static std::uint64_t value = 1;
	return value;
}

inline std::array<std::uint32_t, 5>& rendered_masks()
{
	static std::array<std::uint32_t, 5> value{};
	return value;
}

inline void record(domain_t domain, int index, std::string action, std::string detail = {})
{
	auto& values = receipts();
	values.push_back({domain, index, std::move(action), std::move(detail), next_sequence()++});
	if (values.size() > 256)
		values.erase(values.begin(), values.begin() + 64);
}

inline void select(domain_t domain, int index, const char* label)
{
	record(domain, index, "select", label ? label : "");
}

inline void rendered(domain_t domain, int index, const char* label)
{
	if (index >= 0 && index < 32)
		rendered_masks()[static_cast<std::size_t>(domain)] |= (1u << static_cast<unsigned>(index));
	record(domain, index, "render", label ? label : "");
}

inline std::uint32_t rendered_mask(domain_t domain)
{
	return rendered_masks()[static_cast<std::size_t>(domain)];
}

inline void action(domain_t domain, int index, const char* action_name, const std::string& detail = {})
{
	record(domain, index, action_name ? action_name : "action", detail);
}

}

#endif
