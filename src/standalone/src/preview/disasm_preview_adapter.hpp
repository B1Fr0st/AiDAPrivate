#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace aida::preview::disasm
{
	struct receipt_t
	{
		std::string action;
		std::string detail;
		std::uint64_t address = 0;
		std::uint64_t sequence = 0;
	};

	inline std::vector<receipt_t> receipts;
	inline std::uint64_t next_sequence = 1;

	inline void record(std::string action, std::uint64_t address = 0,
		std::string detail = {})
	{
		receipts.push_back({std::move(action), std::move(detail), address,
			next_sequence++});
		if (receipts.size() > 256)
			receipts.erase(receipts.begin(), receipts.begin() + 64);
	}
}

#endif
