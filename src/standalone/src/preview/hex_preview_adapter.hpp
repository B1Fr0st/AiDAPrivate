#pragma once

#if defined(AIDA_IMGUI_STUDIO_PREVIEW)

#include "../core/ui/application_view_registry.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace aida::preview::hex
{
	struct receipt_t
	{
		std::string action;
		std::uint64_t value = 0;
	};

	inline std::vector<receipt_t> receipts;

	inline std::vector<std::uint8_t> live_memory(std::uint32_t pid,
		std::uint64_t address, std::size_t size)
	{
		std::vector<std::uint8_t> bytes(size);
		std::uint64_t state = address ^ (static_cast<std::uint64_t>(pid) << 32) ^
			0x9E3779B97F4A7C15ULL;
		for (std::size_t index = 0; index < bytes.size(); ++index) {
			state ^= state >> 12;
			state ^= state << 25;
			state ^= state >> 27;
			bytes[index] = static_cast<std::uint8_t>((state * 0x2545F4914F6CDD1DULL) >> 56);
		}
		if (bytes.size() >= 10) {
			bytes[0] = 0x48;
			bytes[1] = 0x89;
			bytes[2] = 0x5C;
			bytes[3] = 0x24;
			bytes[4] = 0x08;
			bytes[5] = 0x57;
			bytes[6] = 0x48;
			bytes[7] = 0x83;
			bytes[8] = 0xEC;
			bytes[9] = 0x20;
		}
		receipts.push_back({ "read_live_memory", address });
		return bytes;
	}

	inline void opened_disassembly(std::uint64_t address)
	{
		aida::ui::application_views::open_or_focus(
			aida::ui::stable_view_id_t("document.disassembly"));
		receipts.push_back({ "open_disassembly", address });
	}
}

#endif
