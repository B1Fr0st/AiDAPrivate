#pragma once

#include "aida_ghidra_preamble.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "loadimage.hh"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

struct DisasmFile;

namespace aida_ghidra {

struct region_t {
	uint64_t start_va = 0;
	std::vector<uint8_t> data;
};

class load_image_t : public ghidra::LoadImage
{
public:
	load_image_t(const uint8_t* buffer,
	             size_t buffer_size,
	             uint64_t buffer_base,
	             const DisasmFile* file_fallback,
	             std::atomic<bool>* cancel_flag);

	void loadFill(ghidra::uint1* ptr, ghidra::int4 size, const ghidra::Address& addr) override;
	void getReadonly(ghidra::RangeList& list) const override;
	std::string getArchType() const override;
	void adjustVma(long adjust) override;

	void set_image_size(uint64_t size) { image_size_ = size; }
	uint64_t image_size() const { return image_size_; }

	void set_address_space_manager(ghidra::AddrSpaceManager* mgr) { addr_space_manager_ = mgr; }

	void add_region(uint64_t start_va, std::vector<uint8_t>&& bytes);

private:
	const uint8_t* buffer_;
	size_t buffer_size_;
	uint64_t buffer_base_;
	const DisasmFile* file_;
	std::atomic<bool>* cancel_flag_;
	uint64_t image_size_;
	ghidra::AddrSpaceManager* addr_space_manager_;
	std::vector<region_t> regions_;
};

}
