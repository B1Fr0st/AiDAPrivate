#pragma once

#include "aida_arch_map.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "../../analysis/workspace/byte_provider.hpp"
#include "../../analysis/workspace/pe_image.hpp"

#include "aida_ghidra_preamble.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4099 4244 4267 4146 4996 4458 4457 4100 4127 4389)
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

struct provider_patch_t {
	uint64_t provider_offset = 0;
	std::vector<uint8_t> bytes;
};

class load_image_t : public ghidra::LoadImage
{
public:
	load_image_t(const uint8_t* buffer,
	             size_t buffer_size,
	             uint64_t buffer_base,
	             const DisasmFile* file_fallback,
	             std::atomic<bool>* cancel_flag);
	load_image_t(std::shared_ptr<const aida::analysis::byte_provider_t> provider,
	             std::shared_ptr<const aida::analysis::pe_image_t> image,
	             uint64_t load_base,
	             std::function<bool()> cancel_check,
	             std::vector<provider_patch_t> patches = {});

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
	std::shared_ptr<const aida::analysis::byte_provider_t> provider_;
	std::shared_ptr<const aida::analysis::pe_image_t> image_;
	std::function<bool()> cancel_check_;
	std::vector<provider_patch_t> patches_;
};

}

namespace aida::analysis::ghidra_adapter {

struct ghidra_load_image_limits_t {
    std::uint64_t max_read_bytes = 4ULL * 1024ULL * 1024ULL;
    std::size_t max_mapping_records = 1U << 20;
    std::size_t max_returned_ranges = 1U << 20;
};

struct ghidra_load_range_t {
    address_t start;
    std::uint64_t size = 0;
    std::uint32_t permissions = image_permission_none;
};

struct ghidra_load_image_read_t {
    std::vector<std::uint8_t> bytes;
    std::uint64_t provider_bytes = 0;
    std::uint64_t zero_filled_bytes = 0;
};

class ghidra_load_image_t final {
public:
    static workspace_result_t<std::shared_ptr<const ghidra_load_image_t>> create(
        std::shared_ptr<const byte_provider_t> provider,
        std::shared_ptr<const workspace_image_t> image,
        ghidra_language_spec_t language,
        ghidra_adapter_revision_t revision,
        ghidra_load_image_limits_t limits = {},
        const cancellation_token_t& cancel = {});

    const workspace_image_t& image() const noexcept { return *image_; }
    const byte_provider_t& provider() const noexcept { return *provider_; }
    const ghidra_language_spec_t& language() const noexcept { return language_; }
    const ghidra_adapter_revision_t& revision() const noexcept { return revision_; }
    const ghidra_adapter_cache_key_t& cache_key() const noexcept { return cache_key_; }
    const std::vector<ghidra_load_range_t>& mapped_ranges() const noexcept {
        return mapped_ranges_;
    }
    const std::vector<ghidra_load_range_t>& readonly_ranges() const noexcept {
        return readonly_ranges_;
    }

    workspace_result_t<ghidra_load_image_read_t> read(
        const address_t& address, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<address_t> address_for_provider_offset(
        std::uint64_t provider_offset, address_space_id_t target_space,
        const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::uint64_t> provider_offset_for_address(
        const address_t& address, const cancellation_token_t& cancel = {}) const;

private:
    struct mapping_t;

    ghidra_load_image_t(std::shared_ptr<const byte_provider_t> provider,
                        std::shared_ptr<const workspace_image_t> image,
                        ghidra_language_spec_t language,
                        ghidra_adapter_revision_t revision,
                        ghidra_adapter_cache_key_t cache_key,
                        ghidra_load_image_limits_t limits,
                        std::vector<mapping_t> mappings,
                        std::vector<ghidra_load_range_t> mapped_ranges,
                        std::vector<ghidra_load_range_t> readonly_ranges);

    std::shared_ptr<const byte_provider_t> provider_;
    std::shared_ptr<const workspace_image_t> image_;
    ghidra_language_spec_t language_;
    ghidra_adapter_revision_t revision_;
    ghidra_adapter_cache_key_t cache_key_;
    ghidra_load_image_limits_t limits_;
    std::vector<mapping_t> mappings_;
    std::vector<ghidra_load_range_t> mapped_ranges_;
    std::vector<ghidra_load_range_t> readonly_ranges_;
};

}
