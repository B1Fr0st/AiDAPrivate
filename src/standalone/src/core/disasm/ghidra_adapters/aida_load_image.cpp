#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4099 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "aida_load_image.hpp"
#include "translate.hh"
#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
#include "../zydis_disasm.hpp"
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "../ghidra_decompiler.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>

#include "aida_ghidra_preamble.hpp"

namespace aida_ghidra {

void load_image_t::add_region(uint64_t start_va, std::vector<uint8_t>&& bytes)
{
	region_t r;
	r.start_va = start_va;
	r.data = std::move(bytes);
	regions_.push_back(std::move(r));
}

void load_image_t::add_region_view(uint64_t start_va, const uint8_t* view, size_t size,
                                   std::shared_ptr<const void> owner)
{
	if (!view || size == 0)
		throw ghidra::LowlevelError("isolated decompiler view region is invalid");
	region_t r;
	r.start_va = start_va;
	r.view = view;
	r.view_size = size;
	r.owner = std::move(owner);
	regions_.push_back(std::move(r));
}

load_image_t::load_image_t(const uint8_t* buffer,
                           size_t buffer_size,
                           uint64_t buffer_base,
                           const DisasmFile* file_fallback,
                           std::atomic<bool>* cancel_flag)
	: ghidra::LoadImage("aida_program"),
	  buffer_(buffer),
	  buffer_size_(buffer_size),
	  buffer_base_(buffer_base),
	  file_(file_fallback),
	  cancel_flag_(cancel_flag),
	  image_size_(buffer_size),
	  addr_space_manager_(nullptr)
{
#if defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
	if (file_fallback != nullptr)
		throw ghidra::LowlevelError("isolated native decompiler cannot access application image state");
#endif
}

#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
load_image_t::load_image_t(
    std::shared_ptr<const aida::analysis::byte_provider_t> provider,
    std::shared_ptr<const aida::analysis::pe_image_t> image,
	uint64_t load_base,
    std::function<bool()> cancel_check,
    std::vector<provider_patch_t> patches)
	: ghidra::LoadImage("aida_workspace"),
	  buffer_(nullptr),
	  buffer_size_(0),
	  buffer_base_(load_base),
	  file_(nullptr),
	  cancel_flag_(nullptr),
	  image_size_(image ? image->image_size() : (provider ? provider->size() : 0)),
	  addr_space_manager_(nullptr),
	  provider_(std::move(provider)),
	  image_(std::move(image)),
	  cancel_check_(std::move(cancel_check)),
	  patches_(std::move(patches))
{
	std::sort(patches_.begin(), patches_.end(),
		[](const provider_patch_t& left, const provider_patch_t& right) {
			return left.provider_offset < right.provider_offset;
	});
}

load_image_t::load_image_t(
	std::shared_ptr<const aida::analysis::ghidra_adapter::ghidra_load_image_t> image,
	aida::analysis::address_space_id_t address_space,
	std::function<bool()> cancel_check)
	: ghidra::LoadImage("aida_normalized_workspace"),
	  buffer_(nullptr),
	  buffer_size_(0),
	  buffer_base_(0),
	  file_(nullptr),
	  cancel_flag_(nullptr),
	  image_size_(image ? image->image().image_size : 0),
	  addr_space_manager_(nullptr),
	  cancel_check_(std::move(cancel_check)),
	  normalized_image_(std::move(image)),
	  normalized_address_space_(address_space)
{
}
#endif

void load_image_t::loadFill(ghidra::uint1* ptr, ghidra::int4 size, const ghidra::Address& addr)
{
	if (!ptr || size <= 0)
		return;
	if (cancel_flag_ && cancel_flag_->load(std::memory_order_acquire))
		throw ghidra::LowlevelError("decompile cancelled");
	if (cancel_check_ && cancel_check_())
		throw ghidra::LowlevelError("decompile cancelled");

	std::memset(ptr, 0, static_cast<size_t>(size));

	uint64_t offset = addr.getOffset();
#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
	if (normalized_image_) {
		const auto& image = normalized_image_->image();
		const uint64_t image_begin =
			(normalized_address_space_ == aida::analysis::address_space_id_t::virtual_address ||
			 normalized_address_space_ == aida::analysis::address_space_id_t::live_virtual)
				? image.image_base : 0;
		if (image.image_size > UINT64_MAX - image_begin)
			throw ghidra::LowlevelError("normalized workspace image address range overflow");
		const uint64_t image_end = image_begin + image.image_size;
		const uint64_t request_size = static_cast<uint64_t>(size);
		const uint64_t request_end = request_size > UINT64_MAX - offset
			? UINT64_MAX : offset + request_size;
		const uint64_t read_begin = (std::max)(offset, image_begin);
		const uint64_t read_end = (std::min)(request_end, image_end);
		if (offset < image_begin || read_begin >= read_end)
			throw ghidra::DataUnavailError("normalized workspace image address is not mapped");
		uint64_t cursor = read_begin;
		while (cursor < read_end) {
			if (cancel_check_ && cancel_check_())
				throw ghidra::LowlevelError("decompile cancelled");
			const uint64_t amount = (std::min)(normalized_image_->max_read_bytes(),
				read_end - cursor);
			aida::analysis::address_t source;
			source.space = normalized_address_space_;
			source.value = cursor;
			source.architecture = image.architecture;
			source.mode = image.architecture_mode;
			auto read = normalized_image_->read(source, amount);
			if (!read) {
				if (read.error().code == aida::analysis::workspace_error_code_t::cancelled ||
					read.error().code == aida::analysis::workspace_error_code_t::deadline_exceeded)
					throw ghidra::LowlevelError("decompile cancelled");
				throw ghidra::LowlevelError(std::string("normalized workspace image read failed: ") +
					read.error().stable_code() + ":" + read.error().message);
			}
			if (read.value().bytes.size() != static_cast<std::size_t>(amount))
				throw ghidra::LowlevelError("normalized workspace image returned a truncated read");
			std::memcpy(ptr + static_cast<std::size_t>(cursor - offset),
				read.value().bytes.data(), read.value().bytes.size());
			cursor += amount;
		}
		ghidra_decompiler::g_state.last_loadfill_tick_ms.store(
			static_cast<uint64_t>(::GetTickCount64()), std::memory_order_release);
		return;
	}
	if (provider_) {
		auto read_and_patch = [&](uint64_t provider_offset, ghidra::uint1* destination,
			size_t amount) {
			auto read = provider_->read_exact(provider_offset, destination,
				static_cast<std::uint64_t>(amount));
			if (read) {
				const uint64_t read_begin = provider_offset;
				const uint64_t read_size = static_cast<uint64_t>(amount);
				const uint64_t read_end = read_begin <= UINT64_MAX - read_size
					? read_begin + read_size : UINT64_MAX;
				for (const auto& patch : patches_) {
					if (patch.bytes.empty())
						continue;
					if (patch.provider_offset >= read_end)
						break;
					const uint64_t patch_size = static_cast<uint64_t>(patch.bytes.size());
					const uint64_t patch_end = patch.provider_offset <= UINT64_MAX - patch_size
						? patch.provider_offset + patch_size : UINT64_MAX;
					if (patch_end <= read_begin)
						continue;
					const uint64_t overlap_begin = (std::max)(read_begin, patch.provider_offset);
					const uint64_t overlap_end = (std::min)(read_end, patch_end);
					if (overlap_end <= overlap_begin)
						continue;
					std::memcpy(destination + static_cast<size_t>(overlap_begin - read_begin),
						patch.bytes.data() + static_cast<size_t>(overlap_begin - patch.provider_offset),
						static_cast<size_t>(overlap_end - overlap_begin));
				}
				return true;
			}
			if (read.error().code == aida::analysis::workspace_error_code_t::cancelled ||
				read.error().code == aida::analysis::workspace_error_code_t::deadline_exceeded)
				throw ghidra::LowlevelError("decompile cancelled");
			throw ghidra::LowlevelError(
				std::string("workspace byte provider read failed: ") +
				read.error().stable_code());
		};

		if (image_) {
			if (offset < buffer_base_)
				return;
			const uint64_t rva = offset - buffer_base_;
			if (rva >= image_->image_size())
				return;
			size_t cursor = 0;
			while (cursor < static_cast<size_t>(size)) {
				if (cancel_check_ && cancel_check_())
					throw ghidra::LowlevelError("decompile cancelled");
				if (static_cast<std::uint64_t>(cursor) > UINT64_MAX - rva)
					throw ghidra::LowlevelError("workspace image address overflow");
				const uint64_t current_rva = rva + static_cast<std::uint64_t>(cursor);
				const size_t remaining = static_cast<size_t>(size) - cursor;
				uint64_t provider_offset = 0;
				size_t readable = 0;
				if (current_rva < image_->headers_size()) {
					provider_offset = current_rva;
					readable = static_cast<size_t>((std::min<uint64_t>)(
						remaining, image_->headers_size() - current_rva));
				} else if (const auto* section = image_->section_for_rva(current_rva, 1)) {
					const uint64_t delta = current_rva - section->virtual_address;
					if (delta < section->raw_size) {
						if (delta > UINT64_MAX - section->raw_offset)
							throw ghidra::LowlevelError("workspace section offset overflow");
						provider_offset = section->raw_offset + delta;
						readable = static_cast<size_t>((std::min<uint64_t>)(
							remaining, section->raw_size - delta));
					}
				}
				if (readable != 0) {
					read_and_patch(provider_offset, ptr + cursor, readable);
					cursor += readable;
				} else {
					++cursor;
				}
			}
			return;
		}
		if (offset >= buffer_base_) {
			const uint64_t provider_offset = offset - buffer_base_;
			if (provider_offset < provider_->size()) {
				const size_t readable = static_cast<size_t>((std::min<uint64_t>)(
					static_cast<uint64_t>(size), provider_->size() - provider_offset));
				read_and_patch(provider_offset, ptr, readable);
			}
		}
		return;
	}
#endif

	if (buffer_ && buffer_size_ > 0) {
		if (offset >= buffer_base_ && offset < buffer_base_ + buffer_size_) {
			size_t buf_off = static_cast<size_t>(offset - buffer_base_);
			size_t avail = buffer_size_ - buf_off;
			size_t to_copy = static_cast<size_t>(size) < avail ? static_cast<size_t>(size) : avail;
			std::memcpy(ptr, buffer_ + buf_off, to_copy);

			if (to_copy >= static_cast<size_t>(size)) {
				ghidra_decompiler::g_state.last_loadfill_tick_ms.store(
					static_cast<uint64_t>(::GetTickCount64()),
					std::memory_order_release);
				return;
			}

#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
			if (file_ && file_->loaded) {
				size_t remaining = static_cast<size_t>(size) - to_copy;
				std::vector<uint8_t> tail;
				if (static_analysis::read_bytes_from_pe(*file_, offset + to_copy, remaining, tail) && !tail.empty()) {
					size_t copy_n = tail.size() < remaining ? tail.size() : remaining;
					std::memcpy(ptr + to_copy, tail.data(), copy_n);
				}
			}
#endif
			ghidra_decompiler::g_state.last_loadfill_tick_ms.store(
				static_cast<uint64_t>(::GetTickCount64()),
				std::memory_order_release);
			return;
		}
	}

	for (auto& reg : regions_) {
		const uint8_t* reg_data = reg.effective_data();
		const size_t reg_size = reg.effective_size();
		if (!reg_data || reg_size == 0)
			continue;
		if (reg_size > UINT64_MAX - reg.start_va)
			throw ghidra::LowlevelError("isolated decompiler region address overflow");
		uint64_t reg_end = reg.start_va + reg_size;
		if (offset >= reg.start_va && offset < reg_end) {
			size_t buf_off = static_cast<size_t>(offset - reg.start_va);
			size_t avail = reg_size - buf_off;
			size_t to_copy = static_cast<size_t>(size) < avail ? static_cast<size_t>(size) : avail;
			std::memcpy(ptr, reg_data + buf_off, to_copy);
			ghidra_decompiler::g_state.last_loadfill_tick_ms.store(
				static_cast<uint64_t>(::GetTickCount64()),
				std::memory_order_release);
			return;
		}
	}

#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
	if (file_ && file_->loaded) {
		std::vector<uint8_t> tmp;
		if (static_analysis::read_bytes_from_pe(*file_, offset, static_cast<size_t>(size), tmp) && !tmp.empty()) {
			size_t copy_n = tmp.size() < static_cast<size_t>(size) ? tmp.size() : static_cast<size_t>(size);
			std::memcpy(ptr, tmp.data(), copy_n);
		}
	}
#endif

#if defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
	throw ghidra::DataUnavailError("isolated native decompiler address is not captured");
#endif

	ghidra_decompiler::g_state.last_loadfill_tick_ms.store(
		static_cast<uint64_t>(::GetTickCount64()),
		std::memory_order_release);
}

void load_image_t::getReadonly(ghidra::RangeList& list) const
{
#if defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
	(void)list;
#endif
	if (cancel_flag_ && cancel_flag_->load(std::memory_order_acquire))
		throw ghidra::LowlevelError("decompile cancelled");
	if (cancel_check_ && cancel_check_())
		throw ghidra::LowlevelError("decompile cancelled");

	if (!addr_space_manager_)
		return;
	auto code_space = addr_space_manager_->getDefaultCodeSpace();
	if (!code_space)
		return;

#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)
	if (normalized_image_) {
		const auto& image = normalized_image_->image();
		for (const auto& range : normalized_image_->readonly_ranges()) {
			if (range.size == 0)
				continue;
			uint64_t start = range.start.value;
			if (normalized_address_space_ == aida::analysis::address_space_id_t::virtual_address ||
				normalized_address_space_ == aida::analysis::address_space_id_t::live_virtual) {
				if (start > UINT64_MAX - image.image_base)
					throw ghidra::LowlevelError("normalized workspace readonly range start overflow");
				start += image.image_base;
			}
			if (range.size > UINT64_MAX - start)
				throw ghidra::LowlevelError("normalized workspace readonly range end overflow");
			const uint64_t end = start + range.size;
			if (end > start)
				list.insertRange(code_space, start, end - 1);
		}
		return;
	}
	if (image_) {
		for (const auto& section : image_->sections()) {
			if (section.virtual_size == 0 || section.writable)
				continue;
			if (section.virtual_address > UINT64_MAX - buffer_base_)
				throw ghidra::LowlevelError("workspace readonly range start overflow");
			const uint64_t start = buffer_base_ + section.virtual_address;
			if (section.virtual_size > UINT64_MAX - start)
				throw ghidra::LowlevelError("workspace readonly range end overflow");
			const uint64_t end = start + section.virtual_size;
			if (end > start)
				list.insertRange(code_space, start, end - 1);
		}
		return;
	}
	if (!file_ || !file_->loaded)
		return;
	for (auto& sec : file_->sections) {
		if (sec.bytes.empty())
			continue;
		uint64_t start = sec.va;
		uint64_t end = sec.va + sec.bytes.size();
		if (end > start)
			list.insertRange(code_space, start, end - 1);
	}
#endif
}

std::string load_image_t::getArchType() const
{
	return "aida";
}

void load_image_t::adjustVma(long )
{
	throw ghidra::LowlevelError("Cannot adjust AiDA virtual memory");
}

}

#if !defined(AIDA_C03_ISOLATED_NATIVE_DECOMPILER_WORKER)

namespace aida::analysis::ghidra_adapter {

struct ghidra_load_image_t::mapping_t {
    std::uint64_t provider_offset = 0;
    std::uint64_t rva = 0;
    std::uint64_t size = 0;
    std::uint32_t permissions = image_permission_none;
};

namespace {

workspace_result_t<void> stopped(const cancellation_token_t& cancel,
                                 const char* phase) {
    if (!cancel.stop_requested())
        return workspace_result_t<void>::success();
    auto error = make_workspace_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                  : workspace_error_code_t::cancelled,
        cancel.deadline_exceeded() ? "Ghidra load-image deadline exceeded"
                                  : "Ghidra load-image operation cancelled",
        phase);
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return workspace_result_t<void>::failure(std::move(error));
}

workspace_result_t<void> validate_limits(const ghidra_load_image_limits_t& limits) {
    if (limits.max_read_bytes == 0 ||
        limits.max_read_bytes > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()) ||
        limits.max_mapping_records == 0 || limits.max_returned_ranges == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "Ghidra load-image limits are invalid", "ghidra.load_image.create"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_language(const workspace_image_t& image,
                                           const ghidra_language_spec_t& language,
                                           const cancellation_token_t& cancel) {
    auto expected = resolve_ghidra_language(image, cancel);
    if (!expected)
        return workspace_result_t<void>::failure(expected.error());
    if (expected.value().family != language.family ||
        expected.value().language_id != language.language_id ||
        expected.value().compiler_spec_id != language.compiler_spec_id ||
        expected.value().language_root != language.language_root) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "Ghidra load-image language does not match the normalized workspace image",
            "ghidra.load_image.create"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_revision(const workspace_image_t& image,
                                           const ghidra_adapter_revision_t& revision) {
    if (revision.binary_id.empty() || revision.load_profile_hash.empty() ||
        revision.generation == 0 || image.workspace_binary_id.empty() ||
        image.workspace_binary_id != revision.binary_id) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "Ghidra load-image revision does not match the normalized workspace image",
            "ghidra.load_image.create"));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::uint64_t> mapping_rva(const workspace_image_t& image,
                                              const image_address_mapping_t& mapping) {
    switch (mapping.target_space) {
    case address_space_id_t::relative_virtual:
        return workspace_result_t<std::uint64_t>::success(mapping.target_start);
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        if (mapping.target_start < image.image_base)
            break;
        return workspace_result_t<std::uint64_t>::success(
            mapping.target_start - image.image_base);
    default:
        break;
    }
    return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
        workspace_error_code_t::unsupported_address_space,
        "Ghidra load-image mapping target is not an image address space",
        "ghidra.load_image.mapping"));
}

workspace_result_t<std::uint64_t> address_rva(const workspace_image_t& image,
                                              const address_t& address,
                                              std::uint64_t size) {
    if (address.architecture != image.architecture ||
        address.mode != image.architecture_mode) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "Ghidra load-image address does not match the workspace architecture and mode",
            "ghidra.load_image.address"));
    }
    std::uint64_t rva = 0;
    switch (address.space) {
    case address_space_id_t::relative_virtual:
        rva = address.value;
        break;
    case address_space_id_t::virtual_address:
    case address_space_id_t::live_virtual:
        if (address.value < image.image_base)
            return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
                workspace_error_code_t::out_of_range,
                "Ghidra load-image address precedes the workspace image base",
                "ghidra.load_image.address"));
        rva = address.value - image.image_base;
        break;
    default:
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_address_space,
            "Ghidra load-image address is not a virtual image address",
            "ghidra.load_image.address"));
    }
    if (!workspace_image_span_within(rva, size, image.image_size)) {
        auto error = make_workspace_error(workspace_error_code_t::out_of_range,
            "Ghidra load-image read exceeds the normalized image", "ghidra.load_image.address");
        error.address = address;
        error.size = size;
        return workspace_result_t<std::uint64_t>::failure(std::move(error));
    }
    return workspace_result_t<std::uint64_t>::success(rva);
}

address_t make_address(const workspace_image_t& image, address_space_id_t space,
                       std::uint64_t rva_or_offset) {
    address_t result;
    result.space = space;
    result.architecture = image.architecture;
    result.mode = image.architecture_mode;
    if (space == address_space_id_t::virtual_address || space == address_space_id_t::live_virtual)
        result.value = image.image_base + rva_or_offset;
    else
        result.value = rva_or_offset;
    return result;
}

}

ghidra_load_image_t::ghidra_load_image_t(
    std::shared_ptr<const byte_provider_t> provider,
    std::shared_ptr<const workspace_image_t> image,
    ghidra_language_spec_t language,
    ghidra_adapter_revision_t revision,
    ghidra_adapter_cache_key_t cache_key,
    ghidra_load_image_limits_t limits,
    std::vector<mapping_t> mappings,
    std::vector<ghidra_load_range_t> mapped_ranges,
    std::vector<ghidra_load_range_t> readonly_ranges)
    : provider_(std::move(provider)),
      image_(std::move(image)),
      language_(std::move(language)),
      revision_(std::move(revision)),
      cache_key_(std::move(cache_key)),
      limits_(limits),
      mappings_(std::move(mappings)),
      mapped_ranges_(std::move(mapped_ranges)),
      readonly_ranges_(std::move(readonly_ranges)) {}

workspace_result_t<std::shared_ptr<const ghidra_load_image_t>> ghidra_load_image_t::create(
    std::shared_ptr<const byte_provider_t> provider,
    std::shared_ptr<const workspace_image_t> image,
    ghidra_language_spec_t language,
    ghidra_adapter_revision_t revision,
    ghidra_load_image_limits_t limits,
    const cancellation_token_t& cancel) {
    auto stop = stopped(cancel, "ghidra.load_image.create");
    if (!stop)
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(stop.error());
    if (!provider || !image) {
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "Ghidra load-image requires a provider and normalized image",
                "ghidra.load_image.create"));
    }
    auto limits_valid = validate_limits(limits);
    if (!limits_valid)
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            limits_valid.error());
    auto image_valid = validate_workspace_image(*image, {}, true, cancel);
    if (!image_valid)
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            image_valid.error());
    if (image->image_base > (std::numeric_limits<std::uint64_t>::max)() - image->image_size) {
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::malformed_image,
                "normalized image virtual range overflows the Ghidra load-image address domain",
                "ghidra.load_image.create"));
    }
    if (provider->size() != image->provider_size) {
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::provider_binding_mismatch,
                "Ghidra load-image provider size does not match the normalized image binding",
                "ghidra.load_image.create"));
    }
    auto language_valid = validate_language(*image, language, cancel);
    if (!language_valid)
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            language_valid.error());
    auto revision_valid = validate_revision(*image, revision);
    if (!revision_valid)
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            revision_valid.error());
    auto cache_key = make_ghidra_adapter_cache_key(revision, language, cancel);
    if (!cache_key)
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            cache_key.error());
    if (image->address_mappings.size() > limits.max_mapping_records) {
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "normalized image address mappings exceed the Ghidra load-image limit",
                "ghidra.load_image.create"));
    }

    try {
        std::vector<mapping_t> mappings;
        mappings.reserve(image->address_mappings.size());
        for (const auto& mapping : image->address_mappings) {
            stop = stopped(cancel, "ghidra.load_image.create");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(stop.error());
            if (mapping.source_space != address_space_id_t::file_offset)
                continue;
            auto rva = mapping_rva(*image, mapping);
            if (!rva)
                return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
                    rva.error());
            if (!workspace_image_span_within(mapping.source_start, mapping.size, provider->size()) ||
                !workspace_image_span_within(rva.value(), mapping.size, image->image_size)) {
                return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
                    make_workspace_error(workspace_error_code_t::malformed_image,
                        "Ghidra load-image mapping exceeds its bound image or provider",
                        "ghidra.load_image.create"));
            }
            mappings.push_back(mapping_t{mapping.source_start, rva.value(), mapping.size,
                                         mapping.permissions});
        }
        if (mappings.empty()) {
            return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
                make_workspace_error(workspace_error_code_t::malformed_image,
                    "normalized image has no provider-backed Ghidra load mappings",
                    "ghidra.load_image.create"));
        }
        std::sort(mappings.begin(), mappings.end(), [](const mapping_t& lhs, const mapping_t& rhs) {
            if (lhs.rva != rhs.rva)
                return lhs.rva < rhs.rva;
            if (lhs.size != rhs.size)
                return lhs.size < rhs.size;
            return lhs.provider_offset < rhs.provider_offset;
        });
        for (std::size_t index = 1; index < mappings.size(); ++index) {
            stop = stopped(cancel, "ghidra.load_image.create");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(stop.error());
            const mapping_t& prior = mappings[index - 1];
            const mapping_t& current = mappings[index];
            if (current.rva < prior.rva + prior.size) {
                return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "normalized image contains ambiguous overlapping Ghidra load mappings",
                        "ghidra.load_image.create"));
            }
        }
        std::vector<mapping_t> provider_order = mappings;
        std::sort(provider_order.begin(), provider_order.end(),
            [](const mapping_t& lhs, const mapping_t& rhs) {
                if (lhs.provider_offset != rhs.provider_offset)
                    return lhs.provider_offset < rhs.provider_offset;
                if (lhs.size != rhs.size)
                    return lhs.size < rhs.size;
                return lhs.rva < rhs.rva;
            });
        for (std::size_t index = 1; index < provider_order.size(); ++index) {
            stop = stopped(cancel, "ghidra.load_image.create");
            if (!stop)
                return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(stop.error());
            const mapping_t& prior = provider_order[index - 1];
            const mapping_t& current = provider_order[index];
            if (current.provider_offset < prior.provider_offset + prior.size) {
                return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "normalized image contains ambiguous provider-backed Ghidra load mappings",
                        "ghidra.load_image.create"));
            }
        }
        if (mappings.size() > limits.max_returned_ranges) {
            return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "Ghidra load-image mapped range count exceeds its limit",
                    "ghidra.load_image.create"));
        }
        std::vector<ghidra_load_range_t> mapped_ranges;
        std::vector<ghidra_load_range_t> readonly_ranges;
        mapped_ranges.reserve(mappings.size());
        readonly_ranges.reserve(mappings.size());
        for (const auto& mapping : mappings) {
            ghidra_load_range_t range;
            range.start = make_address(*image, address_space_id_t::relative_virtual, mapping.rva);
            range.size = mapping.size;
            range.permissions = mapping.permissions;
            mapped_ranges.push_back(range);
            if ((mapping.permissions & image_permission_write) == 0)
                readonly_ranges.push_back(range);
        }
        auto adapter = std::shared_ptr<const ghidra_load_image_t>(new ghidra_load_image_t(
            std::move(provider), std::move(image), std::move(language), std::move(revision),
            cache_key.take_value(), limits, std::move(mappings), std::move(mapped_ranges),
            std::move(readonly_ranges)));
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::success(
            std::move(adapter));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const ghidra_load_image_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "Ghidra load-image allocation exceeds its budget", "ghidra.load_image.create"));
    }
}

workspace_result_t<ghidra_load_image_read_t> ghidra_load_image_t::read(
    const address_t& address, std::uint64_t size, const cancellation_token_t& cancel) const {
    auto stop = stopped(cancel, "ghidra.load_image.read");
    if (!stop)
        return workspace_result_t<ghidra_load_image_read_t>::failure(stop.error());
    if (size > limits_.max_read_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
            "Ghidra load-image read exceeds its bounded window", "ghidra.load_image.read");
        error.address = address;
        error.size = size;
        return workspace_result_t<ghidra_load_image_read_t>::failure(std::move(error));
    }
    if (size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return workspace_result_t<ghidra_load_image_read_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "Ghidra load-image read cannot be represented by the host allocator",
            "ghidra.load_image.read"));
    }
    if (address.architecture != image_->architecture || address.mode != image_->architecture_mode) {
        return workspace_result_t<ghidra_load_image_read_t>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "Ghidra load-image read address does not match the workspace target",
            "ghidra.load_image.read"));
    }
    try {
        ghidra_load_image_read_t result;
        result.bytes.resize(static_cast<std::size_t>(size), 0);
        if (address.space == address_space_id_t::file_offset) {
            if (!workspace_image_span_within(address.value, size, provider_->size())) {
                return workspace_result_t<ghidra_load_image_read_t>::failure(make_workspace_error(
                    workspace_error_code_t::out_of_range,
                    "Ghidra load-image file read exceeds the provider",
                    "ghidra.load_image.read"));
            }
            auto read = provider_->read_exact(address.value, result.bytes.data(), size, cancel);
            if (!read)
                return workspace_result_t<ghidra_load_image_read_t>::failure(read.error());
            result.provider_bytes = size;
            return workspace_result_t<ghidra_load_image_read_t>::success(std::move(result));
        }
        auto rva = address_rva(*image_, address, size);
        if (!rva)
            return workspace_result_t<ghidra_load_image_read_t>::failure(rva.error());
        std::uint64_t cursor = rva.value();
        std::uint64_t remaining = size;
        while (remaining != 0) {
            stop = stopped(cancel, "ghidra.load_image.read");
            if (!stop)
                return workspace_result_t<ghidra_load_image_read_t>::failure(stop.error());
            const auto next = std::upper_bound(mappings_.begin(), mappings_.end(), cursor,
                [](std::uint64_t value, const mapping_t& mapping) { return value < mapping.rva; });
            const mapping_t* active = nullptr;
            if (next != mappings_.begin()) {
                const mapping_t& candidate = *(next - 1);
                if (cursor >= candidate.rva && cursor - candidate.rva < candidate.size)
                    active = &candidate;
            }
            std::uint64_t amount = remaining;
            if (active) {
                amount = (std::min)(amount, active->size - (cursor - active->rva));
                const std::uint64_t provider_offset = active->provider_offset + (cursor - active->rva);
                auto read = provider_->read_exact(provider_offset,
                    result.bytes.data() + static_cast<std::size_t>(cursor - rva.value()), amount,
                    cancel);
                if (!read)
                    return workspace_result_t<ghidra_load_image_read_t>::failure(read.error());
                result.provider_bytes += amount;
            } else {
                if (next != mappings_.end() && next->rva > cursor)
                    amount = (std::min)(amount, next->rva - cursor);
                result.zero_filled_bytes += amount;
            }
            cursor += amount;
            remaining -= amount;
        }
        return workspace_result_t<ghidra_load_image_read_t>::success(std::move(result));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<ghidra_load_image_read_t>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "Ghidra load-image read allocation exceeds its bounded window",
            "ghidra.load_image.read"));
    }
}

workspace_result_t<address_t> ghidra_load_image_t::address_for_provider_offset(
    std::uint64_t provider_offset, address_space_id_t target_space,
    const cancellation_token_t& cancel) const {
    auto stop = stopped(cancel, "ghidra.load_image.translate");
    if (!stop)
        return workspace_result_t<address_t>::failure(stop.error());
    if (provider_offset >= provider_->size()) {
        return workspace_result_t<address_t>::failure(make_workspace_error(
            workspace_error_code_t::out_of_range,
            "Ghidra load-image provider offset exceeds the provider",
            "ghidra.load_image.translate"));
    }
    if (target_space == address_space_id_t::file_offset)
        return workspace_result_t<address_t>::success(
            make_address(*image_, target_space, provider_offset));
    if (target_space != address_space_id_t::relative_virtual &&
        target_space != address_space_id_t::virtual_address &&
        target_space != address_space_id_t::live_virtual) {
        return workspace_result_t<address_t>::failure(make_workspace_error(
            workspace_error_code_t::unsupported_address_space,
            "Ghidra load-image translation target space is unsupported",
            "ghidra.load_image.translate"));
    }
    std::size_t inspected = 0;
    for (const auto& mapping : mappings_) {
        if ((inspected++ & 255U) == 0) {
            stop = stopped(cancel, "ghidra.load_image.translate");
            if (!stop)
                return workspace_result_t<address_t>::failure(stop.error());
        }
        if (provider_offset >= mapping.provider_offset &&
            provider_offset - mapping.provider_offset < mapping.size) {
            return workspace_result_t<address_t>::success(make_address(*image_, target_space,
                mapping.rva + (provider_offset - mapping.provider_offset)));
        }
    }
    return workspace_result_t<address_t>::failure(make_workspace_error(
        workspace_error_code_t::out_of_range,
        "Ghidra load-image provider offset is not mapped into the normalized image",
        "ghidra.load_image.translate"));
}

workspace_result_t<std::uint64_t> ghidra_load_image_t::provider_offset_for_address(
    const address_t& address, const cancellation_token_t& cancel) const {
    auto stop = stopped(cancel, "ghidra.load_image.translate");
    if (!stop)
        return workspace_result_t<std::uint64_t>::failure(stop.error());
    if (address.architecture != image_->architecture || address.mode != image_->architecture_mode) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "Ghidra load-image address does not match the workspace target",
            "ghidra.load_image.translate"));
    }
    if (address.space == address_space_id_t::file_offset) {
        if (address.value >= provider_->size())
            return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
                workspace_error_code_t::out_of_range,
                "Ghidra load-image file offset exceeds the provider",
                "ghidra.load_image.translate"));
        return workspace_result_t<std::uint64_t>::success(address.value);
    }
    auto rva = address_rva(*image_, address, 1);
    if (!rva)
        return workspace_result_t<std::uint64_t>::failure(rva.error());
    const auto next = std::upper_bound(mappings_.begin(), mappings_.end(), rva.value(),
        [](std::uint64_t value, const mapping_t& mapping) { return value < mapping.rva; });
    if (next != mappings_.begin()) {
        const mapping_t& mapping = *(next - 1);
        if (rva.value() >= mapping.rva && rva.value() - mapping.rva < mapping.size)
            return workspace_result_t<std::uint64_t>::success(
                mapping.provider_offset + (rva.value() - mapping.rva));
    }
    return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
        workspace_error_code_t::out_of_range,
        "Ghidra load-image address is not backed by provider bytes",
        "ghidra.load_image.translate"));
}

}

#endif
