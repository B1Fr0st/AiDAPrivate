#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4005 4244 4267 4146 4996 4458 4457 4100 4127 4389)
#endif

#include "aida_load_image.hpp"
#include "translate.hh"
#include "../zydis_disasm.hpp"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../ghidra_decompiler.hpp"

namespace aida_ghidra {

void load_image_t::add_region(uint64_t start_va, std::vector<uint8_t>&& bytes)
{
	region_t r;
	r.start_va = start_va;
	r.data = std::move(bytes);
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
}

void load_image_t::loadFill(ghidra::uint1* ptr, ghidra::int4 size, const ghidra::Address& addr)
{
	if (cancel_flag_ && cancel_flag_->load(std::memory_order_acquire))
		throw ghidra::LowlevelError("decompile cancelled");

	std::memset(ptr, 0, static_cast<size_t>(size));

	uint64_t offset = addr.getOffset();

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

			if (file_ && file_->loaded) {
				size_t remaining = static_cast<size_t>(size) - to_copy;
				std::vector<uint8_t> tail;
				if (static_analysis::read_bytes_from_pe(*file_, offset + to_copy, remaining, tail) && !tail.empty()) {
					size_t copy_n = tail.size() < remaining ? tail.size() : remaining;
					std::memcpy(ptr + to_copy, tail.data(), copy_n);
				}
			}
			ghidra_decompiler::g_state.last_loadfill_tick_ms.store(
				static_cast<uint64_t>(::GetTickCount64()),
				std::memory_order_release);
			return;
		}
	}

	for (auto& reg : regions_) {
		if (reg.data.empty())
			continue;
		uint64_t reg_end = reg.start_va + reg.data.size();
		if (offset >= reg.start_va && offset < reg_end) {
			size_t buf_off = static_cast<size_t>(offset - reg.start_va);
			size_t avail = reg.data.size() - buf_off;
			size_t to_copy = static_cast<size_t>(size) < avail ? static_cast<size_t>(size) : avail;
			std::memcpy(ptr, reg.data.data() + buf_off, to_copy);
			ghidra_decompiler::g_state.last_loadfill_tick_ms.store(
				static_cast<uint64_t>(::GetTickCount64()),
				std::memory_order_release);
			return;
		}
	}

	if (file_ && file_->loaded) {
		std::vector<uint8_t> tmp;
		if (static_analysis::read_bytes_from_pe(*file_, offset, static_cast<size_t>(size), tmp) && !tmp.empty()) {
			size_t copy_n = tmp.size() < static_cast<size_t>(size) ? tmp.size() : static_cast<size_t>(size);
			std::memcpy(ptr, tmp.data(), copy_n);
		}
	}

	ghidra_decompiler::g_state.last_loadfill_tick_ms.store(
		static_cast<uint64_t>(::GetTickCount64()),
		std::memory_order_release);
}

void load_image_t::getReadonly(ghidra::RangeList& list) const
{
	if (cancel_flag_ && cancel_flag_->load(std::memory_order_acquire))
		throw ghidra::LowlevelError("decompile cancelled");

	if (!addr_space_manager_)
		return;
	if (!file_ || !file_->loaded)
		return;

	auto code_space = addr_space_manager_->getDefaultCodeSpace();
	if (!code_space)
		return;

	for (auto& sec : file_->sections) {
		if (sec.bytes.empty())
			continue;
		uint64_t start = sec.va;
		uint64_t end = sec.va + sec.bytes.size();
		if (end > start)
			list.insertRange(code_space, start, end - 1);
	}
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
