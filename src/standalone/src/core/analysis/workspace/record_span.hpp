#pragma once

#include <cstddef>

namespace aida::analysis {

template <typename T>
class record_span_t final {
public:
	using element_type = T;
	using pointer = const T*;
	using const_iterator = const T*;

	constexpr record_span_t() noexcept = default;
	constexpr record_span_t(const T* data, std::size_t size) noexcept : data_(data), size_(size) {}

	constexpr const T* data() const noexcept { return data_; }
	constexpr std::size_t size() const noexcept { return size_; }
	constexpr bool empty() const noexcept { return size_ == 0; }

	constexpr const T* begin() const noexcept { return data_; }
	constexpr const T* end() const noexcept { return data_ + size_; }

	constexpr const T& operator[](std::size_t index) const noexcept { return data_[index]; }
	constexpr const T& front() const noexcept { return data_[0]; }
	constexpr const T& back() const noexcept { return data_[size_ - 1]; }

private:
	const T* data_ = nullptr;
	std::size_t size_ = 0;
};

}
