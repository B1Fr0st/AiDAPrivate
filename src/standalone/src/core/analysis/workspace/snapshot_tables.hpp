#pragma once

#include <cstddef>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

namespace aida::analysis {

template <typename T>
class noinit_allocator_t {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::true_type;

    constexpr noinit_allocator_t() noexcept = default;

    template <typename U>
    constexpr noinit_allocator_t(const noinit_allocator_t<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t count) {
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* pointer, std::size_t count) noexcept {
        std::allocator<T>{}.deallocate(pointer, count);
    }

    template <typename U, typename... Args>
    void construct(U* pointer, Args&&... args)
        noexcept(std::is_nothrow_constructible<U, Args...>::value) {
        if constexpr (sizeof...(Args) != 0) {
            ::new (static_cast<void*>(pointer)) U(std::forward<Args>(args)...);
        }
    }

    template <typename U>
    void destroy(U* pointer) noexcept {
        pointer->~U();
    }

    template <typename U>
    struct rebind {
        using other = noinit_allocator_t<U>;
    };
};

template <typename T, typename U>
constexpr bool operator==(const noinit_allocator_t<T>&,
                          const noinit_allocator_t<U>&) noexcept {
    return true;
}

template <typename T, typename U>
constexpr bool operator!=(const noinit_allocator_t<T>&,
                          const noinit_allocator_t<U>&) noexcept {
    return false;
}

inline constexpr bool snapshot_table_noinit_stage_v = false;

template <typename T>
using snapshot_table_t = std::conditional_t<snapshot_table_noinit_stage_v,
                                            std::vector<T, noinit_allocator_t<T>>,
                                            std::vector<T>>;

template <typename T>
constexpr bool snapshot_table_noinit_safe_v =
    std::is_trivially_copyable<T>::value && std::is_trivially_destructible<T>::value &&
    std::is_standard_layout<T>::value;

template <typename T, typename Allocator>
void reserve_exact(std::vector<T, Allocator>& table, std::size_t count) {
    if (table.capacity() < count)
        table.reserve(count);
}

template <typename T, typename Allocator>
void resize_uninitialized(std::vector<T, Allocator>& table, std::size_t count) {
    if (table.capacity() < count)
        table.reserve(count);
    table.resize(count);
}

}
