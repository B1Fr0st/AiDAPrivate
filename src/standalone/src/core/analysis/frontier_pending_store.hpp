#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <new>
#include <utility>
#include <vector>

namespace aida::analysis {

class frontier_pending_arena_t final {
public:
    explicit frontier_pending_arena_t(std::size_t chunk_bytes = 262'144)
        : chunk_bytes_((std::max)(chunk_bytes, k_minimum_chunk_bytes)) {}

    frontier_pending_arena_t(const frontier_pending_arena_t&) = delete;
    frontier_pending_arena_t& operator=(const frontier_pending_arena_t&) = delete;
    frontier_pending_arena_t(frontier_pending_arena_t&&) = delete;
    frontier_pending_arena_t& operator=(frontier_pending_arena_t&&) = delete;

    ~frontier_pending_arena_t()
    {
        for (const auto& chunk : chunks_)
            ::operator delete(chunk.memory);
    }

    void* allocate_node(std::size_t bytes)
    {
        const std::size_t slot = normalize_slot(bytes);
        if (slot_size_ == 0)
            slot_size_ = slot;
        if (slot != slot_size_)
            return ::operator new(bytes);
        if (free_head_ != nullptr) {
            void* block = free_head_;
            free_head_ = *static_cast<void**>(block);
            return block;
        }
        if (cursor_ + slot > chunk_end_) {
            const std::size_t extent = (std::max)(chunk_bytes_, slot);
            void* memory = ::operator new(extent);
            chunks_.push_back(chunk_t{memory, extent});
            chunk_begin_ = static_cast<std::uint8_t*>(memory);
            cursor_ = 0;
            chunk_end_ = extent;
        }
        void* block = chunk_begin_ + cursor_;
        cursor_ += slot;
        return block;
    }

    void deallocate_node(void* block, std::size_t bytes) noexcept
    {
        if (block == nullptr)
            return;
        const std::size_t slot = normalize_slot(bytes);
        if (slot_size_ == 0 || slot != slot_size_) {
            ::operator delete(block);
            return;
        }
        *static_cast<void**>(block) = free_head_;
        free_head_ = block;
    }

    std::size_t allocated_chunk_bytes() const noexcept
    {
        std::size_t total = 0;
        for (const auto& chunk : chunks_)
            total += chunk.extent;
        return total;
    }

private:
    struct chunk_t final {
        void* memory = nullptr;
        std::size_t extent = 0;
    };

    static constexpr std::size_t k_minimum_chunk_bytes = 4096;

    static std::size_t normalize_slot(std::size_t bytes) noexcept
    {
        constexpr std::size_t alignment = alignof(std::max_align_t);
        const std::size_t slot = (std::max)(bytes, sizeof(void*));
        return (slot + alignment - 1) & ~(alignment - 1);
    }

    std::size_t chunk_bytes_;
    std::size_t slot_size_ = 0;
    std::vector<chunk_t> chunks_;
    std::uint8_t* chunk_begin_ = nullptr;
    std::size_t cursor_ = 0;
    std::size_t chunk_end_ = 0;
    void* free_head_ = nullptr;
};

template <typename T>
class frontier_pending_allocator_t {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_copy_assignment = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::false_type;

    template <typename U>
    struct rebind {
        using other = frontier_pending_allocator_t<U>;
    };

    frontier_pending_allocator_t() noexcept = default;

    explicit frontier_pending_allocator_t(
        std::shared_ptr<frontier_pending_arena_t> arena) noexcept
        : arena_(std::move(arena)) {}

    template <typename U>
    frontier_pending_allocator_t(
        const frontier_pending_allocator_t<U>& other) noexcept
        : arena_(other.arena_) {}

    T* allocate(std::size_t count)
    {
        if (arena_ == nullptr || count != 1)
            return static_cast<T*>(::operator new(sizeof(T) * count));
        return static_cast<T*>(arena_->allocate_node(sizeof(T)));
    }

    void deallocate(T* block, std::size_t count) noexcept
    {
        if (arena_ == nullptr || count != 1) {
            ::operator delete(block);
            return;
        }
        arena_->deallocate_node(block, sizeof(T));
    }

    template <typename U>
    bool operator==(
        const frontier_pending_allocator_t<U>& other) const noexcept
    {
        return arena_ == other.arena_;
    }

    template <typename U>
    bool operator!=(
        const frontier_pending_allocator_t<U>& other) const noexcept
    {
        return arena_ != other.arena_;
    }

private:
    template <typename U>
    friend class frontier_pending_allocator_t;

    std::shared_ptr<frontier_pending_arena_t> arena_;
};

template <typename Key, typename T, typename Compare = std::less<Key>>
class frontier_pending_store_t final {
public:
    using key_type = Key;
    using mapped_type = T;
    using value_type = std::pair<const Key, T>;
    using allocator_type = frontier_pending_allocator_t<value_type>;
    using map_type = std::map<Key, T, Compare, allocator_type>;
    using iterator = typename map_type::iterator;
    using const_iterator = typename map_type::const_iterator;

    frontier_pending_store_t()
        : frontier_pending_store_t(
              std::make_shared<frontier_pending_arena_t>()) {}

    explicit frontier_pending_store_t(
        std::shared_ptr<frontier_pending_arena_t> arena)
        : arena_(std::move(arena)),
          map_(Compare(), allocator_type(arena_)) {}

    iterator begin() noexcept { return map_.begin(); }
    const_iterator begin() const noexcept { return map_.begin(); }
    const_iterator cbegin() const noexcept { return map_.cbegin(); }
    iterator end() noexcept { return map_.end(); }
    const_iterator end() const noexcept { return map_.end(); }
    const_iterator cend() const noexcept { return map_.cend(); }

    bool empty() const noexcept { return map_.empty(); }
    std::size_t size() const noexcept { return map_.size(); }

    iterator find(const Key& key) { return map_.find(key); }
    const_iterator find(const Key& key) const { return map_.find(key); }

    template <typename... Args>
    std::pair<iterator, bool> emplace(Args&&... args)
    {
        return map_.emplace(std::forward<Args>(args)...);
    }

    iterator erase(const_iterator pos) { return map_.erase(pos); }
    std::size_t erase(const Key& key) { return map_.erase(key); }
    void clear() noexcept { map_.clear(); }

    const std::shared_ptr<frontier_pending_arena_t>& arena() const noexcept
    {
        return arena_;
    }

private:
    std::shared_ptr<frontier_pending_arena_t> arena_;
    map_type map_;
};

}
