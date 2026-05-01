#include "event_bus.hpp"

namespace aida {
namespace events {
namespace detail {

    registry_t& get_registry()
    {
        static registry_t s_registry;
        return s_registry;
    }

    static std::mutex& last_error_mutex()
    {
        static std::mutex m;
        return m;
    }

    static std::string& last_error_storage()
    {
        static std::string s;
        return s;
    }

    std::string last_error_slot()
    {
        std::lock_guard<std::mutex> guard(last_error_mutex());
        return last_error_storage();
    }

    void set_last_error(const std::string& msg)
    {
        std::lock_guard<std::mutex> guard(last_error_mutex());
        last_error_storage() = msg;
    }

    subscription_id_t register_subscription(const std::string& type_name, std::type_index payload_type, callback_invoker_t invoker)
    {
        registry_t& reg = get_registry();
        if (reg.shutdown_flag.load(std::memory_order_acquire))
        {
            set_last_error("event_bus: registry has been shut down");
            return 0;
        }

        const subscription_id_t id = reg.next_id.fetch_add(1, std::memory_order_relaxed);

        subscription_record_t record{id, payload_type, std::move(invoker)};

        std::unique_lock<std::shared_mutex> lock(reg.mutex);
        reg.by_type[type_name].push_back(std::move(record));
        return id;
    }

    bool remove_subscription(const std::string& type_name, subscription_id_t id)
    {
        registry_t& reg = get_registry();
        std::unique_lock<std::shared_mutex> lock(reg.mutex);

        auto it = reg.by_type.find(type_name);
        if (it == reg.by_type.end()) return false;

        auto& vec = it->second;
        for (auto vit = vec.begin(); vit != vec.end(); ++vit)
        {
            if (vit->id == id)
            {
                vec.erase(vit);
                if (vec.empty()) reg.by_type.erase(it);
                return true;
            }
        }
        return false;
    }

    void snapshot_subscribers(const std::string& type_name, std::vector<subscription_record_t>& out)
    {
        out.clear();
        registry_t& reg = get_registry();
        if (reg.shutdown_flag.load(std::memory_order_acquire)) return;

        std::shared_lock<std::shared_mutex> lock(reg.mutex);
        auto it = reg.by_type.find(type_name);
        if (it == reg.by_type.end()) return;

        out.reserve(it->second.size());
        for (const auto& rec : it->second)
        {
            out.push_back(rec);
        }
    }

}

    bool unsubscribe(const subscription_handle_t& handle)
    {
        if (!handle.valid())
        {
            detail::set_last_error("event_bus.unsubscribe: invalid handle");
            return false;
        }
        return detail::remove_subscription(handle.type_name, handle.id);
    }

    void shutdown()
    {
        detail::registry_t& reg = detail::get_registry();
        if (reg.shutdown_flag.exchange(true, std::memory_order_acq_rel)) return;

        std::unique_lock<std::shared_mutex> lock(reg.mutex);
        reg.by_type.clear();
    }

}
}
