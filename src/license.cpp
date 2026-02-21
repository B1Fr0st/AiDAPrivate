#include "aida_pro.hpp"

#ifdef __NT__
#include <windows.h>
#include <intrin.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#endif

#include <ctime>

static const std::string& get_firebase_host()
{
    static const std::string host =
        OBFSTR("https://aida-license-prod-default-rtdb.europe-west1.firebasedatabase.app");
    return host;
}

static constexpr int64_t LICENSE_CACHE_DURATION_SEC = 7 * 24 * 3600;

license_manager_t& license_manager_t::instance()
{
    static license_manager_t inst;
    return inst;
}

static qstring get_config_path()
{
    qstring path = get_user_idadir();
    path.append(OBFSTR_C("/ai_assistant.cfg"));
    return path;
}

nlohmann::json license_manager_t::read_license_config() const
{
    qstring path = get_config_path();
    if (!qfileexist(path.c_str()))
        return nlohmann::json::object();

    FILE* fp = qfopen(path.c_str(), "rb");
    if (!fp)
        return nlohmann::json::object();

    file_janitor_t fj(fp);
    uint64 fs = qfsize(fp);
    if (fs == 0)
        return nlohmann::json::object();

    qstring data;
    data.resize(static_cast<size_t>(fs));
    if (qfread(fp, data.begin(), static_cast<size_t>(fs)) != static_cast<ssize_t>(fs))
        return nlohmann::json::object();

    try
    {
        return nlohmann::json::parse(data.c_str());
    }
    catch (...)
    {
        return nlohmann::json::object();
    }
}

bool license_manager_t::write_license_config(const nlohmann::json& config) const
{
    qstring path = get_config_path();

    nlohmann::json merged;
    {
        FILE* fp = qfopen(path.c_str(), "rb");
        if (fp)
        {
            file_janitor_t fj(fp);
            uint64 fs = qfsize(fp);
            if (fs > 0)
            {
                qstring data;
                data.resize(static_cast<size_t>(fs));
                if (qfread(fp, data.begin(), static_cast<size_t>(fs)) == static_cast<ssize_t>(fs))
                {
                    try { merged = nlohmann::json::parse(data.c_str()); }
                    catch (...) { merged = nlohmann::json::object(); }
                }
            }
        }
    }

    static const char* license_keys[] = {
        "license_key", "license_validated_at", "license_hwid"
    };
    for (const char* k : license_keys)
    {
        if (config.contains(k))
            merged[k] = config[k];
    }

    std::string json_str = merged.dump(4);

    FILE* fp = qfopen(path.c_str(), "wb");
    if (!fp)
        return false;

    file_janitor_t fj(fp);
    size_t written = qfwrite(fp, json_str.c_str(), json_str.length());
    return written == json_str.length();
}

std::string license_manager_t::generate_hwid() const
{
    uint64_t hash = 14695981039346656037ULL;
    auto fnv_mix = [&hash](uint64_t val)
    {
        for (int i = 0; i < 8; ++i)
        {
            hash ^= (val >> (i * 8)) & 0xFF;
            hash *= 1099511628211ULL;
        }
    };

#ifdef __NT__
    DWORD volume_serial = 0;
    GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial,
                          nullptr, nullptr, nullptr, 0);

    wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD name_size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(computer_name, &name_size);

    int cpu_info[4] = {};
    __cpuid(cpu_info, 0);
    int cpu_info_ext[4] = {};
    __cpuid(cpu_info_ext, 1);

    fnv_mix(static_cast<uint64_t>(volume_serial));
    fnv_mix(static_cast<uint64_t>(cpu_info[0]) << 32 |
            static_cast<uint64_t>(static_cast<unsigned>(cpu_info[1])));
    fnv_mix(static_cast<uint64_t>(cpu_info[2]) << 32 |
            static_cast<uint64_t>(static_cast<unsigned>(cpu_info[3])));
    fnv_mix(static_cast<uint64_t>(cpu_info_ext[0]) << 32 |
            static_cast<uint64_t>(static_cast<unsigned>(cpu_info_ext[3])));
    for (DWORD i = 0; i < name_size; ++i)
        fnv_mix(static_cast<uint64_t>(computer_name[i]));
#else
    // macOS / Linux: hostname + utsname
    char hostname[256] = {};
    gethostname(hostname, sizeof(hostname));
    for (const char* p = hostname; *p; ++p)
        fnv_mix(static_cast<uint64_t>(static_cast<unsigned char>(*p)));

    struct utsname un = {};
    if (uname(&un) == 0)
    {
        for (const char* p = un.machine; *p; ++p)
            fnv_mix(static_cast<uint64_t>(static_cast<unsigned char>(*p)));
        for (const char* p = un.nodename; *p; ++p)
            fnv_mix(static_cast<uint64_t>(static_cast<unsigned char>(*p)));
    }
#endif

    char buf[17];
    qsnprintf(buf, sizeof(buf), "%016llX",
              static_cast<unsigned long long>(hash));
    return buf;
}

bool license_manager_t::is_cache_valid(int64_t validated_at) const
{
    if (validated_at <= 0)
        return false;
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    return (now - validated_at) < LICENSE_CACHE_DURATION_SEC;
}

bool license_manager_t::validate_with_server(const std::string& key)
{
    try
    {
        httplib::Client client(get_firebase_host());
        client.set_connection_timeout(10);
        client.set_read_timeout(15);
        client.set_write_timeout(10);

        std::string path = OBFSTR("/licenses/") + key + OBFSTR(".json");
        auto res = client.Get(path);

        if (!res || res->status != 200)
            return false;

        auto j = nlohmann::json::parse(res->body, nullptr, false);
        if (j.is_null() || j.is_discarded() || !j.is_object())
            return false;

        bool active = j.value(OBFSTR_C("active"), false);
        if (!active)
            return false;

        std::string expires = j.value(OBFSTR_C("expires"), std::string(""));
        if (!expires.empty())
        {
            time_t now = std::time(nullptr);
            struct tm tm_now;
#ifdef __NT__
            localtime_s(&tm_now, &now);
#else
            localtime_r(&now, &tm_now);
#endif
            char date_buf[11];
            std::strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", &tm_now);
            if (std::string(date_buf) > expires)
                return false; // Expired
        }

        std::string bound_hwid = j.value(OBFSTR_C("hwid"), std::string(""));
        std::string current_hwid = generate_hwid();

        if (bound_hwid.empty())
        {
            return bind_hwid_to_license(key, current_hwid);
        }

        return bound_hwid == current_hwid;
    }
    catch (...)
    {
        return false;
    }
}

bool license_manager_t::bind_hwid_to_license(const std::string& key,
                                               const std::string& hwid)
{
    try
    {
        httplib::Client client(get_firebase_host());
        client.set_connection_timeout(10);
        client.set_read_timeout(10);
        client.set_write_timeout(10);

        std::string path = OBFSTR("/licenses/") + key + OBFSTR(".json");
        nlohmann::json patch;
        patch[OBFSTR("hwid")] = hwid;

        auto res = client.Patch(path, patch.dump(), "application/json");
        return res && res->status == 200;
    }
    catch (...)
    {
        return false;
    }
}

bool license_manager_t::validate()
{
    auto config = read_license_config();

    std::string key = config.value(OBFSTR_C("license_key"), std::string(""));
    if (key.empty())
        return false;

    int64_t validated_at = config.value(OBFSTR_C("license_validated_at"),
                                        static_cast<int64_t>(0));
    std::string stored_hwid = config.value(OBFSTR_C("license_hwid"),
                                            std::string(""));

    if (is_cache_valid(validated_at) && !stored_hwid.empty()
        && stored_hwid == generate_hwid())
    {
        m_valid = true;
        return true;
    }

    if (validate_with_server(key))
    {
        config[OBFSTR("license_key")] = key;
        config[OBFSTR("license_validated_at")] =
            static_cast<int64_t>(std::time(nullptr));
        config[OBFSTR("license_hwid")] = generate_hwid();
        write_license_config(config);
        m_valid = true;
        return true;
    }

    return false;
}

bool license_manager_t::is_valid() const
{
    return m_valid.load(std::memory_order_acquire);
}

bool license_manager_t::show_activation_dialog()
{
    qstring key_input;

    if (!ask_str(&key_input, 0,
                 OBFSTR_C("Enter your license key to activate the plugin:")))
    {
        return false;
    }

    key_input.trim2();
    if (key_input.empty())
    {
        warning(OBFSTR_C("No license key entered. "
                          "The plugin cannot load without a valid license."));
        return false;
    }

    std::string key(key_input.c_str());

    msg(OBFSTR_C("Validating license key, please wait...\n"));

    bool valid = validate_with_server(key);

    if (valid)
    {
        nlohmann::json config = read_license_config();
        config[OBFSTR("license_key")] = key;
        config[OBFSTR("license_validated_at")] =
            static_cast<int64_t>(std::time(nullptr));
        config[OBFSTR("license_hwid")] = generate_hwid();
        write_license_config(config);

        m_valid = true;
        info(OBFSTR_C("License activated successfully! Thank you for your purchase."));
        return true;
    }

    warning(OBFSTR_C("Invalid, expired, or hardware-mismatched license key.\n\n"
                      "Please verify:\n"
                      "- Your key is correct\n"
                      "- Your subscription is active\n"
                      "- This hardware is authorized"));
    return false;
}
