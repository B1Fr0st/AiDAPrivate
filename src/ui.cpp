#ifndef QT_NO_EMIT
#define QT_NO_EMIT
#endif

#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:5219)
#pragma warning(disable:5240)
#endif
#include <QtWidgets>
#ifdef __NT__
#pragma warning(pop)
#endif

#ifdef emit
#undef emit
#endif

#include "aida_pro.hpp"
#include "anti_re.hpp"
#include <moves.hpp>
#include <algorithm>

static bool idaapi handle_viewer_dblclick(TWidget* viewer, int, void*)
{
    qstring word;
    if (get_highlight(&word, viewer, nullptr))
    {
        ea_t ea = BADADDR;
        if (atoea(&ea, word.c_str()))
        {
            jumpto(ea);
            return true;
        }

        ea = get_name_ea(get_screen_ea(), word.c_str());
        if (ea != BADADDR)
        {
            jumpto(ea);
            return true;
        }
    }

    return false;
}

static std::vector<std::string> fetch_models_from_api(
    const std::string& host,
    const std::string& path,
    const httplib::Headers& headers,
    std::function<std::vector<std::string>(const nlohmann::json&)> parser)
{
    std::vector<std::string> models;
    try
    {
        httplib::Client cli(host);
        cli.set_default_headers(headers);
        cli.set_read_timeout(20);
        cli.set_connection_timeout(10);
        cli.enable_server_certificate_verification(false); // FIXED

        auto res = cli.Get(path);
        if (!res || res->status != 200)
        {
            if (res)
                msg(OBFSTR_C("AiDA: Failed to fetch models from %s. HTTP %d.\n"), host.c_str(), res->status);
            else
                msg(OBFSTR_C("AiDA: Failed to fetch models from %s. Request error.\n"), host.c_str());
            return models;
        }

        auto j = nlohmann::json::parse(res->body);
        models = parser(j);
        std::sort(models.begin(), models.end());
        models.erase(std::unique(models.begin(), models.end()), models.end());
    }
    catch (const std::exception& e)
    {
        msg(OBFSTR_C("AiDA: Exception while fetching models from %s: %s\n"), host.c_str(), e.what());
    }
    return models;
}

static bool is_chat_model(const std::string& id)
{
    auto excludes = [](const std::string& s) -> bool {
        return s.find(OBFSTR_C("embedding")) != std::string::npos
            || s.find(OBFSTR_C("embeddings")) != std::string::npos
            || s.find(OBFSTR_C("whisper")) != std::string::npos
            || s.find(OBFSTR_C("audio")) != std::string::npos
            || s.find(OBFSTR_C("tts")) != std::string::npos
            || s.find(OBFSTR_C("dall-e")) != std::string::npos
            || s.find(OBFSTR_C("image")) != std::string::npos
            || s.find(OBFSTR_C("vision-preview")) != std::string::npos
            || s.find(OBFSTR_C("stable-diffusion")) != std::string::npos
            || s.find(OBFSTR_C("sd-")) != std::string::npos
            || s.find(OBFSTR_C("moderation")) != std::string::npos;
    };
    return !excludes(id);
}

static std::vector<std::string> fetch_openrouter_models_via_api(const qstring& api_key)
{
    if (api_key.empty())
        return {};
    std::string auth = api_key.c_str();
    if (auth.find(OBFSTR_C("Bearer ")) != 0)
        auth = OBFSTR("Bearer ") + auth;
    return fetch_models_from_api(OBFSTR_C("https://openrouter.ai"), OBFSTR_C("/api/v1/models"),
        {{OBFSTR_C("Authorization"), auth}},
        [](const nlohmann::json& j) {
            std::vector<std::string> models;
            std::string k_data = OBFSTR("data");
            std::string k_id = OBFSTR("id");
            if (!j.contains(k_data) || !j[k_data].is_array()) return models;
            for (const auto& m : j[k_data]) {
                if (!m.contains(k_id)) continue;
                std::string id = m[k_id].get<std::string>();
                if (is_chat_model(id))
                    models.push_back(std::move(id));
            }
            return models;
        });
}

static std::vector<std::string> fetch_openai_models_via_api(const qstring& api_key, const qstring& base_url = qstring())
{
    bool has_custom_url = !base_url.empty();
    if (api_key.empty() && !has_custom_url)
        return {};
    std::string host = has_custom_url ? std::string(base_url.c_str()) : OBFSTR("https://api.openai.com");
    httplib::Headers headers;
    if (!api_key.empty())
        headers.emplace(OBFSTR_C("Authorization"), OBFSTR("Bearer ") + api_key.c_str());
    bool skip_filter = has_custom_url;
    return fetch_models_from_api(host, OBFSTR_C("/v1/models"),
        headers,
        [skip_filter](const nlohmann::json& j) {
            std::vector<std::string> models;
            std::string k_data = OBFSTR("data");
            std::string k_id = OBFSTR("id");
            if (!j.contains(k_data) || !j[k_data].is_array()) return models;
            for (const auto& m : j[k_data]) {
                if (!m.contains(k_id)) continue;
                std::string id = m[k_id].get<std::string>();
                if (skip_filter)
                {
                    if (is_chat_model(id))
                        models.push_back(std::move(id));
                }
                else
                {
                    bool is_relevant = (id.find(OBFSTR_C("gpt")) != std::string::npos
                        || id.find(OBFSTR_C("o1")) == 0 || id.find(OBFSTR_C("o3")) == 0 || id.find(OBFSTR_C("o4")) == 0);
                    if (is_relevant && is_chat_model(id))
                        models.push_back(std::move(id));
                }
            }
            return models;
        });
}

static std::vector<std::string> fetch_gemini_models_via_api(const qstring& api_key, const qstring& base_url = qstring())
{
    bool has_custom_url = !base_url.empty();
    if (api_key.empty() && !has_custom_url)
        return {};

    std::string host, path;
    httplib::Headers headers;

    if (has_custom_url)
    {
        host = base_url.c_str();
        path = OBFSTR("/v1/models");
    }
    else
    {
        host = OBFSTR("https://generativelanguage.googleapis.com");
        path = OBFSTR("/v1beta/models?key=") + std::string(api_key.c_str());
    }

    return fetch_models_from_api(host, path,
        headers,
        [has_custom_url](const nlohmann::json& j) {
            std::vector<std::string> models;
            if (has_custom_url)
            {
                std::string k_data = OBFSTR("data");
                std::string k_id = OBFSTR("id");
                if (j.contains(k_data) && j[k_data].is_array())
                {
                    for (const auto& m : j[k_data])
                    {
                        if (!m.contains(k_id)) continue;
                        std::string id = m[k_id].get<std::string>();
                        if (is_chat_model(id))
                            models.push_back(std::move(id));
                    }
                    return models;
                }
            }
            std::string k_models = OBFSTR("models");
            std::string k_name = OBFSTR("name");
            std::string k_methods = OBFSTR("supportedGenerationMethods");
            std::string k_gen = OBFSTR("generateContent");
            std::string k_prefix = OBFSTR("models/");
            if (!j.contains(k_models) || !j[k_models].is_array()) return models;
            for (const auto& m : j[k_models]) {
                auto methods = m.value(k_methods, nlohmann::json::array());
                bool supports_generate = false;
                for (const auto& method : methods) {
                    if (method.get<std::string>().find(k_gen) != std::string::npos) {
                        supports_generate = true;
                        break;
                    }
                }
                if (supports_generate) {
                    std::string name = m.value(k_name, std::string(""));
                    if (name.find(k_prefix) == 0)
                        name = name.substr(7);
                    if (!name.empty())
                        models.push_back(std::move(name));
                }
            }
            return models;
        });
}

static std::vector<std::string> fetch_anthropic_models_via_api(const qstring& api_key, const qstring& base_url = qstring())
{
    bool has_custom_url = !base_url.empty();
    if (api_key.empty() && !has_custom_url)
        return {};
    std::string host = has_custom_url ? std::string(base_url.c_str()) : OBFSTR("https://api.anthropic.com");
    httplib::Headers headers;
    if (!api_key.empty())
        headers.emplace(OBFSTR_C("x-api-key"), std::string(api_key.c_str()));
    headers.emplace(OBFSTR_C("anthropic-version"), OBFSTR("2023-06-01"));
    return fetch_models_from_api(host, OBFSTR_C("/v1/models"),
        headers,
        [has_custom_url](const nlohmann::json& j) {
            std::vector<std::string> models;
            std::string k_data = OBFSTR("data");
            std::string k_id = OBFSTR("id");
            if (j.contains(k_data) && j[k_data].is_array())
            {
                for (const auto& m : j[k_data]) {
                    if (!m.contains(k_id)) continue;
                    models.push_back(m[k_id].get<std::string>());
                }
                return models;
            }
            if (has_custom_url)
            {
                std::string k_models = OBFSTR("models");
                if (j.contains(k_models) && j[k_models].is_array())
                {
                    for (const auto& m : j[k_models])
                    {
                        std::string id = m.value(OBFSTR("id"), m.value(OBFSTR("name"), std::string("")));
                        if (!id.empty() && is_chat_model(id))
                            models.push_back(std::move(id));
                    }
                }
            }
            return models;
        });
}

static std::vector<std::string> fetch_copilot_models_via_api(const qstring& proxy_address)
{
    if (proxy_address.empty())
        return {};
    return fetch_models_from_api(std::string(proxy_address.c_str()), OBFSTR("/v1/models"),
        {},
        [](const nlohmann::json& j) {
            std::vector<std::string> models;
            std::string k_data = OBFSTR("data");
            std::string k_id = OBFSTR("id");
            if (!j.contains(k_data) || !j[k_data].is_array()) return models;
            for (const auto& m : j[k_data]) {
                if (!m.contains(k_id)) continue;
                std::string id = m[k_id].get<std::string>();
                if (is_chat_model(id))
                    models.push_back(std::move(id));
            }
            return models;
        });
}

static std::string fetch_copilot_github_user()
{
    std::string result;
#ifdef __NT__

    auto query_github_user = [](const std::string& token) -> std::string {
        if (token.empty()) return {};
        try
        {
            httplib::Client cli("https://api.github.com");
            cli.set_connection_timeout(3);
            cli.set_read_timeout(3);
            cli.enable_server_certificate_verification(false); // FIXED
            httplib::Headers hdrs = {
                {"Authorization", "token " + token},
                {"User-Agent", "AiDA-Plugin"},
                {"Accept", "application/json"}
            };
            auto res = cli.Get("/user", hdrs);
            if (res && res->status == 200)
            {
                auto uj = nlohmann::json::parse(res->body, nullptr, false);
                if (!uj.is_discarded())
                {
                    std::string login = uj.value("login", std::string());
                    if (!login.empty()) return login;
                }
            }
        }
        catch (...) {}
        return {};
    };

    char userprofile_buf[MAX_PATH] = {};
    DWORD uplen = GetEnvironmentVariableA("USERPROFILE", userprofile_buf, MAX_PATH);
    if (uplen > 0 && uplen < MAX_PATH)
    {
        std::string token_path = std::string(userprofile_buf, uplen) +
            "\\.local\\share\\copilot-api\\github_token";
        std::ifstream tf(token_path);
        if (tf.is_open())
        {
            std::string token;
            std::getline(tf, token);

            while (!token.empty() && (token.back() == '\n' || token.back() == '\r' || token.back() == ' '))
                token.pop_back();
            if (!token.empty())
            {

                if (token.front() == '{')
                {
                    auto j = nlohmann::json::parse(token, nullptr, false);
                    if (!j.is_discarded())
                    {
                        std::string user = j.value("user", std::string());
                        if (!user.empty()) return user;
                        token = j.value("token", j.value("oauth_token", std::string()));
                    }
                }
                std::string user = query_github_user(token);
                if (!user.empty()) return user;
            }
        }
    }

    char localappdata_buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("LOCALAPPDATA", localappdata_buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
    {
        std::string localappdata(localappdata_buf, len);
        std::vector<std::string> paths = {
            localappdata + "\\github-copilot\\hosts.json",
            localappdata + "\\github-copilot\\apps.json"
        };

        for (const auto& path : paths)
        {
            std::ifstream f(path);
            if (!f.is_open()) continue;

            try
            {
                std::string content((std::istreambuf_iterator<char>(f)),
                                     std::istreambuf_iterator<char>());
                auto j = nlohmann::json::parse(content, nullptr, false);
                if (j.is_discarded() || !j.is_object()) continue;

                for (auto it = j.begin(); it != j.end(); ++it)
                {
                    if (!it->is_object()) continue;
                    std::string user = it->value("user", std::string());
                    if (!user.empty()) return user;

                    std::string token = it->value("oauth_token", std::string());
                    user = query_github_user(token);
                    if (!user.empty()) return user;
                }
            }
            catch (...) {}
        }
    }
#endif
    return result;
}

static std::vector<std::string> fetch_local_llm_models_via_api(const qstring& base_url)
{
    if (base_url.empty())
        return {};

    std::string host = base_url.c_str();

    auto models = fetch_models_from_api(host, OBFSTR("/v1/models"),
        {},
        [](const nlohmann::json& j) {
            std::vector<std::string> result;
            std::string k_data = OBFSTR("data");
            std::string k_id = OBFSTR("id");
            if (j.contains(k_data) && j[k_data].is_array())
            {
                for (const auto& m : j[k_data])
                {
                    if (!m.contains(k_id)) continue;
                    std::string id = m[k_id].get<std::string>();
                    if (is_chat_model(id))
                        result.push_back(std::move(id));
                }
            }
            return result;
        });

    if (!models.empty())
        return models;

    models = fetch_models_from_api(host, OBFSTR("/api/tags"),
        {},
        [](const nlohmann::json& j) {
            std::vector<std::string> result;
            std::string k_models = OBFSTR("models");
            std::string k_name = OBFSTR("name");
            if (j.contains(k_models) && j[k_models].is_array())
            {
                for (const auto& m : j[k_models])
                {
                    std::string name = m.value(k_name, std::string(""));
                    if (!name.empty())
                        result.push_back(std::move(name));
                }
            }
            return result;
        });

    return models;
}

static inline QString settingsColorToRgb(const QColor& c)
{
    return QStringLiteral("rgb(%1,%2,%3)")
        .arg(c.red()).arg(c.green()).arg(c.blue());
}

static inline QColor settingsBlend(const QColor& a, const QColor& b, double t)
{
    const double r = qBound(0.0, t, 1.0);
    const double inv = 1.0 - r;
    return QColor(
        static_cast<int>(a.red()   * inv + b.red()   * r),
        static_cast<int>(a.green() * inv + b.green() * r),
        static_cast<int>(a.blue()  * inv + b.blue()  * r),
        static_cast<int>(a.alpha() * inv + b.alpha() * r));
}

static inline QColor settingsReadableTextColor(const QColor& bg)
{
    return bg.lightnessF() >= 0.62 ? QColor(24, 24, 24) : QColor(255, 255, 255);
}

struct SettingsTheme
{
    QColor panelBg;
    QColor headerBg;
    QColor headerBorder;
    QColor textPrimary;
    QColor textSecondary;
    QColor inputBg;
    QColor inputBorder;
    QColor inputBorderFocus;
    QColor buttonPrimary;
    QColor buttonPrimaryHover;
    QColor buttonPrimaryPressed;
    QColor buttonPrimaryText;
    QColor buttonSecondaryBg;
    QColor buttonSecondaryBorder;
    QColor buttonSecondaryHover;
    QColor accentColor;
    QColor separatorColor;
    QColor tabSelectedBg;
    QColor tabHoverBg;
    QColor groupBorder;
    QColor groupBg;
    QColor accentGlow;
    QColor accentSubtle;
    QColor cardBg;
    QColor cardBorder;
    QColor headerAccent;
    QColor hoverGlow;
    QColor inputFocusGlow;
    bool isDark;
};

static SettingsTheme detectSettingsTheme(QWidget* ref)
{
    SettingsTheme t;
    QWidget* paletteSource = ref != nullptr && ref->parentWidget() != nullptr
        ? ref->parentWidget()
        : ref;
    QPalette p = paletteSource ? paletteSource->palette() : QApplication::palette();

    QColor windowColor = p.color(QPalette::Window);
    QColor baseColor   = p.color(QPalette::Base);
    QColor highlight   = p.color(QPalette::Highlight);

    t.isDark = windowColor.lightnessF() < 0.5;
    t.textPrimary   = t.isDark ? QColor(230, 230, 230) : QColor(30, 30, 30);
    t.textSecondary = t.isDark ? QColor(170, 170, 170) : QColor(100, 100, 100);
    t.accentColor   = highlight.isValid() ? highlight : (t.isDark ? QColor(110, 110, 110) : QColor(140, 140, 140));

    if (t.isDark)
    {
        QColor base     = settingsBlend(windowColor, QColor(30, 30, 30), 0.72);
        QColor elevated = settingsBlend(base, QColor(44, 44, 44), 0.58);
        QColor stroke   = settingsBlend(base, QColor(72, 72, 72), 0.74);

        t.panelBg             = base;
        t.headerBg            = settingsBlend(base, QColor(22, 22, 22), 0.52);
        t.headerBorder        = stroke;
        t.inputBg             = elevated;
        t.inputBorder         = stroke;
        t.inputBorderFocus    = settingsBlend(t.accentColor, QColor(200, 200, 200), 0.24);
        t.buttonPrimary       = t.accentColor;
        t.buttonPrimaryHover  = settingsBlend(t.accentColor, QColor(200, 200, 200), 0.16);
        t.buttonPrimaryPressed= settingsBlend(t.accentColor, QColor(24, 24, 24), 0.36);
        t.buttonPrimaryText   = settingsReadableTextColor(
            settingsBlend(t.buttonPrimary, t.buttonPrimaryHover, 0.5));
        t.buttonSecondaryBg   = QColor(0, 0, 0, 0);
        t.buttonSecondaryBorder = settingsBlend(base, stroke, 0.9);
        t.buttonSecondaryHover  = settingsBlend(base, elevated, 0.86);
        t.separatorColor      = stroke;
        t.tabSelectedBg       = settingsBlend(t.accentColor, QColor(60, 60, 60), 0.30);
        t.tabHoverBg          = settingsBlend(base, elevated, 0.82);
        t.groupBorder         = settingsBlend(base, stroke, 0.8);
        t.groupBg             = settingsBlend(base, QColor(36, 36, 36), 0.5);
        t.accentGlow          = QColor(t.accentColor.red(), t.accentColor.green(), t.accentColor.blue(), 40);
        t.accentSubtle        = settingsBlend(base, t.accentColor, 0.08);
        t.cardBg              = settingsBlend(base, QColor(40, 40, 42), 0.55);
        t.cardBorder          = settingsBlend(stroke, t.accentColor, 0.15);
        t.headerAccent        = settingsBlend(t.accentColor, QColor(100, 180, 255), 0.3);
        t.hoverGlow           = settingsBlend(base, t.accentColor, 0.12);
        t.inputFocusGlow      = QColor(t.accentColor.red(), t.accentColor.green(), t.accentColor.blue(), 50);
    }
    else
    {
        QColor base     = settingsBlend(windowColor, QColor(248, 248, 248), 0.78);
        QColor elevated = settingsBlend(base, QColor(238, 238, 238), 0.62);
        QColor stroke   = settingsBlend(base, QColor(208, 208, 208), 0.84);

        t.panelBg             = base;
        t.headerBg            = settingsBlend(base, QColor(240, 240, 240), 0.6);
        t.headerBorder        = stroke;
        t.inputBg             = settingsBlend(baseColor, elevated, 0.54);
        t.inputBorder         = stroke;
        t.inputBorderFocus    = settingsBlend(t.accentColor, QColor(140, 140, 140), 0.3);
        t.buttonPrimary       = settingsBlend(t.accentColor, QColor(110, 110, 110), 0.26);
        t.buttonPrimaryHover  = settingsBlend(t.buttonPrimary, QColor(255, 255, 255), 0.12);
        t.buttonPrimaryPressed= settingsBlend(t.buttonPrimary, QColor(50, 50, 50), 0.14);
        t.buttonPrimaryText   = settingsReadableTextColor(
            settingsBlend(t.buttonPrimary, t.buttonPrimaryHover, 0.5));
        t.buttonSecondaryBg   = QColor(0, 0, 0, 0);
        t.buttonSecondaryBorder = stroke;
        t.buttonSecondaryHover  = settingsBlend(base, elevated, 0.68);
        t.separatorColor      = stroke;
        t.tabSelectedBg       = settingsBlend(t.accentColor, QColor(105, 105, 105), 0.26);
        t.tabHoverBg          = settingsBlend(base, elevated, 0.66);
        t.groupBorder         = settingsBlend(base, stroke, 0.85);
        t.groupBg             = settingsBlend(base, QColor(252, 252, 252), 0.5);
        t.accentGlow          = QColor(t.accentColor.red(), t.accentColor.green(), t.accentColor.blue(), 30);
        t.accentSubtle        = settingsBlend(base, t.accentColor, 0.06);
        t.cardBg              = settingsBlend(base, QColor(255, 255, 255), 0.6);
        t.cardBorder          = settingsBlend(stroke, t.accentColor, 0.12);
        t.headerAccent        = settingsBlend(t.accentColor, QColor(60, 120, 200), 0.25);
        t.hoverGlow           = settingsBlend(base, t.accentColor, 0.08);
        t.inputFocusGlow      = QColor(t.accentColor.red(), t.accentColor.green(), t.accentColor.blue(), 40);
    }
    return t;
}

static QWidget* normalizeSettingsThemeWidget(QWidget* widget)
{
    QWidget* current = widget;
    while (current != nullptr && current->parentWidget() != nullptr && !current->isWindow())
        current = current->parentWidget();
    return current;
}

static bool isUsableSettingsThemeWidget(const QWidget* widget)
{
    return widget != nullptr
        && !widget->inherits("QMenu")
        && !widget->inherits("QToolTip")
        && !widget->inherits("QComboBoxPrivateContainer");
}

static QWidget* resolveSettingsThemeSource(QWidget* preferred = nullptr)
{
    QWidget* candidate = normalizeSettingsThemeWidget(preferred);
    if (isUsableSettingsThemeWidget(candidate))
        return candidate;

    candidate = normalizeSettingsThemeWidget(QApplication::activeWindow());
    if (isUsableSettingsThemeWidget(candidate))
        return candidate;

    candidate = normalizeSettingsThemeWidget(QApplication::focusWidget());
    if (isUsableSettingsThemeWidget(candidate))
        return candidate;

    QWidget* best = nullptr;
    qint64 bestArea = -1;
    const auto topLevelWidgets = QApplication::topLevelWidgets();
    for (QWidget* widget : topLevelWidgets)
    {
        candidate = normalizeSettingsThemeWidget(widget);
        if (!isUsableSettingsThemeWidget(candidate) || !candidate->isVisible())
            continue;
        if (candidate->inherits("QMainWindow"))
            return candidate;

        const QSize size = candidate->size();
        const qint64 area = static_cast<qint64>(size.width()) * static_cast<qint64>(size.height());
        if (area > bestArea)
        {
            bestArea = area;
            best = candidate;
        }
    }

    return best;
}

static QString buildSettingsStylesheet(const SettingsTheme& t)
{
    QString css;
    css.reserve(18000);

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog {"
        "  background-color: %1;"
        "  font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', Arial, sans-serif;"
        "  font-size: 9pt;"
        "}").arg(settingsColorToRgb(t.panelBg));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QLabel {"
        "  color: %1;"
        "  background: transparent;"
        "  font-size: 9pt;"
        "}").arg(settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QLabel#sectionHeader {"
        "  color: %1;"
        "  font-size: 12pt;"
        "  font-weight: 700;"
        "  padding: 0px 0px 0px 0px;"
        "  letter-spacing: 0.3px;"
        "}").arg(settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QLabel#sectionSubtitle {"
        "  color: %1;"
        "  font-size: 8pt;"
        "  font-weight: 400;"
        "  padding: 0px 0px 1px 0px;"
        "}").arg(settingsColorToRgb(t.textSecondary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QLabel#fieldLabel {"
        "  color: %1;"
        "  font-size: 8.5pt;"
        "  font-weight: 500;"
        "}").arg(settingsColorToRgb(t.textSecondary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QFrame#headerAccentBar {"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
        "    stop:0 %1, stop:0.5 %2, stop:1 transparent);"
        "  max-height: 2px;"
        "  min-height: 2px;"
        "  border: none;"
        "  border-radius: 1px;"
        "}").arg(settingsColorToRgb(t.headerAccent),
                 settingsColorToRgb(t.accentColor));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QFrame#headerSep {"
        "  background-color: %1;"
        "  max-height: 1px;"
        "  min-height: 1px;"
        "  border: none;"
        "}").arg(settingsColorToRgb(t.separatorColor));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QLineEdit {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 5px;"
        "  color: %3;"
        "  padding: 4px 8px;"
        "  min-height: 22px;"
        "  font-size: 9pt;"
        "  selection-background-color: %4;"
        "}").arg(settingsColorToRgb(t.inputBg),
                 settingsColorToRgb(t.inputBorder),
                 settingsColorToRgb(t.textPrimary),
                 settingsColorToRgb(t.tabSelectedBg));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QLineEdit:focus {"
        "  border: 1.5px solid %1;"
        "  background-color: %2;"
        "}").arg(settingsColorToRgb(t.inputBorderFocus),
                 settingsColorToRgb(t.isDark
                     ? settingsBlend(t.inputBg, t.accentColor, 0.04)
                     : settingsBlend(t.inputBg, t.accentColor, 0.02)));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QLineEdit:hover:!focus {"
        "  border: 1px solid %1;"
        "}").arg(settingsColorToRgb(settingsBlend(t.inputBorder, t.accentColor, 0.3)));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QComboBox {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 5px;"
        "  color: %3;"
        "  padding: 4px 26px 4px 8px;"
        "  min-height: 22px;"
        "  font-size: 9pt;"
        "}").arg(settingsColorToRgb(t.inputBg),
                 settingsColorToRgb(t.inputBorder),
                 settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QComboBox:focus {"
        "  border: 1.5px solid %1;"
        "}").arg(settingsColorToRgb(t.inputBorderFocus));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QComboBox:hover:!focus {"
        "  border: 1px solid %1;"
        "}").arg(settingsColorToRgb(settingsBlend(t.inputBorder, t.accentColor, 0.3)));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QComboBox::drop-down {"
        "  subcontrol-origin: padding;"
        "  subcontrol-position: top right;"
        "  width: 24px;"
        "  border: none;"
        "  border-top-right-radius: 5px;"
        "  border-bottom-right-radius: 5px;"
        "  background: transparent;"
        "}");

    QColor arrowColor = t.isDark ? t.textSecondary : t.textSecondary.darker(120);
    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QComboBox::down-arrow {"
        "  width: 0px; height: 0px;"
        "  border-left: 4px solid transparent;"
        "  border-right: 4px solid transparent;"
        "  border-top: 5px solid %1;"
        "}").arg(settingsColorToRgb(arrowColor));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QComboBox QAbstractItemView {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 6px;"
        "  color: %3;"
        "  padding: 4px;"
        "  selection-background-color: %4;"
        "  selection-color: %5;"
        "  outline: none;"
        "}").arg(settingsColorToRgb(t.inputBg),
                 settingsColorToRgb(t.cardBorder),
                 settingsColorToRgb(t.textPrimary),
                 settingsColorToRgb(t.tabSelectedBg),
                 settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QSpinBox, QDialog#aidaSettingsDialog QDoubleSpinBox {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 5px;"
        "  color: %3;"
        "  padding: 4px 6px;"
        "  min-height: 22px;"
        "  font-size: 9pt;"
        "}").arg(settingsColorToRgb(t.inputBg),
                 settingsColorToRgb(t.inputBorder),
                 settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QSpinBox:focus, QDialog#aidaSettingsDialog QDoubleSpinBox:focus {"
        "  border: 1.5px solid %1;"
        "}").arg(settingsColorToRgb(t.inputBorderFocus));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QSpinBox:hover:!focus, QDialog#aidaSettingsDialog QDoubleSpinBox:hover:!focus {"
        "  border: 1px solid %1;"
        "}").arg(settingsColorToRgb(settingsBlend(t.inputBorder, t.accentColor, 0.3)));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QSpinBox::up-button, QDialog#aidaSettingsDialog QDoubleSpinBox::up-button {"
        "  subcontrol-origin: border;"
        "  subcontrol-position: top right;"
        "  width: 20px;"
        "  border-left: 1px solid %1;"
        "  border-bottom: 1px solid %1;"
        "  border-top-right-radius: 5px;"
        "  background: transparent;"
        "}").arg(settingsColorToRgb(t.inputBorder));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QSpinBox::down-button, QDialog#aidaSettingsDialog QDoubleSpinBox::down-button {"
        "  subcontrol-origin: border;"
        "  subcontrol-position: bottom right;"
        "  width: 20px;"
        "  border-left: 1px solid %1;"
        "  border-bottom-right-radius: 5px;"
        "  background: transparent;"
        "}").arg(settingsColorToRgb(t.inputBorder));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QSpinBox::up-arrow, QDialog#aidaSettingsDialog QDoubleSpinBox::up-arrow {"
        "  width: 0px; height: 0px;"
        "  border-left: 4px solid transparent;"
        "  border-right: 4px solid transparent;"
        "  border-bottom: 4px solid %1;"
        "}").arg(settingsColorToRgb(arrowColor));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QSpinBox::down-arrow, QDialog#aidaSettingsDialog QDoubleSpinBox::down-arrow {"
        "  width: 0px; height: 0px;"
        "  border-left: 4px solid transparent;"
        "  border-right: 4px solid transparent;"
        "  border-top: 4px solid %1;"
        "}").arg(settingsColorToRgb(arrowColor));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QSpinBox::up-button:hover, QDialog#aidaSettingsDialog QDoubleSpinBox::up-button:hover,"
        "QDialog#aidaSettingsDialog QSpinBox::down-button:hover, QDialog#aidaSettingsDialog QDoubleSpinBox::down-button:hover {"
        "  background: %1;"
        "}").arg(settingsColorToRgb(t.hoverGlow));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QPushButton#primaryBtn {"
        "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "    stop:0 %1, stop:1 %2);"
        "  color: %3;"
        "  border: 1px solid %4;"
        "  border-radius: 8px;"
        "  padding: 5px 28px;"
        "  font-size: 9pt;"
        "  font-weight: 600;"
        "  min-height: 20px;"
        "  min-width: 90px;"
        "  letter-spacing: 0.3px;"
        "}").arg(settingsColorToRgb(t.buttonPrimaryHover),
                 settingsColorToRgb(t.buttonPrimary),
                 settingsColorToRgb(t.buttonPrimaryText),
                 settingsColorToRgb(t.buttonPrimary.darker(115)));
    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QPushButton#primaryBtn:hover {"
        "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "    stop:0 %1, stop:1 %2);"
        "  border-color: %3;"
        "}").arg(settingsColorToRgb(settingsBlend(t.buttonPrimaryHover, QColor(255,255,255), 0.08)),
                 settingsColorToRgb(t.buttonPrimaryHover),
                 settingsColorToRgb(t.buttonPrimary));
    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QPushButton#primaryBtn:pressed {"
        "  background-color: %1;"
        "  border-color: %2;"
        "}").arg(settingsColorToRgb(t.buttonPrimaryPressed),
                 settingsColorToRgb(t.buttonPrimaryPressed.darker(120)));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QPushButton#secondaryBtn {"
        "  background-color: transparent;"
        "  color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 8px;"
        "  padding: 5px 16px;"
        "  font-size: 9pt;"
        "  min-height: 20px;"
        "  font-weight: 500;"
        "}").arg(settingsColorToRgb(t.textSecondary),
                 settingsColorToRgb(t.buttonSecondaryBorder));
    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QPushButton#secondaryBtn:hover {"
        "  background-color: %1;"
        "  color: %2;"
        "  border-color: %3;"
        "}").arg(settingsColorToRgb(t.hoverGlow),
                 settingsColorToRgb(t.textPrimary),
                 settingsColorToRgb(settingsBlend(t.inputBorder, t.accentColor, 0.25)));
    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QPushButton#secondaryBtn:pressed {"
        "  background-color: %1;"
        "}").arg(settingsColorToRgb(t.buttonSecondaryHover));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QWidget#providerCard {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 10px;"
        "  padding: 4px;"
        "}").arg(settingsColorToRgb(t.cardBg),
                 settingsColorToRgb(t.cardBorder));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QTabWidget::pane {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-top: none;"
        "  border-bottom-left-radius: 8px;"
        "  border-bottom-right-radius: 8px;"
        "  padding: 2px 4px 2px 4px;"
        "}").arg(settingsColorToRgb(t.cardBg),
                 settingsColorToRgb(t.cardBorder));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QTabBar {"
        "  qproperty-drawBase: 0;"
        "}");

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QTabBar::tab {"
        "  background-color: transparent;"
        "  color: %1;"
        "  border: none;"
        "  border-bottom: 2px solid transparent;"
        "  padding: 5px 14px 4px 14px;"
        "  font-size: 8.5pt;"
        "  margin-right: 2px;"
        "  font-weight: 500;"
        "}").arg(settingsColorToRgb(t.textSecondary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QTabBar::tab:selected {"
        "  color: %1;"
        "  border-bottom: 2px solid %2;"
        "  font-weight: 600;"
        "  background-color: %3;"
        "}").arg(settingsColorToRgb(t.textPrimary),
                 settingsColorToRgb(t.headerAccent),
                 settingsColorToRgb(t.accentSubtle));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QTabBar::tab:!selected:hover {"
        "  background-color: %1;"
        "  color: %2;"
        "  border-bottom: 2px solid %3;"
        "}").arg(settingsColorToRgb(t.tabHoverBg),
                 settingsColorToRgb(t.textPrimary),
                 settingsColorToRgb(settingsBlend(t.headerAccent, t.panelBg, 0.5)));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QGroupBox {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 8px;"
        "  margin-top: 12px;"
        "  padding: 18px 10px 8px 10px;"
        "  font-size: 9pt;"
        "  font-weight: 600;"
        "  color: %3;"
        "}").arg(settingsColorToRgb(t.cardBg),
                 settingsColorToRgb(t.cardBorder),
                 settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QGroupBox::title {"
        "  subcontrol-origin: margin;"
        "  subcontrol-position: top left;"
        "  padding: 2px 10px;"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
        "    stop:0 %1, stop:1 %2);"
        "  border: 1px solid %3;"
        "  border-radius: 5px;"
        "  left: 12px;"
        "  color: %4;"
        "  font-size: 8.5pt;"
        "  font-weight: 600;"
        "}").arg(settingsColorToRgb(t.accentSubtle),
                 settingsColorToRgb(t.cardBg),
                 settingsColorToRgb(t.cardBorder),
                 settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QScrollArea {"
        "  background-color: transparent;"
        "  border: none;"
        "}");

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QScrollBar:vertical {"
        "  background-color: transparent;"
        "  width: 7px;"
        "  margin: 2px 0px;"
        "}");
    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QScrollBar::handle:vertical {"
        "  background-color: %1;"
        "  border-radius: 3px;"
        "  min-height: 30px;"
        "}").arg(settingsColorToRgb(t.inputBorder));
    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QScrollBar::handle:vertical:hover {"
        "  background-color: %1;"
        "}").arg(settingsColorToRgb(settingsBlend(t.inputBorder, t.accentColor, 0.3)));
    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QScrollBar::add-line:vertical,"
        "QDialog#aidaSettingsDialog QScrollBar::sub-line:vertical {"
        "  height: 0px;"
        "}");
    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QScrollBar::add-page:vertical,"
        "QDialog#aidaSettingsDialog QScrollBar::sub-page:vertical {"
        "  background: none;"
        "}");

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QCheckBox {"
        "  color: %1;"
        "  spacing: 6px;"
        "  font-size: 9pt;"
        "}").arg(settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QCheckBox::indicator {"
        "  width: 15px;"
        "  height: 15px;"
        "  border: 1.5px solid %1;"
        "  border-radius: 4px;"
        "  background-color: %2;"
        "}").arg(settingsColorToRgb(t.inputBorder),
                 settingsColorToRgb(t.inputBg));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QCheckBox::indicator:checked {"
        "  background-color: %1;"
        "  border-color: %2;"
        "}").arg(settingsColorToRgb(t.accentColor),
                 settingsColorToRgb(t.accentColor.darker(110)));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QCheckBox::indicator:hover {"
        "  border-color: %1;"
        "}").arg(settingsColorToRgb(t.inputBorderFocus));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QListWidget {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 6px;"
        "  color: %3;"
        "  font-size: 9pt;"
        "  padding: 2px;"
        "  outline: none;"
        "}").arg(settingsColorToRgb(t.inputBg),
                 settingsColorToRgb(t.inputBorder),
                 settingsColorToRgb(t.textPrimary));

    QColor altRowColor = t.isDark
        ? settingsBlend(t.inputBg, QColor(255, 255, 255), 0.04)
        : settingsBlend(t.inputBg, QColor(0, 0, 0), 0.03);

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QListWidget::item {"
        "  background-color: %1;"
        "  color: %2;"
        "  padding: 5px 8px;"
        "  border: none;"
        "  border-radius: 3px;"
        "}").arg(settingsColorToRgb(t.inputBg),
                 settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QListWidget::item:alternate {"
        "  background-color: %1;"
        "}").arg(settingsColorToRgb(altRowColor));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QListWidget::item:selected {"
        "  background-color: %1;"
        "  color: %2;"
        "}").arg(settingsColorToRgb(t.tabSelectedBg),
                 settingsColorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QListWidget::item:hover:!selected {"
        "  background-color: %1;"
        "}").arg(settingsColorToRgb(t.hoverGlow));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QTextEdit {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 5px;"
        "  color: %3;"
        "  padding: 6px 8px;"
        "  font-size: 9pt;"
        "  selection-background-color: %4;"
        "}").arg(settingsColorToRgb(t.inputBg),
                 settingsColorToRgb(t.inputBorder),
                 settingsColorToRgb(t.textPrimary),
                 settingsColorToRgb(t.tabSelectedBg));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QTextEdit:focus {"
        "  border: 1.5px solid %1;"
        "}").arg(settingsColorToRgb(t.inputBorderFocus));

    css += QStringLiteral(
        "QDialog#aidaSettingsDialog QToolTip {"
        "  background-color: %1;"
        "  color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 6px;"
        "  padding: 6px 10px;"
        "  font-size: 9pt;"
        "}").arg(settingsColorToRgb(t.cardBg),
                 settingsColorToRgb(t.textPrimary),
                 settingsColorToRgb(t.cardBorder));

    return css;
}

static void applySettingsDialogTheme(QDialog* dialog, QWidget* preferredRef = nullptr)
{
    if (dialog == nullptr)
        return;

    QWidget* themeSource = resolveSettingsThemeSource(
        preferredRef != nullptr ? preferredRef : dialog->parentWidget());
    if (themeSource == dialog)
        themeSource = dialog->parentWidget();

    const SettingsTheme theme = detectSettingsTheme(themeSource != nullptr ? themeSource : dialog);
    dialog->setStyleSheet(buildSettingsStylesheet(theme));

    QPalette palette = dialog->palette();
    palette.setColor(QPalette::Window, theme.panelBg);
    palette.setColor(QPalette::WindowText, theme.textPrimary);
    palette.setColor(QPalette::Base, theme.inputBg);
    palette.setColor(QPalette::AlternateBase, theme.cardBg);
    palette.setColor(QPalette::Text, theme.textPrimary);
    palette.setColor(QPalette::Button, theme.cardBg);
    palette.setColor(QPalette::ButtonText, theme.textPrimary);
    palette.setColor(QPalette::Highlight, theme.accentColor);
    palette.setColor(QPalette::HighlightedText, theme.buttonPrimaryText);
#if QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)
    palette.setColor(
        QPalette::PlaceholderText,
        settingsBlend(theme.textSecondary, theme.inputBg, 0.48));
#endif
    dialog->setPalette(palette);
    dialog->update();
}

static QWidget* resolveDeferredSettingsHostWindow()
{
    QWidget* host = resolveSettingsThemeSource(nullptr);
    if (host == nullptr || !host->isVisible())
        return nullptr;
    if (host->inherits("QDialog")
        || host->inherits("QMessageBox")
        || host->inherits("QMenu")
        || host->inherits("QToolTip"))
    {
        return nullptr;
    }
    return host;
}

static bool& welcomeSettingsDialogPending()
{
    static bool pending = false;
    return pending;
}

static void queueWelcomeSettingsDialog(aida_plugin_t* plugin_instance, int attempt)
{
    QObject* app = QApplication::instance();
    if (app == nullptr)
    {
        info(OBFSTR_C("Welcome! Please configure the plugin to begin."));
        SettingsForm::show_and_apply(plugin_instance);
        return;
    }

    if (attempt == 0)
    {
        if (welcomeSettingsDialogPending())
            return;
        welcomeSettingsDialogPending() = true;
    }

    static const int kMaxAttempts = 25;
    static const int kRetryDelayMs = 120;
    const int delayMs = attempt == 0 ? 0 : kRetryDelayMs;

    QTimer::singleShot(delayMs, app, [plugin_instance, attempt]() {
        QWidget* host = resolveDeferredSettingsHostWindow();
        if (host == nullptr && attempt + 1 < kMaxAttempts)
        {
            queueWelcomeSettingsDialog(plugin_instance, attempt + 1);
            return;
        }

        info(OBFSTR_C("Welcome! Please configure the plugin to begin."));

        QObject* appInstance = QApplication::instance();
        if (appInstance != nullptr)
        {
            QTimer::singleShot(0, appInstance, [plugin_instance]() {
                SettingsForm::show_and_apply(plugin_instance);
                welcomeSettingsDialogPending() = false;
            });
        }
        else
        {
            SettingsForm::show_and_apply(plugin_instance);
            welcomeSettingsDialogPending() = false;
        }
    });
}

static QWidget* makeFieldRow(const QString& label, QWidget* field, const QString& tooltip = QString())
{
    QWidget* row = new QWidget();
    QHBoxLayout* lay = new QHBoxLayout(row);
    lay->setContentsMargins(2, 2, 2, 2);
    lay->setSpacing(10);

    QLabel* lbl = new QLabel(label);
    lbl->setObjectName(QStringLiteral("fieldLabel"));
    lbl->setFixedWidth(130);
    lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    if (!tooltip.isEmpty())
    {
        lbl->setToolTip(tooltip);
        field->setToolTip(tooltip);
    }

    lay->addWidget(lbl);
    lay->addWidget(field, 1);
    return row;
}

struct ProviderTabData
{
    QLineEdit*   keyEdit      = nullptr;
    QComboBox*   modelCombo   = nullptr;
    QLineEdit*   urlEdit      = nullptr;
    QLineEdit*   extraKeyEdit = nullptr;
    QSpinBox*    ctxWindowSpin= nullptr;
    QPushButton* refreshBtn   = nullptr;
};

static QWidget* buildProviderTab(
    const QString& providerName,
    const SettingsTheme& theme,
    const std::vector<std::string>& models,
    const std::string& currentModel,
    const std::string& apiKey,
    const std::string& baseUrl,
    ProviderTabData& out)
{
    (void)theme;
    QWidget* page = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(page);
    layout->setContentsMargins(8, 6, 8, 4);
    layout->setSpacing(3);

    out.keyEdit = new QLineEdit(QString::fromStdString(apiKey));
    out.keyEdit->setEchoMode(QLineEdit::Password);
    out.keyEdit->setPlaceholderText(QStringLiteral("Enter your %1 API key...").arg(providerName));
    layout->addWidget(makeFieldRow(QStringLiteral("API Key"), out.keyEdit,
        QStringLiteral("Your %1 API key").arg(providerName)));

    out.modelCombo = new QComboBox();
    out.modelCombo->setEditable(true);
    out.modelCombo->setInsertPolicy(QComboBox::NoInsert);
    int selectedIdx = 0;
    for (size_t i = 0; i < models.size(); ++i)
    {
        out.modelCombo->addItem(QString::fromStdString(models[i]));
        if (models[i] == currentModel)
            selectedIdx = static_cast<int>(i);
    }
    if (!currentModel.empty())
    {
        bool found = false;
        for (const auto& m : models)
            if (m == currentModel) { found = true; break; }
        if (!found)
        {
            out.modelCombo->addItem(QString::fromStdString(currentModel));
            selectedIdx = out.modelCombo->count() - 1;
        }
    }
    out.modelCombo->setCurrentIndex(selectedIdx);

    QWidget* modelRow = new QWidget();
    QHBoxLayout* modelRowLay = new QHBoxLayout(modelRow);
    modelRowLay->setContentsMargins(2, 2, 2, 2);
    modelRowLay->setSpacing(6);
    QLabel* modelLbl = new QLabel(QStringLiteral("Model"));
    modelLbl->setObjectName(QStringLiteral("fieldLabel"));
    modelLbl->setFixedWidth(130);
    modelLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    modelRowLay->addWidget(modelLbl);
    modelRowLay->addWidget(out.modelCombo, 1);
    out.refreshBtn = new QPushButton(QStringLiteral("Refresh"));
    out.refreshBtn->setObjectName(QStringLiteral("secondaryBtn"));
    out.refreshBtn->setToolTip(QStringLiteral("Fetch available models from the API endpoint"));
    out.refreshBtn->setFixedWidth(80);
    modelRowLay->addWidget(out.refreshBtn);
    layout->addWidget(modelRow);

    if (!providerName.isEmpty())
    {
        out.urlEdit = new QLineEdit(QString::fromStdString(baseUrl));
        out.urlEdit->setPlaceholderText(QStringLiteral("(optional) Custom endpoint URL"));
        layout->addWidget(makeFieldRow(QStringLiteral("Base URL"), out.urlEdit,
            QStringLiteral("Override the default %1 API endpoint").arg(providerName)));
    }

    layout->addStretch();
    return page;
}

void SettingsForm::show_and_apply(aida_plugin_t* plugin_instance)
{
    QWidget* idaMainWindow = resolveSettingsThemeSource(QApplication::activeWindow());
    SettingsTheme theme = detectSettingsTheme(idaMainWindow);

    QDialog dlg(idaMainWindow);
    dlg.setObjectName(QString::fromStdString(OBFSTR("aidaSettingsDialog")));
    dlg.setWindowTitle(QString::fromStdString(OBFSTR("AiDA Settings")));
    const QSize baseMinSize(680, 560);
    dlg.setMinimumSize(baseMinSize);

    QVBoxLayout* mainLayout = new QVBoxLayout(&dlg);
    mainLayout->setContentsMargins(18, 12, 18, 10);
    mainLayout->setSpacing(3);

    QLabel* titleLabel = new QLabel(QString::fromStdString(OBFSTR("AiDA Settings")));
    titleLabel->setObjectName(QStringLiteral("sectionHeader"));
    {
        QFont titleFont = titleLabel->font();
        titleFont.setPointSize(12);
        titleFont.setWeight(QFont::Bold);
        titleLabel->setFont(titleFont);
    }
    mainLayout->addWidget(titleLabel);

    QLabel* subtitleLabel = new QLabel(QStringLiteral("Configure your AI provider, model preferences, and analysis parameters"));
    subtitleLabel->setObjectName(QStringLiteral("sectionSubtitle"));
    mainLayout->addWidget(subtitleLabel);

    QFrame* headerAccent = new QFrame();
    headerAccent->setObjectName(QStringLiteral("headerAccentBar"));
    headerAccent->setFrameShape(QFrame::HLine);
    mainLayout->addWidget(headerAccent);

    mainLayout->addSpacing(4);

    static const char* const providers_list_items[] = {
        "Gemini", "OpenAI", "OpenRouter", "Anthropic", "Copilot", "Local LLM"
    };
    const int num_providers = 6;

    qstring provider_setting = g_settings.api_provider.c_str();
    provider_setting = ida_utils::qstring_tolower(provider_setting.c_str());
    int provider_idx = 0;
    if (provider_setting == OBFSTR_C("openai"))          provider_idx = 1;
    else if (provider_setting == OBFSTR_C("openrouter")) provider_idx = 2;
    else if (provider_setting == OBFSTR_C("anthropic"))  provider_idx = 3;
    else if (provider_setting == OBFSTR_C("copilot"))    provider_idx = 4;
    else if (provider_setting == OBFSTR_C("local llm"))  provider_idx = 5;

    QComboBox* providerCombo = new QComboBox();
    for (int i = 0; i < num_providers; ++i)
        providerCombo->addItem(QString::fromLatin1(providers_list_items[i]));
    providerCombo->setCurrentIndex(provider_idx);
    mainLayout->addWidget(makeFieldRow(QStringLiteral("API Provider"), providerCombo));

    mainLayout->addSpacing(2);

    QTabWidget* tabs = new QTabWidget();

    auto find_model_index = [](const std::vector<std::string>& models, const std::string& name) -> int {
        auto it = std::find(models.begin(), models.end(), name);
        if (it == models.end())
            return 0;
        return static_cast<int>(std::distance(models.begin(), it));
    };

    std::vector<std::string> gemini_models_vec;
    if (provider_idx == 0)
        gemini_models_vec = fetch_gemini_models_via_api(g_settings.gemini_api_key.c_str(), g_settings.gemini_base_url.c_str());
    if (gemini_models_vec.empty())
        gemini_models_vec = settings_t::gemini_models;

    std::vector<std::string> openai_models_vec;
    if (provider_idx == 1)
        openai_models_vec = fetch_openai_models_via_api(g_settings.openai_api_key.c_str(), g_settings.openai_base_url.c_str());
    if (openai_models_vec.empty())
        openai_models_vec = settings_t::openai_models;

    std::vector<std::string> openrouter_models_vec;
    if (provider_idx == 2)
        openrouter_models_vec = fetch_openrouter_models_via_api(g_settings.openrouter_api_key.c_str());
    if (openrouter_models_vec.empty())
        openrouter_models_vec = settings_t::openrouter_models;

    std::vector<std::string> anthropic_models_vec;
    if (provider_idx == 3)
        anthropic_models_vec = fetch_anthropic_models_via_api(g_settings.anthropic_api_key.c_str(), g_settings.anthropic_base_url.c_str());
    if (anthropic_models_vec.empty())
        anthropic_models_vec = settings_t::anthropic_models;

    std::vector<std::string> copilot_models_vec;
    if (provider_idx == 4)
        copilot_models_vec = fetch_copilot_models_via_api(g_settings.copilot_proxy_address.c_str());
    if (copilot_models_vec.empty())
        copilot_models_vec = settings_t::copilot_models;

    std::vector<std::string> local_llm_models_vec;
    if (provider_idx == 5)
        local_llm_models_vec = fetch_local_llm_models_via_api(g_settings.local_llm_base_url.c_str());
    if (local_llm_models_vec.empty())
        local_llm_models_vec = settings_t::local_llm_models;

    ProviderTabData geminiTab, openaiTab, openrouterTab, anthropicTab, copilotTab, localLlmTab;

    tabs->addTab(
        buildProviderTab(QStringLiteral("Gemini"), theme,
            gemini_models_vec, g_settings.gemini_model_name,
            g_settings.gemini_api_key, g_settings.gemini_base_url, geminiTab),
        QStringLiteral("Gemini"));

    tabs->addTab(
        buildProviderTab(QStringLiteral("OpenAI"), theme,
            openai_models_vec, g_settings.openai_model_name,
            g_settings.openai_api_key, g_settings.openai_base_url, openaiTab),
        QStringLiteral("OpenAI"));

    {
        QWidget* orPage = new QWidget();
        QVBoxLayout* orLay = new QVBoxLayout(orPage);
        orLay->setContentsMargins(8, 6, 8, 4);
        orLay->setSpacing(3);

        openrouterTab.keyEdit = new QLineEdit(QString::fromStdString(g_settings.openrouter_api_key));
        openrouterTab.keyEdit->setEchoMode(QLineEdit::Password);
        openrouterTab.keyEdit->setPlaceholderText(QStringLiteral("Enter your OpenRouter API key..."));
        orLay->addWidget(makeFieldRow(QStringLiteral("API Key"), openrouterTab.keyEdit));

        openrouterTab.modelCombo = new QComboBox();
        openrouterTab.modelCombo->setEditable(true);
        openrouterTab.modelCombo->setInsertPolicy(QComboBox::NoInsert);
        int orIdx = 0;
        for (size_t i = 0; i < openrouter_models_vec.size(); ++i)
        {
            openrouterTab.modelCombo->addItem(QString::fromStdString(openrouter_models_vec[i]));
            if (openrouter_models_vec[i] == g_settings.openrouter_model_name)
                orIdx = static_cast<int>(i);
        }
        if (!g_settings.openrouter_model_name.empty())
        {
            bool found = false;
            for (const auto& m : openrouter_models_vec)
                if (m == g_settings.openrouter_model_name) { found = true; break; }
            if (!found)
            {
                openrouterTab.modelCombo->addItem(QString::fromStdString(g_settings.openrouter_model_name));
                orIdx = openrouterTab.modelCombo->count() - 1;
            }
        }
        openrouterTab.modelCombo->setCurrentIndex(orIdx);
        {
            QWidget* orModelRow = new QWidget();
            QHBoxLayout* orModelRowLay = new QHBoxLayout(orModelRow);
            orModelRowLay->setContentsMargins(2, 2, 2, 2);
            orModelRowLay->setSpacing(6);
            QLabel* orModelLbl = new QLabel(QStringLiteral("Model"));
            orModelLbl->setObjectName(QStringLiteral("fieldLabel"));
            orModelLbl->setFixedWidth(130);
            orModelLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            orModelRowLay->addWidget(orModelLbl);
            orModelRowLay->addWidget(openrouterTab.modelCombo, 1);
            openrouterTab.refreshBtn = new QPushButton(QStringLiteral("Refresh"));
            openrouterTab.refreshBtn->setObjectName(QStringLiteral("secondaryBtn"));
            openrouterTab.refreshBtn->setToolTip(QStringLiteral("Fetch available models from the API endpoint"));
            openrouterTab.refreshBtn->setFixedWidth(80);
            orModelRowLay->addWidget(openrouterTab.refreshBtn);
            orLay->addWidget(orModelRow);
        }
        orLay->addStretch();
        tabs->addTab(orPage, QStringLiteral("OpenRouter"));
    }

    tabs->addTab(
        buildProviderTab(QStringLiteral("Anthropic"), theme,
            anthropic_models_vec, g_settings.anthropic_model_name,
            g_settings.anthropic_api_key, g_settings.anthropic_base_url, anthropicTab),
        QStringLiteral("Anthropic"));

    {
        QWidget* copPage = new QWidget();
        QVBoxLayout* copLay = new QVBoxLayout(copPage);
        copLay->setContentsMargins(8, 6, 8, 4);
        copLay->setSpacing(3);

        copilotTab.urlEdit = new QLineEdit(QString::fromStdString(g_settings.copilot_proxy_address));
        copilotTab.urlEdit->setPlaceholderText(QStringLiteral("http://127.0.0.1:4141"));
        copLay->addWidget(makeFieldRow(QStringLiteral("Proxy Address"), copilotTab.urlEdit,
            QStringLiteral("Copilot API proxy address")));

        copilotTab.modelCombo = new QComboBox();
        copilotTab.modelCombo->setEditable(true);
        copilotTab.modelCombo->setInsertPolicy(QComboBox::NoInsert);
        int copIdx = 0;
        for (size_t i = 0; i < copilot_models_vec.size(); ++i)
        {
            copilotTab.modelCombo->addItem(QString::fromStdString(copilot_models_vec[i]));
            if (copilot_models_vec[i] == g_settings.copilot_model_name)
                copIdx = static_cast<int>(i);
        }
        if (!g_settings.copilot_model_name.empty())
        {
            bool found = false;
            for (const auto& m : copilot_models_vec)
                if (m == g_settings.copilot_model_name) { found = true; break; }
            if (!found)
            {
                copilotTab.modelCombo->addItem(QString::fromStdString(g_settings.copilot_model_name));
                copIdx = copilotTab.modelCombo->count() - 1;
            }
        }
        copilotTab.modelCombo->setCurrentIndex(copIdx);
        {
            QWidget* copModelRow = new QWidget();
            QHBoxLayout* copModelRowLay = new QHBoxLayout(copModelRow);
            copModelRowLay->setContentsMargins(2, 2, 2, 2);
            copModelRowLay->setSpacing(6);
            QLabel* copModelLbl = new QLabel(QStringLiteral("Model"));
            copModelLbl->setObjectName(QStringLiteral("fieldLabel"));
            copModelLbl->setFixedWidth(130);
            copModelLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            copModelRowLay->addWidget(copModelLbl);
            copModelRowLay->addWidget(copilotTab.modelCombo, 1);
            copilotTab.refreshBtn = new QPushButton(QStringLiteral("Refresh"));
            copilotTab.refreshBtn->setObjectName(QStringLiteral("secondaryBtn"));
            copilotTab.refreshBtn->setToolTip(QStringLiteral("Fetch available models from the API endpoint"));
            copilotTab.refreshBtn->setFixedWidth(80);
            copModelRowLay->addWidget(copilotTab.refreshBtn);
            copLay->addWidget(copModelRow);
        }

        {
            QWidget* accountRow = new QWidget();
            QHBoxLayout* accountLay = new QHBoxLayout(accountRow);
            accountLay->setContentsMargins(2, 6, 2, 2);
            accountLay->setSpacing(6);

            QLabel* accountLbl = new QLabel(QStringLiteral("Account"));
            accountLbl->setObjectName(QStringLiteral("fieldLabel"));
            accountLbl->setFixedWidth(130);
            accountLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            accountLay->addWidget(accountLbl);

            QLabel* copilotUserLabel = new QLabel(QStringLiteral("Checking..."));
            copilotUserLabel->setObjectName(QStringLiteral("copilotAccountStatus"));
            copilotUserLabel->setStyleSheet(QStringLiteral(
                "QLabel { font-style: italic; padding: 2px 6px; }"));
            accountLay->addWidget(copilotUserLabel, 1);

            QPushButton* switchAccountBtn = new QPushButton(QStringLiteral("Switch Account"));
            switchAccountBtn->setObjectName(QStringLiteral("secondaryBtn"));
            switchAccountBtn->setToolTip(QStringLiteral(
                "Open a terminal to re-authenticate your GitHub Copilot account"));
            switchAccountBtn->setFixedWidth(120);
            accountLay->addWidget(switchAccountBtn);
            copLay->addWidget(accountRow);


            auto refreshUser = [copilotUserLabel]() {
                std::thread([copilotUserLabel]() {
                    std::string user = fetch_copilot_github_user();
                    QMetaObject::invokeMethod(copilotUserLabel, [copilotUserLabel, user]() {
                        if (user.empty())
                            copilotUserLabel->setText(QStringLiteral("Not logged in"));
                        else
                        {
                            copilotUserLabel->setText(
                                QStringLiteral("Logged in as <b>%1</b>").arg(QString::fromStdString(user)));
                            msg("AiDA: Copilot account — Logged in as %s\n", user.c_str());
                        }
                    });
                }).detach();
            };


            refreshUser();


            QTimer* authTimer = new QTimer(copPage);
            QObject::connect(authTimer, &QTimer::timeout, copilotUserLabel, refreshUser);
            authTimer->start(30000);


            QObject::connect(switchAccountBtn, &QPushButton::clicked, copilotUserLabel,
                [refreshUser]() {
#ifdef __NT__
                    STARTUPINFOW si = {};
                    si.cb = sizeof(si);
                    si.dwFlags = STARTF_USESHOWWINDOW;
                    si.wShowWindow = SW_SHOW;
                    PROCESS_INFORMATION pi = {};

                    wchar_t cmdline[512] = {};
                    wcscpy_s(cmdline, _countof(cmdline),
                             L"cmd.exe /c npx copilot-api@latest auth & pause");

                    DWORD flags = CREATE_NEW_CONSOLE;
                    if (CreateProcessW(nullptr, cmdline, nullptr, nullptr, FALSE,
                        flags, nullptr, nullptr, &si, &pi))
                    {
                        msg("AiDA: Launched Copilot auth — complete the login in the CMD window.\n");


                        std::thread([pi, refreshUser]() {
                            WaitForSingleObject(pi.hProcess, INFINITE);
                            CloseHandle(pi.hProcess);
                            CloseHandle(pi.hThread);


                            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
                            refreshUser();
                        }).detach();
                    }
                    else
                    {
                        DWORD err = GetLastError();
                        msg("AiDA: Failed to launch Copilot auth (error %lu). "
                            "Ensure Node.js and npx are installed.\n",
                            static_cast<unsigned long>(err));
                    }
#endif
                });
        }

        copLay->addStretch();
        tabs->addTab(copPage, QStringLiteral("Copilot"));
    }

    {
        QWidget* llmPage = new QWidget();
        QVBoxLayout* llmLay = new QVBoxLayout(llmPage);
        llmLay->setContentsMargins(8, 6, 8, 4);
        llmLay->setSpacing(3);

        localLlmTab.urlEdit = new QLineEdit(QString::fromStdString(g_settings.local_llm_base_url));
        localLlmTab.urlEdit->setPlaceholderText(QStringLiteral("http://localhost:11434"));
        llmLay->addWidget(makeFieldRow(QStringLiteral("Server URL"), localLlmTab.urlEdit));

        localLlmTab.modelCombo = new QComboBox();
        localLlmTab.modelCombo->setEditable(true);
        localLlmTab.modelCombo->setInsertPolicy(QComboBox::NoInsert);
        int llmIdx = 0;
        for (size_t i = 0; i < local_llm_models_vec.size(); ++i)
        {
            localLlmTab.modelCombo->addItem(QString::fromStdString(local_llm_models_vec[i]));
            if (local_llm_models_vec[i] == g_settings.local_llm_model_name)
                llmIdx = static_cast<int>(i);
        }
        if (!g_settings.local_llm_model_name.empty())
        {
            bool found = false;
            for (const auto& m : local_llm_models_vec)
                if (m == g_settings.local_llm_model_name) { found = true; break; }
            if (!found)
            {
                localLlmTab.modelCombo->addItem(QString::fromStdString(g_settings.local_llm_model_name));
                llmIdx = localLlmTab.modelCombo->count() - 1;
            }
        }
        localLlmTab.modelCombo->setCurrentIndex(llmIdx);
        {
            QWidget* llmModelRow = new QWidget();
            QHBoxLayout* llmModelRowLay = new QHBoxLayout(llmModelRow);
            llmModelRowLay->setContentsMargins(2, 2, 2, 2);
            llmModelRowLay->setSpacing(6);
            QLabel* llmModelLbl = new QLabel(QStringLiteral("Model"));
            llmModelLbl->setObjectName(QStringLiteral("fieldLabel"));
            llmModelLbl->setFixedWidth(130);
            llmModelLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            llmModelRowLay->addWidget(llmModelLbl);
            llmModelRowLay->addWidget(localLlmTab.modelCombo, 1);
            localLlmTab.refreshBtn = new QPushButton(QStringLiteral("Refresh"));
            localLlmTab.refreshBtn->setObjectName(QStringLiteral("secondaryBtn"));
            localLlmTab.refreshBtn->setToolTip(QStringLiteral("Fetch available models from the API endpoint"));
            localLlmTab.refreshBtn->setFixedWidth(80);
            llmModelRowLay->addWidget(localLlmTab.refreshBtn);
            llmLay->addWidget(llmModelRow);
        }

        localLlmTab.extraKeyEdit = new QLineEdit(QString::fromStdString(g_settings.local_llm_api_key));
        localLlmTab.extraKeyEdit->setEchoMode(QLineEdit::Password);
        localLlmTab.extraKeyEdit->setPlaceholderText(QStringLiteral("(optional) API key"));
        llmLay->addWidget(makeFieldRow(QStringLiteral("API Key"), localLlmTab.extraKeyEdit));

        localLlmTab.ctxWindowSpin = new QSpinBox();
        localLlmTab.ctxWindowSpin->setRange(512, 2097152);
        localLlmTab.ctxWindowSpin->setSingleStep(1024);
        localLlmTab.ctxWindowSpin->setValue(g_settings.local_llm_context_window);
        llmLay->addWidget(makeFieldRow(QStringLiteral("Context Window"), localLlmTab.ctxWindowSpin));

        llmLay->addStretch();
        tabs->addTab(llmPage, QStringLiteral("Local LLM"));
    }

    tabs->setCurrentIndex(provider_idx);

    QObject::connect(providerCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
        [tabs](int idx) { if (idx >= 0 && idx < tabs->count()) tabs->setCurrentIndex(idx); });

    auto repopulateModels = [](QComboBox* combo, const std::vector<std::string>& models) {
        QString prev = combo->currentText();
        combo->clear();
        int selIdx = 0;
        for (size_t i = 0; i < models.size(); ++i)
        {
            combo->addItem(QString::fromStdString(models[i]));
            if (QString::fromStdString(models[i]) == prev)
                selIdx = static_cast<int>(i);
        }
        if (!prev.isEmpty())
        {
            bool found = false;
            for (int i = 0; i < combo->count(); ++i)
                if (combo->itemText(i) == prev) { found = true; break; }
            if (!found)
            {
                combo->addItem(prev);
                selIdx = combo->count() - 1;
            }
        }
        combo->setCurrentIndex(selIdx);
    };


    QObject::connect(geminiTab.refreshBtn, &QPushButton::clicked,
        [&geminiTab, repopulateModels]() {
            qstring key(geminiTab.keyEdit->text().toUtf8().constData());
            qstring url(geminiTab.urlEdit ? geminiTab.urlEdit->text().trimmed().toUtf8().constData() : "");
            auto models = fetch_gemini_models_via_api(key, url);
            if (models.empty())
                models = settings_t::gemini_models;
            repopulateModels(geminiTab.modelCombo, models);
        });


    QObject::connect(openaiTab.refreshBtn, &QPushButton::clicked,
        [&openaiTab, repopulateModels]() {
            qstring key(openaiTab.keyEdit->text().toUtf8().constData());
            qstring url(openaiTab.urlEdit ? openaiTab.urlEdit->text().trimmed().toUtf8().constData() : "");
            auto models = fetch_openai_models_via_api(key, url);
            if (models.empty())
                models = settings_t::openai_models;
            repopulateModels(openaiTab.modelCombo, models);
        });


    QObject::connect(openrouterTab.refreshBtn, &QPushButton::clicked,
        [&openrouterTab, repopulateModels]() {
            qstring key(openrouterTab.keyEdit->text().toUtf8().constData());
            auto models = fetch_openrouter_models_via_api(key);
            if (models.empty())
                models = settings_t::openrouter_models;
            repopulateModels(openrouterTab.modelCombo, models);
        });


    QObject::connect(anthropicTab.refreshBtn, &QPushButton::clicked,
        [&anthropicTab, repopulateModels]() {
            qstring key(anthropicTab.keyEdit->text().toUtf8().constData());
            qstring url(anthropicTab.urlEdit ? anthropicTab.urlEdit->text().trimmed().toUtf8().constData() : "");
            auto models = fetch_anthropic_models_via_api(key, url);
            if (models.empty())
                models = settings_t::anthropic_models;
            repopulateModels(anthropicTab.modelCombo, models);
        });


    QObject::connect(copilotTab.refreshBtn, &QPushButton::clicked,
        [&copilotTab, repopulateModels]() {
            qstring url(copilotTab.urlEdit->text().trimmed().toUtf8().constData());
            auto models = fetch_copilot_models_via_api(url);
            if (models.empty())
                models = settings_t::copilot_models;
            repopulateModels(copilotTab.modelCombo, models);
        });


    QObject::connect(localLlmTab.refreshBtn, &QPushButton::clicked,
        [&localLlmTab, repopulateModels]() {
            qstring url(localLlmTab.urlEdit->text().trimmed().toUtf8().constData());
            auto models = fetch_local_llm_models_via_api(url);
            if (models.empty())
                models = settings_t::local_llm_models;
            repopulateModels(localLlmTab.modelCombo, models);
        });

    mainLayout->addWidget(tabs, 0);

    QGroupBox* generalGroup = new QGroupBox(QStringLiteral("General Settings"));
    QVBoxLayout* generalLay = new QVBoxLayout(generalGroup);
    generalLay->setContentsMargins(10, 18, 10, 6);
    generalLay->setSpacing(2);

    QComboBox* promptCombo = new QComboBox();
    promptCombo->addItem(QStringLiteral("Default (Game Hacking)"));
    std::vector<std::string> prompt_keys;
    for (const auto& pair : g_settings.custom_prompts)
        prompt_keys.push_back(pair.first);
    std::sort(prompt_keys.begin(), prompt_keys.end());
    for (const auto& key : prompt_keys)
        promptCombo->addItem(QString::fromStdString(key));

    int active_prompt_idx = 0;
    if (!g_settings.active_prompt_name.empty())
    {
        auto it = std::find(prompt_keys.begin(), prompt_keys.end(), g_settings.active_prompt_name);
        if (it != prompt_keys.end())
            active_prompt_idx = 1 + static_cast<int>(std::distance(prompt_keys.begin(), it));
    }
    promptCombo->setCurrentIndex(active_prompt_idx);

    QWidget* promptRow = new QWidget();
    QHBoxLayout* promptRowLay = new QHBoxLayout(promptRow);
    promptRowLay->setContentsMargins(2, 2, 2, 2);
    promptRowLay->setSpacing(6);

    QLabel* promptLbl = new QLabel(QStringLiteral("System Prompt"));
    promptLbl->setObjectName(QStringLiteral("fieldLabel"));
    promptLbl->setFixedWidth(130);
    promptLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    promptRowLay->addWidget(promptLbl);
    promptRowLay->addWidget(promptCombo, 1);

    QPushButton* managePromptsBtn = new QPushButton(QStringLiteral("Manage"));
    managePromptsBtn->setObjectName(QStringLiteral("secondaryBtn"));
    managePromptsBtn->setToolTip(QStringLiteral("Add, edit, or delete custom system prompts"));
    managePromptsBtn->setFixedWidth(80);
    QObject::connect(managePromptsBtn, &QPushButton::clicked, [promptCombo, &prompt_keys]() {
        show_prompt_manager_dialog();

        int prevIdx = promptCombo->currentIndex();
        QString prevText = promptCombo->currentText();
        promptCombo->clear();
        promptCombo->addItem(QStringLiteral("Default (Game Hacking)"));

        prompt_keys.clear();
        for (const auto& pair : g_settings.custom_prompts)
            prompt_keys.push_back(pair.first);
        std::sort(prompt_keys.begin(), prompt_keys.end());
        for (const auto& key : prompt_keys)
            promptCombo->addItem(QString::fromStdString(key));

        int newIdx = promptCombo->findText(prevText);
        if (newIdx >= 0)
            promptCombo->setCurrentIndex(newIdx);
        else
            promptCombo->setCurrentIndex(0);
    });
    promptRowLay->addWidget(managePromptsBtn);
    generalLay->addWidget(promptRow);

    QSpinBox* xrefCountSpin = new QSpinBox();
    xrefCountSpin->setRange(0, 100);
    xrefCountSpin->setValue(g_settings.xref_context_count);
    generalLay->addWidget(makeFieldRow(QStringLiteral("XRef Context Count"), xrefCountSpin,
        QStringLiteral("Number of cross-references to include in analysis context")));

    QSpinBox* xrefDepthSpin = new QSpinBox();
    xrefDepthSpin->setRange(0, 20);
    xrefDepthSpin->setValue(g_settings.xref_analysis_depth);
    generalLay->addWidget(makeFieldRow(QStringLiteral("XRef Analysis Depth"), xrefDepthSpin,
        QStringLiteral("Depth of cross-reference traversal")));

    QSpinBox* snippetLinesSpin = new QSpinBox();
    snippetLinesSpin->setRange(1, 500);
    snippetLinesSpin->setValue(g_settings.xref_code_snippet_lines);
    generalLay->addWidget(makeFieldRow(QStringLiteral("Code Snippet Lines"), snippetLinesSpin,
        QStringLiteral("Number of code lines to include per referenced function")));

    QDoubleSpinBox* delaySpin = new QDoubleSpinBox();
    delaySpin->setRange(0.0, 60.0);
    delaySpin->setSingleStep(0.25);
    delaySpin->setDecimals(2);
    delaySpin->setValue(g_settings.bulk_processing_delay);
    generalLay->addWidget(makeFieldRow(QStringLiteral("Bulk Delay (sec)"), delaySpin,
        QStringLiteral("Delay in seconds between bulk processing operations")));

    QDoubleSpinBox* tempSpin = new QDoubleSpinBox();
    tempSpin->setRange(0.0, 2.0);
    tempSpin->setSingleStep(0.05);
    tempSpin->setDecimals(2);
    tempSpin->setValue(g_settings.temperature);
    generalLay->addWidget(makeFieldRow(QStringLiteral("Temperature"), tempSpin,
        QStringLiteral("Model temperature (lower = more deterministic)")));

    mainLayout->addWidget(generalGroup);

    QGroupBox* mcpGroup = new QGroupBox(QStringLiteral("MCP Server"));
    QVBoxLayout* mcpLay = new QVBoxLayout(mcpGroup);
    mcpLay->setContentsMargins(10, 18, 10, 6);
    mcpLay->setSpacing(2);

    QCheckBox* mcpEnabledCheck = new QCheckBox(QStringLiteral("Enable MCP Server"));
    mcpEnabledCheck->setChecked(g_settings.mcp_enabled);
    mcpEnabledCheck->setToolTip(QStringLiteral("Enable the Model Context Protocol server for external tool integration"));
    mcpLay->addWidget(makeFieldRow(QStringLiteral("MCP Enabled"), mcpEnabledCheck));

    QSpinBox* mcpPortSpin = new QSpinBox();
    mcpPortSpin->setRange(1024, 65535);
    mcpPortSpin->setValue(g_settings.mcp_port);
    mcpPortSpin->setToolTip(QStringLiteral("TCP port for the MCP server"));
    mcpLay->addWidget(makeFieldRow(QStringLiteral("MCP Port"), mcpPortSpin,
        QStringLiteral("Port number for the MCP server (requires restart)")));

    mainLayout->addWidget(mcpGroup);
    mainLayout->addStretch(1);

    mainLayout->addSpacing(4);

    QHBoxLayout* btnRow = new QHBoxLayout();
    btnRow->setSpacing(14);
    btnRow->addStretch();

    QPushButton* cancelBtn = new QPushButton(QStringLiteral("Cancel"));
    cancelBtn->setObjectName(QStringLiteral("secondaryBtn"));
    QObject::connect(cancelBtn, &QPushButton::clicked, &dlg, &QDialog::reject);
    btnRow->addWidget(cancelBtn);

    QPushButton* okBtn = new QPushButton(QStringLiteral("Save"));
    okBtn->setObjectName(QStringLiteral("primaryBtn"));
    okBtn->setDefault(true);
    QObject::connect(okBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    btnRow->addWidget(okBtn);

    mainLayout->addLayout(btnRow);

    applySettingsDialogTheme(&dlg, idaMainWindow);

    dlg.ensurePolished();
    if (QLayout* layout = dlg.layout())
    {
        layout->invalidate();
        layout->activate();
    }

    QSize effectiveMinSize = baseMinSize;
    if (QScreen* screen = dlg.screen())
    {
        const QRect avail = screen->availableGeometry();
        const int maxWidth = qMax(480, static_cast<int>(avail.width() * 0.92));
        const int maxHeight = qMax(420, static_cast<int>(avail.height() * 0.92));
        effectiveMinSize.setWidth(qMin(effectiveMinSize.width(), maxWidth));
        effectiveMinSize.setHeight(qMin(effectiveMinSize.height(), maxHeight));
    }

    dlg.setMinimumSize(effectiveMinSize);
    QSize initialSize = dlg.sizeHint().expandedTo(effectiveMinSize);
    if (QScreen* screen = dlg.screen())
    {
        const QRect avail = screen->availableGeometry();
        const int maxWidth = qMax(480, static_cast<int>(avail.width() * 0.92));
        const int maxHeight = qMax(420, static_cast<int>(avail.height() * 0.92));
        initialSize.setWidth(qMin(initialSize.width(), maxWidth));
        initialSize.setHeight(qMin(initialSize.height(), maxHeight));
    }
    dlg.resize(initialSize);

    QTimer::singleShot(0, &dlg, [&dlg, idaMainWindow]() {
        applySettingsDialogTheme(&dlg, idaMainWindow);
    });

    if (dlg.exec() != QDialog::Accepted)
        return;

    int selectedProvider = providerCombo->currentIndex();
    if (selectedProvider >= 0 && selectedProvider < num_providers)
        g_settings.api_provider = providers_list_items[selectedProvider];

    if (geminiTab.keyEdit)
        g_settings.gemini_api_key = geminiTab.keyEdit->text().toStdString();
    if (geminiTab.modelCombo)
        g_settings.gemini_model_name = geminiTab.modelCombo->currentText().toStdString();
    if (geminiTab.urlEdit)
        g_settings.gemini_base_url = geminiTab.urlEdit->text().toStdString();

    if (openaiTab.keyEdit)
        g_settings.openai_api_key = openaiTab.keyEdit->text().toStdString();
    if (openaiTab.modelCombo)
        g_settings.openai_model_name = openaiTab.modelCombo->currentText().toStdString();
    if (openaiTab.urlEdit)
        g_settings.openai_base_url = openaiTab.urlEdit->text().toStdString();

    if (openrouterTab.keyEdit)
        g_settings.openrouter_api_key = openrouterTab.keyEdit->text().toStdString();
    if (openrouterTab.modelCombo)
        g_settings.openrouter_model_name = openrouterTab.modelCombo->currentText().toStdString();

    if (anthropicTab.keyEdit)
        g_settings.anthropic_api_key = anthropicTab.keyEdit->text().toStdString();
    if (anthropicTab.modelCombo)
        g_settings.anthropic_model_name = anthropicTab.modelCombo->currentText().toStdString();
    if (anthropicTab.urlEdit)
        g_settings.anthropic_base_url = anthropicTab.urlEdit->text().toStdString();

    if (copilotTab.urlEdit)
        g_settings.copilot_proxy_address = copilotTab.urlEdit->text().toStdString();
    if (copilotTab.modelCombo)
        g_settings.copilot_model_name = copilotTab.modelCombo->currentText().toStdString();

    if (localLlmTab.urlEdit)
        g_settings.local_llm_base_url = localLlmTab.urlEdit->text().toStdString();
    if (localLlmTab.modelCombo)
        g_settings.local_llm_model_name = localLlmTab.modelCombo->currentText().toStdString();
    if (localLlmTab.extraKeyEdit)
        g_settings.local_llm_api_key = localLlmTab.extraKeyEdit->text().toStdString();
    if (localLlmTab.ctxWindowSpin)
        g_settings.local_llm_context_window = localLlmTab.ctxWindowSpin->value();

    g_settings.xref_context_count      = xrefCountSpin->value();
    g_settings.xref_analysis_depth     = xrefDepthSpin->value();
    g_settings.xref_code_snippet_lines = snippetLinesSpin->value();
    g_settings.bulk_processing_delay   = delaySpin->value();
    g_settings.temperature             = tempSpin->value();

    g_settings.mcp_enabled = mcpEnabledCheck->isChecked();
    g_settings.mcp_port    = mcpPortSpin->value();

    int selPrompt = promptCombo->currentIndex();
    if (selPrompt == 0)
    {
        g_settings.active_prompt_name.clear();
    }
    else if (selPrompt - 1 < static_cast<int>(prompt_keys.size()))
    {
        g_settings.active_prompt_name = prompt_keys[selPrompt - 1];
    }

    g_settings.save();

    if (plugin_instance)
    {
        msg(OBFSTR_C("AI Assistant: Settings updated. Re-initializing AI client...\n"));
        plugin_instance->reinit_ai_client();
    }
}

void SettingsForm::show_welcome_and_apply_deferred(aida_plugin_t* plugin_instance)
{
    queueWelcomeSettingsDialog(plugin_instance, 0);
}

void idaapi close_handler(TWidget*, void* ud)
{
    strvec_t* lines_ptr = (strvec_t*)ud;
    delete lines_ptr;
}

static QString sanitizeEulaPlainText(const char* rawText)
{
    QString text = QString::fromUtf8(rawText);
    text.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));

    const QStringList lines = text.split(QChar('\n'));
    QStringList cleaned;
    cleaned.reserve(lines.size());

    bool skipHeader = true;
    for (QString line : lines)
    {
        QString trimmed = line.trimmed();

        if (skipHeader)
        {
            if (trimmed == QStringLiteral("# AiDA (Artificial Intelligence Disassembly Assistant)")
                || trimmed == QStringLiteral("## END USER LICENSE AGREEMENT (EULA)"))
            {
                continue;
            }
            if (!trimmed.isEmpty())
                skipHeader = false;
        }

        if (trimmed == QStringLiteral("---") || trimmed == QStringLiteral("***"))
        {
            cleaned.push_back(QString());
            continue;
        }

        if (trimmed.startsWith(QStringLiteral("### ")))
            line = line.mid(line.indexOf(QStringLiteral("### ")) + 4);
        else if (trimmed.startsWith(QStringLiteral("## ")))
            line = line.mid(line.indexOf(QStringLiteral("## ")) + 3);
        else if (trimmed.startsWith(QStringLiteral("# ")))
            line = line.mid(line.indexOf(QStringLiteral("# ")) + 2);

        if (trimmed.startsWith(QStringLiteral("*   ")))
            line = QStringLiteral("- ") + trimmed.mid(4);

        line.replace(QStringLiteral("**"), QString());
        line.replace(QStringLiteral("`") , QString());
        cleaned.push_back(line);
    }

    while (!cleaned.isEmpty() && cleaned.front().trimmed().isEmpty())
        cleaned.pop_front();

    return cleaned.join(QStringLiteral("\n"));
}

bool show_eula_dialog()
{
    static const char eula_text[] = R"EULA(# AiDA (Artificial Intelligence Disassembly Assistant) 
## END USER LICENSE AGREEMENT (EULA)

**IMPORTANT – READ CAREFULLY BEFORE PROCEEDING.**

THIS END USER LICENSE AGREEMENT ("EULA" OR "AGREEMENT") IS A LEGALLY BINDING CONTRACT BETWEEN YOU (EITHER AN INDIVIDUAL OR A SINGLE LEGAL ENTITY, HEREINAFTER REFERRED TO AS "YOU", "YOUR", OR "LICENSEE") AND THE DEVELOPER(S) OF AiDA ("DEVELOPER", "WE", OR "US"). 

THIS AGREEMENT GOVERNS YOUR USE OF THE AiDA IDA PRO PLUGIN, INCLUDING ITS ASSOCIATED DYNAMIC LINK LIBRARIES (`AiDA.dll`), KERNEL-MODE DRIVERS, INTEGRATED SCRIPTS, GRAPH/RAG DATABASES, AND ANY ASSOCIATED ONLINE SERVICES OR PROXY SERVERS (COLLECTIVELY, THE "SOFTWARE").

**BY CLICKING "I AGREE", LOADING THIS PLUGIN INTO IDA PRO, OR OTHERWISE USING THE SOFTWARE, YOU EXPRESSLY ACKNOWLEDGE THAT YOU HAVE READ, UNDERSTOOD, AND UNCONDITIONALLY AGREED TO ALL TERMS AND CONDITIONS HEREIN. IF YOU DO NOT AGREE TO ALL OF THESE TERMS, YOU MUST IMMEDIATELY UNLOAD THE PLUGIN, DELETE ALL COPIES OF THE SOFTWARE FROM YOUR SYSTEM, AND CEASE ALL USE.**

---

### 1. GRANT OF LICENSE
Subject to your strict compliance with the terms and conditions of this Agreement, the Developer grants you a limited, non-exclusive, non-transferable, non-sublicensable, and revocable license to install and use the Software solely for your personal or internal business purposes, strictly in accordance with the Authorized Use defined below.

### 2. STRICT RESTRICTION TO AUTHORIZED USE ONLY (ZERO LIABILITY FOR DEVELOPER)
**2.1. Authorized Targets:** The Software is an exceptionally powerful reverse engineering, network interception, memory dumping, and kernel manipulation suite. You explicitly agree that you will **ONLY** use the Software on computer systems, networks, executables, binaries, memory spaces, and games for which you have explicit, documented, and legal authorization to analyze, reverse engineer, and modify. 
**2.2. Total User Responsibility:** WHAT YOU DO WITH THIS PLUGIN IS COMPLETELY AND SOLELY ON YOU. The Developer provides the Software solely as a neutral tool for educational, security auditing, and authorized analysis purposes. The Developer does not endorse, condone, or support the use of the Software for copyright infringement, unauthorized game hacking, malware development, unauthorized bypassing of digital rights management (DRM), or the subversion of anti-cheat software (e.g., EasyAntiCheat, BattlEye, Vanguard) on live servers or unauthorized targets.
**2.3. Indemnification:** You hereby agree to indemnify, defend, and hold harmless the Developer, its affiliates, and its contributors from and against any and all claims, lawsuits, liabilities, damages, criminal charges, losses, and expenses (including legal fees) arising out of or resulting from your use, misuse, or illegal application of the Software. 

### 3. THIRD-PARTY AI PROVIDERS AND ENDPOINTS (VOLATILITY CLAUSE)
**3.1. Provided Access:** The Software integrates heavily with third-party Large Language Models (LLMs) and AI API providers (including, but not limited to, OpenAI, Google Gemini, Anthropic Claude, OpenRouter, GitHub Copilot, and Local LLMs). The Developer may, at their sole discretion, provide proxy endpoints or bundled API keys to facilitate your initial use of the Software's AI features.
**3.2. No Guarantee of Service:** YOU EXPRESSLY ACKNOWLEDGE AND AGREE THAT THESE AI PROVIDERS, PROXIES, AND BUNDLED ENDPOINTS ARE HIGHLY VOLATILE. They may be rate-limited, banned, shut down, or disappear completely AT ANY MOMENT, WITHOUT PRIOR NOTICE. 
**3.3. Bring Your Own Key (BYOK):** The Developer is under absolutely no obligation to maintain, replace, or fund these AI endpoints. If the provided AI features cease to function, it is solely your responsibility to procure and input your own valid API keys or configure your own local LLM server. The failure of provided AI endpoints does not constitute a defect in the Software and is not grounds for a refund.

### 4. ANTI-REVERSE ENGINEERING AND DESTRUCTIVE SELF-DEFENSE MECHANISMS (CRITICAL)
The Software contains highly proprietary, confidential algorithms pertaining to kernel-level memory access, obfuscation circumvention, and Windows Filtering Platform (WFP) network interception. To protect this intellectual property, the Software is armed with aggressive, active, and destructive self-defense mechanisms.

**BY ACCEPTING THIS AGREEMENT, YOU EXPRESSLY CONSENT TO THE FOLLOWING CONDITIONS:**
**4.1. Prohibition on Analysis:** You shall not decompile, disassemble, reverse engineer, debug, unpack, memory-dump, patch, or otherwise attempt to derive the source code or internal workings of `AiDA.dll` or its associated kernel drivers. You are strictly forbidden from loading the Software's binaries into IDA Pro, Ghidra, x64dbg, or any other analysis tool.
**4.2. Destructive Payloads (BOOT FAILURE):** The Software continually monitors its environment for debuggers, unauthorized memory accesses, hash mismatches, and specific reverse-engineering tools. **IF ANY UNAUTHORIZED ANALYSIS OR TAMPERING IS DETECTED, THE SOFTWARE WILL INITIATE A DESTRUCTIVE SEQUENCE.** 
**4.3. Specific Consequences:** You acknowledge that triggering the Software's self-defense mechanisms will result in:
*   **Irreversible corruption of your Windows Boot Configuration Data (BCD)** via system-level commands (e.g., `bcdedit /clean`), rendering your PC completely unable to boot.
*   An immediate, forced Critical System Failure (Blue Screen of Death / BSOD) via `NtRaiseHardError`.
*   Permanent hardware and IP bans communicated to the Developer's licensing servers.
*   Immediate and permanent revocation of your license without refund.
**4.4. Assumption of Risk:** YOU ACKNOWLEDGE THAT ANY DESTRUCTION TO YOUR OPERATING SYSTEM, LOSS OF DATA, HARDWARE BANS, OR INABILITY TO BOOT YOUR COMPUTER CAUSED BY TRIGGERING THE SOFTWARE'S ANTI-REVERSE ENGINEERING PROTECTIONS IS 100% YOUR FAULT. THE DEVELOPER SHALL BEAR ABSOLUTELY NO LIABILITY FOR ANY DAMAGE, DATA LOSS, OR SYSTEM BRICKING CAUSED BY YOUR ATTEMPT TO ANALYZE OR TAMPER WITH THE SOFTWARE.

### 5. AGGRESSIVE TELEMETRY, PRIVACY, AND DATA COLLECTION
To enforce licensing, prevent Software leaks, and identify unauthorized usage, the Software actively collects and transmits system telemetry to the Developer's cloud servers.
**5.1. Data Collected:** You consent to the collection and transmission of:
*   Your IP Address (Public and Local).
*   Your MAC Address and Network Adapter details.
*   Your Hardware ID (HWID), calculated using CPU metrics and Volume Serial numbers.
*   Your Windows Username and Computer Name.
*   **Your Discord User ID and Username**, which the Software actively harvests from local AppData storage (e.g., LevelDB files associated with Discord, Chrome, Edge, and Brave browsers).
**5.2. Leak Prevention:** If the Software detects that your license is being used on an unauthorized machine, or if the DLL has been shared/leaked, your Discord identity, IP, and HWID will be permanently banned and your license revoked. The Developer reserves the right to publicly publish the identities of users who leak the Software.

### 6. KERNEL DRIVER RISKS AND SYSTEM INSTABILITY
**6.1. Ring 0 Operations:** The Software utilizes an active Windows Kernel-Mode driver (operating at Ring 0) to bypass operating system protections, including PatchGuard, Driver Signature Enforcement (DSE), and memory isolation. The Software performs physical memory translation (Virtual to Physical), Direct Kernel Object Manipulation (DKOM), SSDT/IRP inspection, and WFP callout injection.
**6.2. No Guarantee of Stability:** Modifying the Windows Kernel, manipulating thread contexts remotely, and bypassing anti-cheat hypervisors carries extreme inherent risks. The Software may cause unexpected system crashes (BSODs), system lockups, or data corruption during ordinary use. The Developer provides this functionality entirely "AS-IS" and accepts no liability for system instability resulting from the use of the kernel driver or emulation engines.

### 7. INTELLECTUAL PROPERTY RIGHTS
All title, ownership rights, and intellectual property rights in and to the Software, including any accompanying documentation and any copies thereof, remain the sole property of the Developer. The Software is protected by copyright laws and international copyright treaties, as well as other intellectual property laws and treaties. You agree not to remove, obscure, or alter any copyright, trademark, or other proprietary rights notices affixed to or contained within the Software.

### 8. DISCLAIMER OF WARRANTIES
THE SOFTWARE IS PROVIDED "AS-IS" AND "AS-AVAILABLE", WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND. TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE DEVELOPER EXPRESSLY DISCLAIMS ALL WARRANTIES, WHETHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. THE DEVELOPER DOES NOT WARRANT THAT THE SOFTWARE WILL MEET YOUR REQUIREMENTS, THAT ITS OPERATION WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT DEFECTS IN THE SOFTWARE WILL BE CORRECTED.

### 9. LIMITATION OF LIABILITY
TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE DEVELOPER, ITS AFFILIATES, OR ITS SUPPLIERS BE LIABLE FOR ANY SPECIAL, INCIDENTAL, PUNITIVE, INDIRECT, OR CONSEQUENTIAL DAMAGES WHATSOEVER (INCLUDING, BUT NOT LIMITED TO, DAMAGES FOR LOSS OF PROFITS, LOSS OF CONFIDENTIAL OR OTHER INFORMATION, BUSINESS INTERRUPTION, PERSONAL INJURY, LOSS OF PRIVACY, FAILURE TO MEET ANY DUTY INCLUDING OF GOOD FAITH OR OF REASONABLE CARE, NEGLIGENCE, DESTRUCTION OF BOOT PARTITIONS, CORRUPTION OF OPERATING SYSTEMS, AND ANY OTHER PECUNIARY OR OTHER LOSS WHATSOEVER) ARISING OUT OF OR IN ANY WAY RELATED TO THE USE OF OR INABILITY TO USE THE SOFTWARE, EVEN IF THE DEVELOPER HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

### 10. TERMINATION
This Agreement is effective until terminated. Your rights under this License will terminate automatically without notice from the Developer if you fail to comply with any term(s) of this Agreement (specifically including Section 4). Upon termination of the License, you shall cease all use of the Software and destroy all copies, full or partial, of the Software. Sections 2, 4, 5, 8, and 9 shall survive any termination of this Agreement.

### 11. GOVERNING LAW AND SEVERABILITY
This Agreement shall be governed by and construed in accordance with international legal standards governing software licensing, without regard to conflict of law principles. If any provision of this Agreement is held to be void, invalid, unenforceable, or illegal, the other provisions shall continue in full force and effect.

***

**WARNING: DO NOT CLICK "I AGREE" UNLESS YOU FULLY ACCEPT THE RAMIFICATIONS OF THE DESTRUCTIVE ANTI-REVERSE ENGINEERING MEASURES OUTLINED IN SECTION 4. BY CLICKING "I AGREE", YOU FORFEIT ANY RIGHT TO HOLD THE DEVELOPER RESPONSIBLE FOR DAMAGES CAUSED TO YOUR HARDWARE, SOFTWARE, OR DATA.**
)EULA";

    QWidget* parentWidget = resolveSettingsThemeSource(QApplication::activeWindow());

    QDialog dlg(parentWidget);
    dlg.setWindowTitle(QStringLiteral("AiDA End User License Agreement"));
    dlg.setModal(true);
    dlg.setSizeGripEnabled(false);
    dlg.resize(610, 655);
    dlg.setMinimumSize(610, 655);
    dlg.setMaximumWidth(610);
    dlg.setWindowFlags(dlg.windowFlags() & ~Qt::WindowContextHelpButtonHint);
    if (parentWidget != nullptr)
        dlg.setWindowIcon(parentWidget->windowIcon());

    QVBoxLayout* mainLayout = new QVBoxLayout(&dlg);
    mainLayout->setContentsMargins(12, 10, 12, 12);
    mainLayout->setSpacing(8);

    QLabel* introLabel = new QLabel(
        QStringLiteral("Please read the following End User License Agreement carefully.\n"
                       "You must accept this agreement to use AiDA."),
        &dlg);
    introLabel->setWordWrap(true);
    mainLayout->addWidget(introLabel);

    QTextEdit* eulaView = new QTextEdit(&dlg);
    eulaView->setObjectName(QStringLiteral("aidaEulaTextView"));
    eulaView->setReadOnly(true);
    eulaView->setAcceptRichText(false);
    eulaView->setUndoRedoEnabled(false);
    eulaView->setLineWrapMode(QTextEdit::WidgetWidth);
    eulaView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    eulaView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    eulaView->setPlainText(sanitizeEulaPlainText(eula_text));
    eulaView->moveCursor(QTextCursor::Start);
    mainLayout->addWidget(eulaView, 1);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(8);
    buttonLayout->addStretch(1);

    QPushButton* agreeButton = new QPushButton(QStringLiteral("I Agree"), &dlg);
    QPushButton* disagreeButton = new QPushButton(QStringLiteral("I Disagree"), &dlg);
    agreeButton->setDefault(true);
    agreeButton->setAutoDefault(true);
    disagreeButton->setAutoDefault(false);
    agreeButton->setMinimumWidth(72);
    disagreeButton->setMinimumWidth(72);

    QObject::connect(agreeButton, &QPushButton::clicked, &dlg, &QDialog::accept);
    QObject::connect(disagreeButton, &QPushButton::clicked, &dlg, &QDialog::reject);

    buttonLayout->addWidget(agreeButton);
    buttonLayout->addWidget(disagreeButton);
    buttonLayout->addStretch(1);
    mainLayout->addLayout(buttonLayout);

    eulaView->setFocus();
    return dlg.exec() == QDialog::Accepted;
}

void show_text_in_viewer(const char* title, const std::string& text_content)
{
    if (text_content.empty() || text_content.find_first_not_of(" \t\n\r") == std::string::npos)
    {
        warning(OBFSTR_C("AI returned an empty or whitespace-only response. Nothing to display."));
        return;
    }

    TWidget* existing_viewer = find_widget(title);
    if (existing_viewer)
    {
        close_widget(existing_viewer, WCLS_SAVE);
    }

    strvec_t* lines_ptr = new strvec_t();

    std::string marked_up_content = ida_utils::markup_text_with_addresses(text_content);

    std::stringstream ss(marked_up_content);
    std::string line;
    while (std::getline(ss, line, '\n'))
    {
        lines_ptr->push_back(simpleline_t(line.c_str()));
    }

    simpleline_place_t s1;
    simpleline_place_t s2;
    s2.n = lines_ptr->empty() ? 0 : static_cast<uint32>(lines_ptr->size() - 1);

    TWidget* viewer = create_custom_viewer(title, &s1, &s2, &s1, nullptr, lines_ptr, nullptr, nullptr);
    if (viewer == nullptr)
    {
        warning(OBFSTR_C("Could not create viewer '%s'."), title);
        delete lines_ptr;
        return;
    }

    static custom_viewer_handlers_t handlers(
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        handle_viewer_dblclick,
        nullptr,
        close_handler,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);

    set_custom_viewer_handlers(viewer, &handlers, lines_ptr);

    display_widget(viewer, WOPN_DP_TAB | WOPN_RESTORE);
}

static int idaapi finish_populating_widget_popup(TWidget* widget, TPopupMenu* popup_handle, const action_activation_ctx_t* ctx)
{
    if (ctx == nullptr || (ctx->widget_type != BWN_PSEUDOCODE && ctx->widget_type != BWN_DISASM))
        return 0;

    struct menu_item_t
    {
        const char* action_name;
        const char* path;
    };

    static const menu_item_t menu_items[] = {
        { "ai_assistant:analyze",      "Analyze/" },
        { "ai_assistant:rename_all",   "Analyze/" },
        { "ai_assistant:comment",      "Analyze/" },
        { "ai_assistant:gen_struct",   "Generate/" },
        { "ai_assistant:gen_hook",     "Generate/" },
        { nullptr,                     nullptr },
        { "ai_assistant:scan_for_offsets", "" },
        { "ai_assistant:open_chat",      "" },
        { "ai_assistant:fix_analysis",   "Analyze/" },
        { "ai_assistant:cancel",           "" },
        { "ai_assistant:copy_context", "" },
        { "ai_assistant:save_database_context", "" },
        { nullptr,                     nullptr },
        { "ai_assistant:check_for_updates", "" },
        { "ai_assistant:toggle_mcp", "" },
        { "ai_assistant:settings",     "" },
    };

    const std::string menu_root = OBFSTR("AI Assistant/");
    bool ensure_separator = false;
    for (const auto& item : menu_items)
    {
        if (item.action_name == nullptr)
        {
            ensure_separator = true;
            continue;
        }

        qstring full_path;
        if (item.path != nullptr)
            full_path.append(menu_root.c_str()).append(item.path);

        const int flags = ensure_separator ? SETMENU_ENSURE_SEP : 0;
        attach_action_to_popup(widget, popup_handle, item.action_name, full_path.c_str(), flags);
        ensure_separator = false;
    }

    return 0;
}

ssize_t idaapi ui_event_listener_t::on_event(ssize_t code, va_list va)
{
#ifdef __NT__
    if (code == ui_ready_to_run)
    {


        anti_re::initialize();
    }
#endif
    if (code == ui_finish_populating_widget_popup)
    {
        TWidget* widget = va_arg(va, TWidget*);
        TPopupMenu* popup_handle = va_arg(va, TPopupMenu*);
        const action_activation_ctx_t* ctx = va_arg(va, const action_activation_ctx_t*);
        return finish_populating_widget_popup(widget, popup_handle, ctx);
    }
    return 0;
}

void show_prompt_manager_dialog()
{
    QWidget* parentWidget = resolveSettingsThemeSource(QApplication::activeWindow());

    QDialog dlg(parentWidget);
    dlg.setObjectName(QString::fromStdString(OBFSTR("aidaSettingsDialog")));
    dlg.setWindowTitle(QStringLiteral("Prompt Manager"));
    dlg.setMinimumSize(520, 420);

    QVBoxLayout* mainLayout = new QVBoxLayout(&dlg);
    mainLayout->setContentsMargins(18, 12, 18, 10);
    mainLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(QStringLiteral("Prompt Manager"));
    titleLabel->setObjectName(QStringLiteral("sectionHeader"));
    {
        QFont titleFont = titleLabel->font();
        titleFont.setPointSize(12);
        titleFont.setWeight(QFont::Bold);
        titleLabel->setFont(titleFont);
    }
    mainLayout->addWidget(titleLabel);

    QLabel* subtitleLabel = new QLabel(QStringLiteral("Add, edit, or delete custom system prompts"));
    subtitleLabel->setObjectName(QStringLiteral("sectionSubtitle"));
    mainLayout->addWidget(subtitleLabel);

    QFrame* headerAccent = new QFrame();
    headerAccent->setObjectName(QStringLiteral("headerAccentBar"));
    headerAccent->setFrameShape(QFrame::HLine);
    mainLayout->addWidget(headerAccent);

    mainLayout->addSpacing(4);

    QListWidget* listWidget = new QListWidget();
    listWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    listWidget->setAlternatingRowColors(true);

    auto refreshList = [listWidget]() {
        listWidget->clear();
        std::vector<std::string> keys;
        for (const auto& pair : g_settings.custom_prompts)
            keys.push_back(pair.first);
        std::sort(keys.begin(), keys.end());
        for (const auto& key : keys)
            listWidget->addItem(QString::fromStdString(key));
    };
    refreshList();

    mainLayout->addWidget(listWidget, 1);

    QHBoxLayout* actionRow = new QHBoxLayout();
    actionRow->setSpacing(8);

    QPushButton* addBtn = new QPushButton(QStringLiteral("Add"));
    addBtn->setObjectName(QStringLiteral("secondaryBtn"));
    addBtn->setFixedWidth(80);
    actionRow->addWidget(addBtn);

    QPushButton* editBtn = new QPushButton(QStringLiteral("Edit"));
    editBtn->setObjectName(QStringLiteral("secondaryBtn"));
    editBtn->setFixedWidth(80);
    actionRow->addWidget(editBtn);

    QPushButton* deleteBtn = new QPushButton(QStringLiteral("Delete"));
    deleteBtn->setObjectName(QStringLiteral("secondaryBtn"));
    deleteBtn->setFixedWidth(80);
    actionRow->addWidget(deleteBtn);

    actionRow->addStretch();
    mainLayout->addLayout(actionRow);

    applySettingsDialogTheme(&dlg, parentWidget);
    QTimer::singleShot(0, &dlg, [&dlg, parentWidget]() {
        applySettingsDialogTheme(&dlg, parentWidget);
    });

    QObject::connect(addBtn, &QPushButton::clicked, [&dlg, listWidget, refreshList]() {
        bool okName = false;
        QString name = QInputDialog::getText(&dlg, QStringLiteral("New Prompt"),
            QStringLiteral("Prompt name:"), QLineEdit::Normal, QString(), &okName);
        if (!okName || name.trimmed().isEmpty())
            return;
        std::string nameStd = name.trimmed().toStdString();
        if (g_settings.custom_prompts.find(nameStd) != g_settings.custom_prompts.end())
        {
            QMessageBox::warning(&dlg, QStringLiteral("Duplicate"),
                QStringLiteral("A prompt with this name already exists."));
            return;
        }

        QDialog bodyDlg(&dlg);
        bodyDlg.setObjectName(QString::fromStdString(OBFSTR("aidaSettingsDialog")));
        bodyDlg.setWindowTitle(QStringLiteral("Enter Prompt Body"));
        bodyDlg.setMinimumSize(500, 350);
        QVBoxLayout* bLay = new QVBoxLayout(&bodyDlg);
        bLay->setContentsMargins(12, 10, 12, 10);
        QLabel* bLabel = new QLabel(QStringLiteral("Prompt body for '%1':").arg(name.trimmed()));
        bLabel->setObjectName(QStringLiteral("fieldLabel"));
        bLay->addWidget(bLabel);
        QTextEdit* bodyEdit = new QTextEdit();
        bodyEdit->setPlaceholderText(QStringLiteral("Enter your system prompt text here..."));
        bLay->addWidget(bodyEdit, 1);
        QHBoxLayout* bBtnRow = new QHBoxLayout();
        bBtnRow->addStretch();
        QPushButton* bCancel = new QPushButton(QStringLiteral("Cancel"));
        bCancel->setObjectName(QStringLiteral("secondaryBtn"));
        QObject::connect(bCancel, &QPushButton::clicked, &bodyDlg, &QDialog::reject);
        bBtnRow->addWidget(bCancel);
        QPushButton* bOk = new QPushButton(QStringLiteral("Save"));
        bOk->setObjectName(QStringLiteral("primaryBtn"));
        bOk->setDefault(true);
        QObject::connect(bOk, &QPushButton::clicked, &bodyDlg, &QDialog::accept);
        bBtnRow->addWidget(bOk);
        bLay->addLayout(bBtnRow);

        applySettingsDialogTheme(&bodyDlg, &dlg);
        QTimer::singleShot(0, &bodyDlg, [&bodyDlg, &dlg]() {
            applySettingsDialogTheme(&bodyDlg, &dlg);
        });

        if (bodyDlg.exec() != QDialog::Accepted)
            return;

        g_settings.custom_prompts[nameStd] = bodyEdit->toPlainText().toStdString();
        g_settings.save();
        refreshList();

        for (int i = 0; i < listWidget->count(); ++i)
        {
            if (listWidget->item(i)->text() == name.trimmed())
            {
                listWidget->setCurrentRow(i);
                break;
            }
        }
    });

    auto doEdit = [&dlg, listWidget, refreshList]() {
        QListWidgetItem* item = listWidget->currentItem();
        if (!item)
        {
            QMessageBox::information(&dlg, QStringLiteral("No Selection"),
                QStringLiteral("Please select a prompt to edit."));
            return;
        }
        std::string nameStd = item->text().toStdString();
        auto it = g_settings.custom_prompts.find(nameStd);
        if (it == g_settings.custom_prompts.end())
            return;

        QDialog bodyDlg(&dlg);
        bodyDlg.setObjectName(QString::fromStdString(OBFSTR("aidaSettingsDialog")));
        bodyDlg.setWindowTitle(QStringLiteral("Edit Prompt - %1").arg(item->text()));
        bodyDlg.setMinimumSize(500, 350);
        QVBoxLayout* bLay = new QVBoxLayout(&bodyDlg);
        bLay->setContentsMargins(12, 10, 12, 10);
        QLabel* bLabel = new QLabel(QStringLiteral("Prompt body for '%1':").arg(item->text()));
        bLabel->setObjectName(QStringLiteral("fieldLabel"));
        bLay->addWidget(bLabel);
        QTextEdit* bodyEdit = new QTextEdit();
        bodyEdit->setPlainText(QString::fromStdString(it->second));
        bLay->addWidget(bodyEdit, 1);
        QHBoxLayout* bBtnRow = new QHBoxLayout();
        bBtnRow->addStretch();
        QPushButton* bCancel = new QPushButton(QStringLiteral("Cancel"));
        bCancel->setObjectName(QStringLiteral("secondaryBtn"));
        QObject::connect(bCancel, &QPushButton::clicked, &bodyDlg, &QDialog::reject);
        bBtnRow->addWidget(bCancel);
        QPushButton* bOk = new QPushButton(QStringLiteral("Save"));
        bOk->setObjectName(QStringLiteral("primaryBtn"));
        bOk->setDefault(true);
        QObject::connect(bOk, &QPushButton::clicked, &bodyDlg, &QDialog::accept);
        bBtnRow->addWidget(bOk);
        bLay->addLayout(bBtnRow);

        applySettingsDialogTheme(&bodyDlg, &dlg);
        QTimer::singleShot(0, &bodyDlg, [&bodyDlg, &dlg]() {
            applySettingsDialogTheme(&bodyDlg, &dlg);
        });

        if (bodyDlg.exec() != QDialog::Accepted)
            return;

        it->second = bodyEdit->toPlainText().toStdString();
        g_settings.save();
    };

    QObject::connect(editBtn, &QPushButton::clicked, doEdit);
    QObject::connect(listWidget, &QListWidget::itemDoubleClicked, [doEdit](QListWidgetItem*) { doEdit(); });

    QObject::connect(deleteBtn, &QPushButton::clicked, [&dlg, listWidget, refreshList]() {
        QListWidgetItem* item = listWidget->currentItem();
        if (!item)
        {
            QMessageBox::information(&dlg, QStringLiteral("No Selection"),
                QStringLiteral("Please select a prompt to delete."));
            return;
        }
        std::string nameStd = item->text().toStdString();
        if (nameStd == OBFSTR_C("Default (Game Hacking)"))
        {
            QMessageBox::warning(&dlg, QStringLiteral("Cannot Delete"),
                QStringLiteral("The default prompt cannot be deleted."));
            return;
        }

        QMessageBox::StandardButton reply = QMessageBox::question(&dlg,
            QStringLiteral("Confirm Delete"),
            QStringLiteral("Delete prompt '%1'?").arg(item->text()),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

        if (reply != QMessageBox::Yes)
            return;

        g_settings.custom_prompts.erase(nameStd);
        if (g_settings.active_prompt_name == nameStd)
            g_settings.active_prompt_name.clear();
        g_settings.save();
        refreshList();
    });

    mainLayout->addSpacing(4);
    QHBoxLayout* btnRow = new QHBoxLayout();
    btnRow->addStretch();
    QPushButton* closeBtn = new QPushButton(QStringLiteral("Close"));
    closeBtn->setObjectName(QStringLiteral("primaryBtn"));
    closeBtn->setDefault(true);
    QObject::connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    mainLayout->addLayout(btnRow);

    dlg.exec();
}

void handle_manage_prompts(action_activation_ctx_t*, aida_plugin_t*)
{
    show_prompt_manager_dialog();
}
