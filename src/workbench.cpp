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

#include <limits>

#include "aida_pro.hpp"
#include "workbench.hpp"

#include "analysis_db.hpp"
#include "actions.hpp"
#include "chat_widget_ui.hpp"
#include "graphrag.hpp"
#include "rlhf.hpp"
#include "ui.hpp"

namespace
{

static uint64_t now_ms()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

static QString to_qstring(const qstring& value)
{
    return QString::fromLatin1(value.c_str());
}

static QString to_qstring(const std::string& value)
{
    return QString::fromUtf8(value.c_str());
}

static QString format_ea(ea_t ea)
{
    if (ea == BADADDR)
        return QStringLiteral("No function context");
    return QStringLiteral("0x%1").arg(static_cast<qulonglong>(ea), 0, 16).toUpper();
}

static qstring get_function_name_for_ea(ea_t ea)
{
    qstring name;
    if (ea != BADADDR)
        get_func_name(&name, ea);
    if (name.empty() && ea != BADADDR)
        name.sprnt("sub_%llX", static_cast<unsigned long long>(ea));
    return name;
}

static std::string active_model_name()
{
    if (g_settings.api_provider == "gemini")
        return g_settings.gemini_model_name;
    if (g_settings.api_provider == "openai")
        return g_settings.openai_model_name;
    if (g_settings.api_provider == "openrouter")
        return g_settings.openrouter_model_name;
    if (g_settings.api_provider == "anthropic")
        return g_settings.anthropic_model_name;
    if (g_settings.api_provider == "copilot")
        return g_settings.copilot_model_name;
    if (g_settings.api_provider == "local_llm")
        return g_settings.local_llm_model_name;
    return {};
}

static QString style_color(const QColor& color)
{
    return QStringLiteral("rgb(%1,%2,%3)")
        .arg(color.red())
        .arg(color.green())
        .arg(color.blue());
}

static QColor blend_color(const QColor& a, const QColor& b, double t)
{
    const double ratio = qBound(0.0, t, 1.0);
    const double inv = 1.0 - ratio;
    return QColor(
        static_cast<int>(a.red() * inv + b.red() * ratio),
        static_cast<int>(a.green() * inv + b.green() * ratio),
        static_cast<int>(a.blue() * inv + b.blue() * ratio),
        static_cast<int>(a.alpha() * inv + b.alpha() * ratio));
}

struct workbench_theme_t
{
    bool is_dark = false;
    QColor window_bg;
    QColor base_bg;
    QColor panel_bg;
    QColor header_bg;
    QColor header_border;
    QColor elevated_bg;
    QColor text_primary;
    QColor text_secondary;
    QColor accent;
    QColor accent_soft;
    QColor accent_border;
    QColor button_primary;
    QColor button_primary_hover;
    QColor button_primary_pressed;
    QColor button_primary_text;
    QColor button_secondary_bg;
    QColor button_secondary_text;
    QColor button_secondary_hover;
    QColor button_border;
    QColor tab_bg;
    QColor tab_hover;
    QColor tab_selected;
    QColor input_bg;
    QColor input_border;
    QColor selection_bg;
    QColor selection_text;
    QColor link;
};

static QPalette resolve_workbench_palette(const QWidget* widget)
{
    const QWidget* current = widget;
    while (current != nullptr)
    {
        const QPalette pal = current->palette();
        const QColor window = pal.color(QPalette::Window);
        const QColor base = pal.color(QPalette::Base);
        if (window.isValid() && base.isValid())
            return pal;
        current = current->parentWidget();
    }
    return QApplication::palette();
}

static workbench_theme_t detect_workbench_theme(const QWidget* widget)
{
    workbench_theme_t theme;
    const QPalette palette = resolve_workbench_palette(widget);

    const QColor window = palette.color(QPalette::Window);
    const QColor base = palette.color(QPalette::Base);
    const QColor button = palette.color(QPalette::Button);
    const QColor button_text = palette.color(QPalette::ButtonText);
    const QColor window_text = palette.color(QPalette::WindowText);
    const QColor text = palette.color(QPalette::Text);
    const QColor mid = palette.color(QPalette::Mid);
    const QColor alternate = palette.color(QPalette::AlternateBase);
    const QColor highlight = palette.color(QPalette::Highlight);
    const QColor highlighted_text = palette.color(QPalette::HighlightedText);
    const QColor link = palette.color(QPalette::Link);

    theme.is_dark = window.lightnessF() < 0.5;
    theme.window_bg = window;
    theme.base_bg = base;
    theme.text_primary = window_text.isValid() ? window_text : (text.isValid() ? text : (theme.is_dark ? QColor(236, 241, 247) : QColor(29, 37, 47)));
    theme.text_secondary = blend_color(theme.text_primary, window, theme.is_dark ? 0.38 : 0.52);
    theme.accent = highlight.isValid()
        ? highlight
        : (theme.is_dark ? QColor(84, 164, 255) : QColor(51, 123, 214));
    theme.link = link.isValid() ? link : theme.accent;

    const QColor border = mid.isValid()
        ? mid
        : blend_color(window, theme.text_primary, theme.is_dark ? 0.28 : 0.18);
    const QColor secondary_surface = alternate.isValid()
        ? alternate
        : blend_color(base, button.isValid() ? button : window, 0.5);
    const QColor button_surface = button.isValid()
        ? button
        : blend_color(window, base, 0.55);
    const QColor button_text_color = button_text.isValid() ? button_text : theme.text_primary;
    const QColor selected_text = highlighted_text.isValid() ? highlighted_text : button_text_color;

    theme.panel_bg = window;
    theme.header_bg = button_surface;
    theme.header_border = border;
    theme.elevated_bg = secondary_surface;
    theme.accent_soft = blend_color(button_surface, theme.accent, theme.is_dark ? 0.12 : 0.08);
    theme.accent_border = blend_color(border, theme.accent, theme.is_dark ? 0.34 : 0.26);
    theme.button_primary = button_surface;
    theme.button_primary_hover = blend_color(button_surface, theme.accent, theme.is_dark ? 0.12 : 0.08);
    theme.button_primary_pressed = blend_color(button_surface, theme.accent, theme.is_dark ? 0.20 : 0.14);
    theme.button_primary_text = button_text_color;
    theme.button_secondary_bg = button_surface;
    theme.button_secondary_text = button_text_color;
    theme.button_secondary_hover = blend_color(button_surface, secondary_surface, 0.55);
    theme.button_border = border;
    theme.tab_bg = button_surface;
    theme.tab_hover = blend_color(button_surface, secondary_surface, 0.52);
    theme.tab_selected = base;
    theme.input_bg = base;
    theme.input_border = border;
    theme.selection_bg = highlight.isValid() ? highlight : blend_color(theme.accent, window, 0.35);
    theme.selection_text = selected_text.isValid() ? selected_text : theme.text_primary;

    return theme;
}

static QString build_html_document(const QString& body, const workbench_theme_t& theme)
{
    return QStringLiteral(
        "<html><head><style>"
        "body{font-family:'Segoe UI';font-size:10pt;color:%1;background:%2;margin:0;}"
        "h1,h2,h3{margin:0 0 8px 0;font-weight:600;color:%1;}"
        ".card{border:1px solid %3;border-radius:10px;padding:12px;margin-bottom:12px;background:%4;}"
        ".muted{color:%5;font-size:9pt;}"
        "pre{white-space:pre-wrap;font-family:'Cascadia Mono','Consolas',monospace;font-size:9pt;line-height:1.45;margin:0;}"
        "a{color:%6;text-decoration:none;}"
        "table{border-collapse:collapse;width:100%%;}"
        "td,th{padding:6px;border-bottom:1px solid %3;text-align:left;vertical-align:top;}"
        "</style></head><body>%7</body></html>")
        .arg(style_color(theme.text_primary))
        .arg(style_color(theme.panel_bg))
        .arg(style_color(theme.header_border))
        .arg(style_color(theme.elevated_bg))
        .arg(style_color(theme.text_secondary))
        .arg(style_color(theme.link))
        .arg(body);
}

static QString linkify_plain_text(const QString& text)
{
    static const QRegularExpression re(QStringLiteral("\\b0x[0-9A-Fa-f]{4,16}\\b"));
    QString escaped = text.toHtmlEscaped();
    QString result;
    const qsizetype reserve_size = escaped.size() > (std::numeric_limits<int>::max)() - 256
        ? (std::numeric_limits<int>::max)()
        : escaped.size() + 256;
    result.reserve(static_cast<int>(reserve_size));

    qsizetype last = 0;
    QRegularExpressionMatchIterator it = re.globalMatch(escaped);
    while (it.hasNext())
    {
        QRegularExpressionMatch match = it.next();
        result += escaped.mid(last, match.capturedStart() - last);
        const QString token = match.captured(0);
        result += QStringLiteral("<a href=\"aida://jump/%1\">%1</a>").arg(token);
        last = match.capturedEnd();
    }
    result += escaped.mid(last);
    return result;
}

static QString plain_card(const QString& title, const QString& text)
{
    return QStringLiteral("<div class='card'><h3>%1</h3><pre>%2</pre></div>")
        .arg(title.toHtmlEscaped())
        .arg(linkify_plain_text(text));
}

static QString bool_text(bool value)
{
    return value ? QStringLiteral("Enabled") : QStringLiteral("Disabled");
}

static bool parse_hex_ea(const QString& text, ea_t* out)
{
    if (out == nullptr)
        return false;
    QString value = text.trimmed();
    if (value.startsWith('/'))
        value.remove(0, 1);
    if (value.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        value.remove(0, 2);
    bool ok = false;
    qulonglong parsed = value.toULongLong(&ok, 16);
    if (!ok)
        return false;
    *out = static_cast<ea_t>(parsed);
    return true;
}

static QString json_pretty(const nlohmann::json& value)
{
    return to_qstring(json_dump_safe(value, 2));
}

static std::string extract_markdown_json_block(const std::string& text)
{
    static const std::regex md_json_re("```(?:json)?\\s*([\\s\\S]*?)\\s*```");
    std::smatch match;
    if (std::regex_search(text, match, md_json_re) && match.size() > 1)
        return match[1].str();
    return text;
}

static std::string current_line_text(ea_t ea)
{
    qstring line;
    generate_disasm_line(&line, ea, GENDSM_REMOVE_TAGS);
    line.trim2();
    return line.c_str();
}

static std::string data_path_summary()
{
    qstring path = get_user_idadir();
    path.append("/aida_db");
    return path.c_str();
}

}

AiDAWorkbenchPanel::AiDAWorkbenchPanel(
    QWidget* parent,
    aida_plugin_t* plugin,
    ea_t context_ea,
    const QString& context_func_name)
    : QWidget(parent)
    , m_plugin(plugin)
    , m_contextEa(context_ea)
    , m_contextFuncName(context_func_name)
    , m_lineExplainText()
    , m_binaryHash()
    , m_applyingTheme(false)
    , m_visualRefreshQueued(false)
    , m_appliedStyleSheet()
    , m_headerContextLabel(nullptr)
    , m_headerProviderLabel(nullptr)
    , m_headerGraphLabel(nullptr)
    , m_tabs(nullptr)
    , m_queryPanel(nullptr)
    , m_explainContextLabel(nullptr)
    , m_explainBrowser(nullptr)
    , m_explainDetailsBrowser(nullptr)
    , m_explainFunctionBtn(nullptr)
    , m_explainLineBtn(nullptr)
    , m_explainCopyBtn(nullptr)
    , m_explainClearBtn(nullptr)
    , m_actionsContextLabel(nullptr)
    , m_actionsLogBrowser(nullptr)
    , m_actionRenameBtn(nullptr)
    , m_actionCommentsBtn(nullptr)
    , m_actionStructBtn(nullptr)
    , m_actionHookBtn(nullptr)
    , m_actionFixBtn(nullptr)
    , m_actionCopyBtn(nullptr)
    , m_graphContextLabel(nullptr)
    , m_graphStatsLabel(nullptr)
    , m_graphOverviewBrowser(nullptr)
    , m_graphSearchEdit(nullptr)
    , m_graphLimitSpin(nullptr)
    , m_graphResultsTable(nullptr)
    , m_graphIndexBtn(nullptr)
    , m_graphReindexBtn(nullptr)
    , m_graphSecurityBtn(nullptr)
    , m_graphCommunitiesBtn(nullptr)
    , m_graphNetworkBtn(nullptr)
    , m_ragContextLabel(nullptr)
    , m_ragContextBrowser(nullptr)
    , m_ragQueryEdit(nullptr)
    , m_ragResultsTable(nullptr)
    , m_ragRefreshBtn(nullptr)
    , m_ragSearchBtn(nullptr)
    , m_settingsBrowser(nullptr)
    , m_settingsOpenBtn(nullptr)
    , m_settingsRefreshBtn(nullptr)
    , m_settingsToggleMcpBtn(nullptr)
    , m_settingsPromptMgrBtn(nullptr)
{
    setObjectName(QStringLiteral("aidaWorkbench"));
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_binaryHash = aida_db::AnalysisDB::instance().get_binary_hash();
    build_ui();
    apply_theme();
    refresh_all_tabs();
}

AiDAChatPanel* AiDAWorkbenchPanel::query_panel() const
{
    return m_queryPanel;
}

void AiDAWorkbenchPanel::set_context_function(ea_t ea, const QString& func_name)
{
    m_contextEa = ea;
    m_contextFuncName = func_name;
    m_lineExplainText.clear();

    if (m_queryPanel != nullptr)
        m_queryPanel->setContextFunction(ea, func_name);

    refresh_all_tabs();
}

void AiDAWorkbenchPanel::build_ui()
{
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(8);

    QWidget* header = new QWidget(this);
    header->setObjectName(QStringLiteral("workbenchHeader"));
    QHBoxLayout* headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(12, 10, 12, 10);
    headerLayout->setSpacing(10);

    QVBoxLayout* titleLayout = new QVBoxLayout();
    titleLayout->setContentsMargins(0, 0, 0, 0);
    titleLayout->setSpacing(2);

    QLabel* title = new QLabel(QStringLiteral("AiDA Workbench"), header);
    title->setObjectName(QStringLiteral("workbenchTitle"));
    titleLayout->addWidget(title);

    m_headerContextLabel = new QLabel(header);
    m_headerContextLabel->setObjectName(QStringLiteral("workbenchContext"));
    titleLayout->addWidget(m_headerContextLabel);

    headerLayout->addLayout(titleLayout, 1);

    m_headerProviderLabel = new QLabel(header);
    m_headerProviderLabel->setObjectName(QStringLiteral("workbenchBadge"));
    headerLayout->addWidget(m_headerProviderLabel);

    m_headerGraphLabel = new QLabel(header);
    m_headerGraphLabel->setObjectName(QStringLiteral("workbenchBadgeSecondary"));
    headerLayout->addWidget(m_headerGraphLabel);

    QPushButton* refreshBtn = new QPushButton(QStringLiteral("Refresh"), header);
    QObject::connect(refreshBtn, &QPushButton::clicked, [this]() { refresh_all_tabs(); });
    headerLayout->addWidget(refreshBtn);

    root->addWidget(header);

    m_tabs = new QTabWidget(this);
    m_tabs->setDocumentMode(true);
    root->addWidget(m_tabs, 1);

    build_explain_tab();

    QWidget* queryTab = new QWidget(m_tabs);
    QVBoxLayout* queryLayout = new QVBoxLayout(queryTab);
    queryLayout->setContentsMargins(0, 0, 0, 0);
    queryLayout->setSpacing(0);
    m_queryPanel = new AiDAChatPanel(queryTab, m_plugin, m_contextEa, m_contextFuncName);
    queryLayout->addWidget(m_queryPanel);
    m_tabs->addTab(queryTab, QStringLiteral("Query"));

    build_actions_tab();
    build_graph_tab();
    build_rag_tab();
    build_settings_tab();
}

void AiDAWorkbenchPanel::apply_theme()
{
    if (m_applyingTheme)
        return;

    m_applyingTheme = true;
    const workbench_theme_t theme = detect_workbench_theme(this);

    const QString style = QStringLiteral(
        "#aidaWorkbench { background:%1; color:%2; }"
        "#workbenchHeader { background:%3; border:1px solid %4; border-radius:12px; }"
        "#workbenchTitle { font-size:15pt; font-weight:700; color:%2; }"
        "#workbenchContext { color:%5; font-size:10pt; }"
        "#workbenchBadge, #workbenchBadgeSecondary { padding:6px 10px; border-radius:10px; border:1px solid %4; }"
        "#workbenchBadge { background:%7; color:%8; border-color:%6; font-weight:600; }"
        "#workbenchBadgeSecondary { background:%7; color:%2; }"
        "QTabWidget::pane { border:1px solid %4; border-radius:12px; background:%1; top:-1px; }"
        "QTabBar::tab { background:%9; color:%5; padding:10px 14px; border:1px solid %4; border-bottom:none; border-top-left-radius:10px; border-top-right-radius:10px; margin-right:4px; }"
        "QTabBar::tab:hover { background:%10; color:%2; }"
        "QTabBar::tab:selected { background:%11; color:%2; }"
        "QGroupBox { border:1px solid %4; border-radius:10px; margin-top:10px; padding-top:10px; font-weight:600; background:%7; }"
        "QGroupBox::title { subcontrol-origin: margin; left:10px; padding:0 4px; color:%5; }"
        "QPushButton { background:%7; color:%8; border:1px solid %4; border-radius:8px; padding:7px 12px; }"
        "QPushButton:hover { background:%10; border-color:%6; }"
        "QPushButton:pressed { background:%12; }"
        "QLineEdit, QSpinBox, QTextEdit, QPlainTextEdit, QTextBrowser, QTableWidget { background:%13; color:%2; border:1px solid %4; border-radius:8px; }"
        "QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus { border-color:%6; }"
        "QHeaderView::section { background:%7; color:%5; border:0; border-bottom:1px solid %4; padding:6px; font-weight:600; }"
        "QTableWidget { gridline-color:%4; }"
        "QTableWidget::item:selected { background:%14; color:%15; }"
        "QScrollBar:vertical { background:transparent; width:12px; margin:2px; }"
        "QScrollBar::handle:vertical { background:%4; border-radius:6px; min-height:24px; }"
        "QLabel { color:%2; }")
        .arg(style_color(theme.panel_bg))
        .arg(style_color(theme.text_primary))
        .arg(style_color(theme.header_bg))
        .arg(style_color(theme.header_border))
        .arg(style_color(theme.text_secondary))
        .arg(style_color(theme.accent_border))
        .arg(style_color(theme.button_secondary_bg))
        .arg(style_color(theme.button_secondary_text))
        .arg(style_color(theme.tab_bg))
        .arg(style_color(theme.tab_hover))
        .arg(style_color(theme.tab_selected))
        .arg(style_color(theme.button_primary_pressed))
        .arg(style_color(theme.input_bg))
        .arg(style_color(theme.selection_bg))
        .arg(style_color(theme.selection_text));

    if (m_appliedStyleSheet != style)
    {
        m_appliedStyleSheet = style;
        setStyleSheet(style);
    }

    m_applyingTheme = false;
}

void AiDAWorkbenchPanel::queue_visual_refresh()
{
    if (m_visualRefreshQueued)
        return;

    m_visualRefreshQueued = true;
    QPointer<AiDAWorkbenchPanel> self(this);
    QTimer::singleShot(0, this, [self]() {
        if (self.isNull())
            return;
        self->m_visualRefreshQueued = false;
        if (self->m_applyingTheme)
            return;
        self->refresh_all_tabs();
    });
}

bool AiDAWorkbenchPanel::event(QEvent* event)
{
    const QEvent::Type type = event->type();
    const bool visual_change =
        type == QEvent::Show
        || type == QEvent::ParentChange
        || type == QEvent::PaletteChange
        || type == QEvent::ApplicationPaletteChange
        || type == QEvent::StyleChange;

    const bool result = QWidget::event(event);

    if (visual_change)
    {
        apply_theme();
        queue_visual_refresh();
    }

    return result;
}

bool AiDAWorkbenchPanel::has_function_context() const
{
    return current_function_ea() != BADADDR;
}

ea_t AiDAWorkbenchPanel::current_function_ea() const
{
    if (m_contextEa == BADADDR)
        return BADADDR;
    func_t* pfn = get_func(m_contextEa);
    return pfn != nullptr ? pfn->start_ea : BADADDR;
}

QString AiDAWorkbenchPanel::current_function_display_name() const
{
    const ea_t func_ea = current_function_ea();
    if (func_ea == BADADDR)
        return QStringLiteral("No function selected");

    qstring name = get_function_name_for_ea(func_ea);
    return QStringLiteral("%1  |  %2").arg(to_qstring(name), format_ea(func_ea));
}

std::string AiDAWorkbenchPanel::current_model_name() const
{
    return active_model_name();
}

std::string AiDAWorkbenchPanel::analysis_type_key(const char* suffix) const
{
    return std::string("workbench.") + suffix;
}

void AiDAWorkbenchPanel::refresh_all_tabs()
{
    refresh_header();
    refresh_explain_tab();
    refresh_actions_tab();
    refresh_graph_tab();
    refresh_rag_tab();
    refresh_settings_tab();
}

void AiDAWorkbenchPanel::refresh_header()
{
    m_headerContextLabel->setText(current_function_display_name());

    QString provider = QStringLiteral("Provider: %1").arg(to_qstring(g_settings.api_provider.empty() ? std::string("unconfigured") : g_settings.api_provider));
    const std::string model_name = current_model_name();
    if (!model_name.empty())
        provider += QStringLiteral(" / %1").arg(to_qstring(model_name));
    m_headerProviderLabel->setText(provider);

    if (!m_binaryHash.empty())
    {
        auto stats = graphrag::GraphStore::instance().get_stats(m_binaryHash);
        m_headerGraphLabel->setText(
            QStringLiteral("Graph %1 nodes / %2 edges / %3 communities")
                .arg(stats.nodes)
                .arg(stats.edges)
                .arg(stats.communities));
    }
    else
    {
        m_headerGraphLabel->setText(QStringLiteral("Graph unavailable"));
    }
}

void AiDAWorkbenchPanel::set_busy_button(QPushButton* button, bool busy, const QString& busy_text, const QString& idle_text)
{
    if (button == nullptr)
        return;
    button->setEnabled(!busy);
    button->setText(busy ? busy_text : idle_text);
}

void AiDAWorkbenchPanel::render_text_browser(QTextBrowser* browser, const std::string& text, const QString& title) const
{
    if (browser == nullptr)
        return;
    const workbench_theme_t theme = detect_workbench_theme(this);

    QString body;
    if (!title.isEmpty())
        body += QStringLiteral("<div class='card'><h2>%1</h2><div class='muted'>Generated inside the active AiDA workbench context.</div></div>").arg(title.toHtmlEscaped());
    body += plain_card(QStringLiteral("Content"), to_qstring(text));
    browser->setHtml(build_html_document(body, theme));
}

void AiDAWorkbenchPanel::handle_browser_link(const QUrl& url)
{
    if (url.scheme() != QStringLiteral("aida"))
        return;

    ea_t ea = BADADDR;
    if (parse_hex_ea(url.path(), &ea) && ea != BADADDR)
        jumpto(ea);
}

void AiDAWorkbenchPanel::save_analysis_entry(const std::string& type, const std::string& result)
{
    const ea_t func_ea = current_function_ea();
    if (func_ea == BADADDR || m_binaryHash.empty())
        return;

    aida_db::analysis_entry_t entry;
    entry.address = func_ea;
    entry.function_name = get_function_name_for_ea(func_ea).c_str();
    entry.analysis_type = type;
    entry.result = result;
    entry.model_name = current_model_name();
    entry.timestamp_ms = now_ms();
    aida_db::AnalysisDB::instance().add_analysis(m_binaryHash, entry);
    aida_db::AnalysisDB::instance().save();
}

std::string AiDAWorkbenchPanel::load_analysis_entry(const std::string& type) const
{
    const ea_t func_ea = current_function_ea();
    if (func_ea == BADADDR || m_binaryHash.empty())
        return {};

    auto entries = aida_db::AnalysisDB::instance().get_analysis(m_binaryHash, func_ea);
    for (auto it = entries.rbegin(); it != entries.rend(); ++it)
    {
        if (it->analysis_type == type)
            return it->result;
    }
    return {};
}

void AiDAWorkbenchPanel::build_explain_tab()
{
    QWidget* tab = new QWidget(m_tabs);
    QVBoxLayout* layout = new QVBoxLayout(tab);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(8);

    QHBoxLayout* top = new QHBoxLayout();
    m_explainContextLabel = new QLabel(tab);
    top->addWidget(m_explainContextLabel, 1);

    m_explainFunctionBtn = new QPushButton(QStringLiteral("Explain Function"), tab);
    QObject::connect(m_explainFunctionBtn, &QPushButton::clicked, [this]() { run_explain_function(); });
    top->addWidget(m_explainFunctionBtn);

    m_explainLineBtn = new QPushButton(QStringLiteral("Explain Current Line"), tab);
    QObject::connect(m_explainLineBtn, &QPushButton::clicked, [this]() { run_explain_line(); });
    top->addWidget(m_explainLineBtn);

    m_explainCopyBtn = new QPushButton(QStringLiteral("Copy Context"), tab);
    QObject::connect(m_explainCopyBtn, &QPushButton::clicked, [this]() { run_copy_context(); });
    top->addWidget(m_explainCopyBtn);

    m_explainClearBtn = new QPushButton(QStringLiteral("Clear Cache"), tab);
    QObject::connect(m_explainClearBtn, &QPushButton::clicked, [this]() {
        save_analysis_entry(analysis_type_key("explain.function"), std::string());
        m_lineExplainText.clear();
        refresh_explain_tab();
    });
    top->addWidget(m_explainClearBtn);

    layout->addLayout(top);

    QSplitter* splitter = new QSplitter(Qt::Horizontal, tab);
    m_explainBrowser = new QTextBrowser(splitter);
    m_explainBrowser->setOpenLinks(false);
    QObject::connect(m_explainBrowser, &QTextBrowser::anchorClicked, [this](const QUrl& url) { handle_browser_link(url); });
    splitter->addWidget(m_explainBrowser);

    m_explainDetailsBrowser = new QTextBrowser(splitter);
    m_explainDetailsBrowser->setOpenLinks(false);
    QObject::connect(m_explainDetailsBrowser, &QTextBrowser::anchorClicked, [this](const QUrl& url) { handle_browser_link(url); });
    splitter->addWidget(m_explainDetailsBrowser);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    layout->addWidget(splitter, 1);

    m_tabs->addTab(tab, QStringLiteral("Explain"));
}

void AiDAWorkbenchPanel::refresh_explain_tab()
{
    m_explainContextLabel->setText(current_function_display_name());

    const std::string cached = load_analysis_entry(analysis_type_key("explain.function"));
    if (!cached.empty())
    {
        render_text_browser(m_explainBrowser, cached, QStringLiteral("Cached Function Analysis"));
    }
    else if (has_function_context())
    {
        render_text_browser(
            m_explainBrowser,
            "No cached explanation for the current function. Use Explain Function to generate a fresh analysis.",
            QStringLiteral("Function Analysis"));
    }
    else
    {
        render_text_browser(
            m_explainBrowser,
            "Move the cursor into a function in disassembly or pseudocode to enable function explanations.",
            QStringLiteral("Function Analysis"));
    }

    refresh_explain_side_panel();
}

void AiDAWorkbenchPanel::refresh_explain_side_panel()
{
    const workbench_theme_t theme = detect_workbench_theme(this);

    QString body;
    body += plain_card(
        QStringLiteral("Current Context"),
        current_function_display_name() + QStringLiteral("\nProvider: ")
            + to_qstring(g_settings.api_provider.empty() ? std::string("unconfigured") : g_settings.api_provider)
            + QStringLiteral("\nModel: ") + to_qstring(current_model_name()));

    if (!m_lineExplainText.isEmpty())
    {
        body += plain_card(QStringLiteral("Current Line"), m_lineExplainText);
    }
    else if (has_function_context())
    {
        body += plain_card(
            QStringLiteral("Current Line"),
            to_qstring(current_line_text(m_contextEa)));
    }

    if (has_function_context() && !m_binaryHash.empty())
    {
        auto& store = graphrag::GraphStore::instance();
        if (store.get_node_by_address(m_binaryHash, graphrag::node_type_t::FUNCTION, current_function_ea()) == nullptr)
        {
            graphrag::StructureExtractor extractor(store);
            extractor.extract_function(current_function_ea(), m_binaryHash);
            graphrag::save_graph(m_binaryHash);
        }

        graphrag::QueryEngine qe(store);
        nlohmann::json semantic = qe.get_semantic_analysis(m_binaryHash, current_function_ea());
        QString semantic_text;
        semantic_text += QStringLiteral("Risk: %1\nActivity: %2\nConfidence: %3")
            .arg(to_qstring(json_str(semantic, "risk_level", "UNKNOWN")))
            .arg(to_qstring(json_str(semantic, "activity_profile", "N/A")))
            .arg(semantic.value("confidence", 0.0), 0, 'f', 2);

        const auto flags_it = semantic.find("security_flags");
        if (flags_it != semantic.end() && flags_it->is_array() && !flags_it->empty())
        {
            semantic_text += QStringLiteral("\nFlags:\n");
            for (const auto& flag : *flags_it)
                semantic_text += QStringLiteral("  - %1\n").arg(to_qstring(flag.get<std::string>()));
        }

        if (semantic.contains("summary") && semantic["summary"].is_string())
        {
            semantic_text += QStringLiteral("\nSummary:\n%1").arg(to_qstring(semantic["summary"].get<std::string>()));
        }

        body += plain_card(QStringLiteral("Security and Semantic Signals"), semantic_text.trimmed());
    }
    else
    {
        body += plain_card(
            QStringLiteral("Security and Semantic Signals"),
            QStringLiteral("Graph-backed semantic details will appear here when a function context is active."));
    }

    m_explainDetailsBrowser->setHtml(build_html_document(body, theme));
}

void AiDAWorkbenchPanel::run_explain_function()
{
    if (!can_use_ai(m_plugin) || !has_function_context())
        return;

    QPointer<AiDAWorkbenchPanel> self(this);
    set_busy_button(m_explainFunctionBtn, true, QStringLiteral("Explaining..."), QStringLiteral("Explain Function"));
    m_plugin->ai_client->analyze_function(current_function_ea(), [self](const std::string& result) {
        if (self.isNull())
            return;
        self->set_busy_button(self->m_explainFunctionBtn, false, QStringLiteral("Explaining..."), QStringLiteral("Explain Function"));
        if (result.empty())
            return;
        self->save_analysis_entry(self->analysis_type_key("explain.function"), result);
        self->render_text_browser(self->m_explainBrowser, result, QStringLiteral("Generated Function Analysis"));
        self->refresh_explain_side_panel();
    });
}

void AiDAWorkbenchPanel::run_explain_line()
{
    if (!can_use_ai(m_plugin) || !has_function_context())
        return;

    const std::string line = current_line_text(m_contextEa);
    std::ostringstream prompt;
    prompt
        << "Explain the instruction or statement currently selected at "
        << format_ea(m_contextEa).toStdString()
        << ". Focus tightly on this specific address, but use the surrounding function context for accuracy.\n\n"
        << "Current line:\n" << line;

    QPointer<AiDAWorkbenchPanel> self(this);
    set_busy_button(m_explainLineBtn, true, QStringLiteral("Explaining..."), QStringLiteral("Explain Current Line"));
    m_plugin->ai_client->custom_query(current_function_ea(), prompt.str(), [self](const std::string& result) {
        if (self.isNull())
            return;
        self->set_busy_button(self->m_explainLineBtn, false, QStringLiteral("Explaining..."), QStringLiteral("Explain Current Line"));
        if (result.empty())
            return;
        self->m_lineExplainText = to_qstring(result);
        self->save_analysis_entry(self->analysis_type_key("explain.line"), result);
        self->refresh_explain_side_panel();
    });
}

void AiDAWorkbenchPanel::build_actions_tab()
{
    QWidget* tab = new QWidget(m_tabs);
    QVBoxLayout* layout = new QVBoxLayout(tab);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(8);

    m_actionsContextLabel = new QLabel(tab);
    layout->addWidget(m_actionsContextLabel);

    QGridLayout* grid = new QGridLayout();
    grid->setHorizontalSpacing(8);
    grid->setVerticalSpacing(8);

    m_actionRenameBtn = new QPushButton(QStringLiteral("Rename Symbols"), tab);
    QObject::connect(m_actionRenameBtn, &QPushButton::clicked, [this]() { run_rename_all(); });
    grid->addWidget(m_actionRenameBtn, 0, 0);

    m_actionCommentsBtn = new QPushButton(QStringLiteral("Add Comments"), tab);
    QObject::connect(m_actionCommentsBtn, &QPushButton::clicked, [this]() { run_generate_comments(); });
    grid->addWidget(m_actionCommentsBtn, 0, 1);

    m_actionStructBtn = new QPushButton(QStringLiteral("Generate Struct"), tab);
    QObject::connect(m_actionStructBtn, &QPushButton::clicked, [this]() { run_generate_struct(); });
    grid->addWidget(m_actionStructBtn, 1, 0);

    m_actionHookBtn = new QPushButton(QStringLiteral("Generate Hook"), tab);
    QObject::connect(m_actionHookBtn, &QPushButton::clicked, [this]() { run_generate_hook(); });
    grid->addWidget(m_actionHookBtn, 1, 1);

    m_actionFixBtn = new QPushButton(QStringLiteral("Fix Analysis"), tab);
    QObject::connect(m_actionFixBtn, &QPushButton::clicked, [this]() { run_fix_analysis(); });
    grid->addWidget(m_actionFixBtn, 2, 0);

    m_actionCopyBtn = new QPushButton(QStringLiteral("Copy Full Context"), tab);
    QObject::connect(m_actionCopyBtn, &QPushButton::clicked, [this]() { run_copy_context(); });
    grid->addWidget(m_actionCopyBtn, 2, 1);

    layout->addLayout(grid);

    m_actionsLogBrowser = new QTextBrowser(tab);
    m_actionsLogBrowser->setOpenLinks(false);
    QObject::connect(m_actionsLogBrowser, &QTextBrowser::anchorClicked, [this](const QUrl& url) { handle_browser_link(url); });
    layout->addWidget(m_actionsLogBrowser, 1);

    m_tabs->addTab(tab, QStringLiteral("Actions"));
}

void AiDAWorkbenchPanel::append_actions_log(const QString& title, const std::string& body, bool overwrite)
{
    const workbench_theme_t theme = detect_workbench_theme(this);

    QString bodyHtml = plain_card(title, to_qstring(body));
    QString finalBody;
    if (!overwrite)
    {
        finalBody = m_actionsLogBrowser->property("rawBody").toString();
        finalBody.prepend(bodyHtml);
    }
    else
    {
        finalBody = bodyHtml;
    }
    m_actionsLogBrowser->setProperty("rawBody", finalBody);
    m_actionsLogBrowser->setHtml(build_html_document(finalBody, theme));
}

void AiDAWorkbenchPanel::refresh_actions_tab()
{
    m_actionsContextLabel->setText(current_function_display_name());
    if (m_actionsLogBrowser->property("rawBody").toString().isEmpty())
    {
        append_actions_log(
            QStringLiteral("Direct IDB Actions"),
            "This tab exposes AiDA's C++ action workflows directly in the docked workbench.\n"
            "Rename applies AI-proposed symbol updates. Comments writes decompiler and disassembly comments.\n"
            "Struct uses the generated C++ layout. Hook opens a MinHook-ready snippet. Fix Analysis can apply clean-up tool calls back into the IDB.",
            true);
    }
}

void AiDAWorkbenchPanel::run_copy_context()
{
    if (!has_function_context())
        return;

    nlohmann::json context = ida_utils::get_context_for_prompt(current_function_ea(), true);
    if (!(context.contains("ok") && context["ok"].is_boolean() && context["ok"].get<bool>()))
    {
        append_actions_log(QStringLiteral("Copy Context"), json_str(context, "message", "Failed to gather function context."), false);
        return;
    }

    const std::string text = ida_utils::format_context_for_clipboard(context);
    if (!ida_utils::set_clipboard_text(text.c_str()))
    {
        append_actions_log(QStringLiteral("Copy Context"), "Failed to write the current function context to the clipboard.", false);
        return;
    }

    append_actions_log(QStringLiteral("Copy Context"), "Function context copied to the clipboard successfully.", false);
}

void AiDAWorkbenchPanel::run_rename_all()
{
    if (!can_use_ai(m_plugin) || !has_function_context())
        return;

    QPointer<AiDAWorkbenchPanel> self(this);
    set_busy_button(m_actionRenameBtn, true, QStringLiteral("Renaming..."), QStringLiteral("Rename Symbols"));
    m_plugin->ai_client->rename_all(current_function_ea(), [self](const std::string& result) {
        if (self.isNull())
            return;
        self->set_busy_button(self->m_actionRenameBtn, false, QStringLiteral("Renaming..."), QStringLiteral("Rename Symbols"));
        if (result.empty())
            return;
        qstring summary = ida_utils::apply_renames_from_ai(self->current_function_ea(), result);
        if (summary.empty())
            summary = "AiDA did not produce any applicable rename suggestions.";
        else
            mark_builtin_widgets(IWID_DISASM | IWID_PSEUDOCODE);
        self->append_actions_log(QStringLiteral("Rename Symbols"), summary.c_str(), false);
        self->refresh_all_tabs();
    });
}

void AiDAWorkbenchPanel::run_generate_comments()
{
    if (!can_use_ai(m_plugin) || !has_function_context())
        return;

    QPointer<AiDAWorkbenchPanel> self(this);
    set_busy_button(m_actionCommentsBtn, true, QStringLiteral("Commenting..."), QStringLiteral("Add Comments"));
    m_plugin->ai_client->generate_comments(current_function_ea(), [self](const std::string& result) {
        if (self.isNull())
            return;
        self->set_busy_button(self->m_actionCommentsBtn, false, QStringLiteral("Commenting..."), QStringLiteral("Add Comments"));
        if (result.empty())
            return;

        std::string json_text = extract_markdown_json_block(result);
        try
        {
            cfuncptr_t cfunc(nullptr);
            if (init_hexrays_plugin())
            {
                func_t* pfn = get_func(self->current_function_ea());
                if (pfn != nullptr)
                {
                    try { cfunc = decompile(pfn); }
                    catch (const vd_failure_t&) {}
                }
            }

            const auto comments = nlohmann::json::parse(json_text);
            if (!comments.is_array())
            {
                self->append_actions_log(QStringLiteral("Add Comments"), "The AI response was not a JSON array of comments.", false);
                return;
            }

            int count = 0;
            for (const auto& item : comments)
            {
                if (!item.is_object() || !item.contains("address") || !item.contains("comment"))
                    continue;

                const std::string addr_text = item["address"].get<std::string>();
                const std::string comment_text = item["comment"].get<std::string>();

                ea_t ea = BADADDR;
                if (sscanf(addr_text.c_str(), "0x%llX", &ea) != 1 && sscanf(addr_text.c_str(), "%llX", &ea) != 1)
                    continue;
                if (!is_mapped(ea))
                    continue;

                qstring comment = comment_text.c_str();
                comment.trim2();
                if (comment.empty())
                    continue;

                qstring existing;
                get_cmt(&existing, ea, false);

                qstring merged;
                if (existing.empty())
                    merged = comment;
                else
                    merged.sprnt("%s\n%s", comment.c_str(), existing.c_str());

                set_cmt(ea, merged.c_str(), false);
                ++count;

                if (cfunc != nullptr)
                {
                    treeloc_t loc;
                    loc.ea = ea;
                    loc.itp = ITP_BLOCK1;
                    const char* existing_pcomment = cfunc->get_user_cmt(loc, RETRIEVE_ALWAYS);
                    qstring merged_pcomment;
                    if (existing_pcomment == nullptr || *existing_pcomment == '\0')
                        merged_pcomment = comment;
                    else
                        merged_pcomment.sprnt("%s\n%s", comment.c_str(), existing_pcomment);
                    cfunc->set_user_cmt(loc, merged_pcomment.c_str());
                }
            }

            if (cfunc != nullptr)
            {
                cfunc->save_user_cmts();
                cfunc->refresh_func_ctext();
            }

            if (count > 0)
            {
                mark_builtin_widgets(IWID_DISASM | IWID_PSEUDOCODE);
                self->append_actions_log(QStringLiteral("Add Comments"),
                    (QStringLiteral("Applied %1 AI-generated comments to the current function.").arg(count)).toStdString(),
                    false);
            }
            else
            {
                self->append_actions_log(QStringLiteral("Add Comments"), "No valid comments were produced for the current function.", false);
            }
        }
        catch (const std::exception& e)
        {
            self->append_actions_log(QStringLiteral("Add Comments"), std::string("Failed to parse or apply comments: ") + e.what(), false);
        }
    });
}

void AiDAWorkbenchPanel::run_generate_struct()
{
    if (!can_use_ai(m_plugin) || !has_function_context())
        return;

    QPointer<AiDAWorkbenchPanel> self(this);
    set_busy_button(m_actionStructBtn, true, QStringLiteral("Generating..."), QStringLiteral("Generate Struct"));
    m_plugin->ai_client->generate_struct(current_function_ea(), [self](const std::string& result) {
        if (self.isNull())
            return;
        self->set_busy_button(self->m_actionStructBtn, false, QStringLiteral("Generating..."), QStringLiteral("Generate Struct"));
        if (result.empty())
            return;

        std::string target_param;
        static const std::regex apply_to_re("//\\s*APPLY_TO:\\s*(\\S+)");
        std::smatch match;
        if (std::regex_search(result, match, apply_to_re) && match.size() > 1)
            target_param = match[1].str();

        ida_utils::apply_struct_from_cpp_ex(result, self->current_function_ea(), target_param);
        self->append_actions_log(QStringLiteral("Generate Struct"), result, false);
        self->refresh_all_tabs();
    });
}

void AiDAWorkbenchPanel::run_generate_hook()
{
    if (!can_use_ai(m_plugin) || !has_function_context())
        return;

    QPointer<AiDAWorkbenchPanel> self(this);
    set_busy_button(m_actionHookBtn, true, QStringLiteral("Generating..."), QStringLiteral("Generate Hook"));
    m_plugin->ai_client->generate_hook(current_function_ea(), [self](const std::string& result) {
        if (self.isNull())
            return;
        self->set_busy_button(self->m_actionHookBtn, false, QStringLiteral("Generating..."), QStringLiteral("Generate Hook"));
        if (result.empty())
            return;

        qstring title;
        title.sprnt("MinHook Snippet for %s", get_function_name_for_ea(self->current_function_ea()).c_str());
        show_text_in_viewer(title.c_str(), result);
        self->append_actions_log(QStringLiteral("Generate Hook"), result, false);
    });
}

void AiDAWorkbenchPanel::run_fix_analysis()
{
    if (!can_use_ai(m_plugin) || !has_function_context())
        return;

    QPointer<AiDAWorkbenchPanel> self(this);
    set_busy_button(m_actionFixBtn, true, QStringLiteral("Fixing..."), QStringLiteral("Fix Analysis"));
    m_plugin->ai_client->fix_analysis(current_function_ea(), [self](const std::string& result) {
        if (self.isNull())
            return;
        self->set_busy_button(self->m_actionFixBtn, false, QStringLiteral("Fixing..."), QStringLiteral("Fix Analysis"));
        if (result.empty())
            return;

        auto calls = tool_executor::parse_tool_calls(result);
        if (calls.empty())
        {
            self->append_actions_log(QStringLiteral("Fix Analysis"), result, false);
            return;
        }

        std::string cleaned_code;
        try
        {
            auto parsed = nlohmann::json::parse(extract_markdown_json_block(result));
            cleaned_code = json_str(parsed, "cleaned_code");
        }
        catch (...) {}

        std::string review = tool_executor::format_tool_calls_for_review(calls);
        if (!cleaned_code.empty())
            review = std::string("=== Cleaned Code ===\n\n") + cleaned_code + "\n\n=== Proposed Actions ===\n\n" + review;

        self->append_actions_log(QStringLiteral("Fix Analysis"), review, false);

        qstring prompt;
        prompt.sprnt("AiDA proposed %zu analysis correction(s). Apply all?", calls.size());
        if (ask_yn(ASKBTN_YES, prompt.c_str()) == ASKBTN_YES)
        {
            qstring summary = tool_executor::execute_tool_calls(self->current_function_ea(), calls);
            self->append_actions_log(QStringLiteral("Fix Analysis Applied"), summary.c_str(), false);
            self->refresh_all_tabs();
        }
    });
}

void AiDAWorkbenchPanel::build_graph_tab()
{
    QWidget* tab = new QWidget(m_tabs);
    QVBoxLayout* layout = new QVBoxLayout(tab);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(8);

    m_graphContextLabel = new QLabel(tab);
    layout->addWidget(m_graphContextLabel);

    QHBoxLayout* controls = new QHBoxLayout();
    m_graphIndexBtn = new QPushButton(QStringLiteral("Index Current"), tab);
    QObject::connect(m_graphIndexBtn, &QPushButton::clicked, [this]() { index_current_function(); });
    controls->addWidget(m_graphIndexBtn);

    m_graphReindexBtn = new QPushButton(QStringLiteral("ReIndex Binary"), tab);
    QObject::connect(m_graphReindexBtn, &QPushButton::clicked, [this]() { reindex_binary(); });
    controls->addWidget(m_graphReindexBtn);

    m_graphSecurityBtn = new QPushButton(QStringLiteral("Security Overview"), tab);
    QObject::connect(m_graphSecurityBtn, &QPushButton::clicked, [this]() { run_graph_security_overview(); });
    controls->addWidget(m_graphSecurityBtn);

    m_graphCommunitiesBtn = new QPushButton(QStringLiteral("Detect Communities"), tab);
    QObject::connect(m_graphCommunitiesBtn, &QPushButton::clicked, [this]() { run_graph_communities(); });
    controls->addWidget(m_graphCommunitiesBtn);

    m_graphNetworkBtn = new QPushButton(QStringLiteral("Analyze Network Flow"), tab);
    QObject::connect(m_graphNetworkBtn, &QPushButton::clicked, [this]() { run_graph_network_flow(); });
    controls->addWidget(m_graphNetworkBtn);

    controls->addStretch();
    layout->addLayout(controls);

    m_graphStatsLabel = new QLabel(tab);
    layout->addWidget(m_graphStatsLabel);

    QSplitter* splitter = new QSplitter(Qt::Vertical, tab);
    m_graphOverviewBrowser = new QTextBrowser(splitter);
    m_graphOverviewBrowser->setOpenLinks(false);
    QObject::connect(m_graphOverviewBrowser, &QTextBrowser::anchorClicked, [this](const QUrl& url) { handle_browser_link(url); });
    splitter->addWidget(m_graphOverviewBrowser);

    QWidget* searchPane = new QWidget(splitter);
    QVBoxLayout* searchLayout = new QVBoxLayout(searchPane);
    searchLayout->setContentsMargins(0, 0, 0, 0);
    searchLayout->setSpacing(6);

    QHBoxLayout* searchControls = new QHBoxLayout();
    m_graphSearchEdit = new QLineEdit(searchPane);
    m_graphSearchEdit->setPlaceholderText(QStringLiteral("Search semantic graph..."));
    QObject::connect(m_graphSearchEdit, &QLineEdit::returnPressed, [this]() { run_graph_search(); });
    searchControls->addWidget(m_graphSearchEdit, 1);

    m_graphLimitSpin = new QSpinBox(searchPane);
    m_graphLimitSpin->setRange(1, 100);
    m_graphLimitSpin->setValue(12);
    searchControls->addWidget(m_graphLimitSpin);

    QPushButton* searchBtn = new QPushButton(QStringLiteral("Search"), searchPane);
    QObject::connect(searchBtn, &QPushButton::clicked, [this]() { run_graph_search(); });
    searchControls->addWidget(searchBtn);
    searchLayout->addLayout(searchControls);

    m_graphResultsTable = new QTableWidget(searchPane);
    m_graphResultsTable->setColumnCount(4);
    m_graphResultsTable->setHorizontalHeaderLabels({QStringLiteral("Function"), QStringLiteral("Address"), QStringLiteral("Risk"), QStringLiteral("Summary")});
    m_graphResultsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_graphResultsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_graphResultsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_graphResultsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_graphResultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_graphResultsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    QObject::connect(m_graphResultsTable, &QTableWidget::cellDoubleClicked, [this](int row, int) {
        QTableWidgetItem* item = m_graphResultsTable->item(row, 1);
        if (item == nullptr)
            return;
        ea_t ea = BADADDR;
        if (parse_hex_ea(item->text(), &ea) && ea != BADADDR)
            jumpto(ea);
    });
    searchLayout->addWidget(m_graphResultsTable, 1);

    splitter->addWidget(searchPane);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 1);
    layout->addWidget(splitter, 1);

    m_tabs->addTab(tab, QStringLiteral("Semantic Graph"));
}

void AiDAWorkbenchPanel::refresh_graph_tab()
{
    m_graphContextLabel->setText(current_function_display_name());

    if (m_binaryHash.empty())
    {
        render_text_browser(m_graphOverviewBrowser, "Graph data is unavailable because no input binary hash is active.", QStringLiteral("Semantic Graph"));
        return;
    }

    auto& store = graphrag::GraphStore::instance();
    auto stats = store.get_stats(m_binaryHash);
    m_graphStatsLabel->setText(
        QStringLiteral("Nodes: %1 | Edges: %2 | Stale: %3 | Communities: %4")
            .arg(stats.nodes)
            .arg(stats.edges)
            .arg(stats.stale)
            .arg(stats.communities));

    if (!has_function_context())
    {
        render_text_browser(m_graphOverviewBrowser,
            "Select a function to inspect its callers, callees, taint paths, and semantic summary. Binary-wide search remains available below.",
            QStringLiteral("Semantic Graph"));
        return;
    }

    if (store.get_node_by_address(m_binaryHash, graphrag::node_type_t::FUNCTION, current_function_ea()) == nullptr)
    {
        graphrag::StructureExtractor extractor(store);
        extractor.extract_function(current_function_ea(), m_binaryHash);
        graphrag::save_graph(m_binaryHash);
        stats = store.get_stats(m_binaryHash);
        m_graphStatsLabel->setText(
            QStringLiteral("Nodes: %1 | Edges: %2 | Stale: %3 | Communities: %4")
                .arg(stats.nodes)
                .arg(stats.edges)
                .arg(stats.stale)
                .arg(stats.communities));
    }

    graphrag::QueryEngine qe(store);
    nlohmann::json semantic = qe.get_semantic_analysis(m_binaryHash, current_function_ea());
    nlohmann::json callctx = qe.get_call_context(m_binaryHash, current_function_ea(), 2);
    nlohmann::json taint = qe.get_taint_paths(m_binaryHash, current_function_ea());

    QString overview;
    overview += QStringLiteral("Function: %1\nAddress: %2\nRisk: %3\nActivity: %4\nConfidence: %5\n\n")
        .arg(to_qstring(json_str(semantic, "name", get_function_name_for_ea(current_function_ea()).c_str())))
        .arg(format_ea(current_function_ea()))
        .arg(to_qstring(json_str(semantic, "risk_level", "UNKNOWN")))
        .arg(to_qstring(json_str(semantic, "activity_profile", "N/A")))
        .arg(semantic.value("confidence", 0.0), 0, 'f', 2);

    overview += QStringLiteral("Summary:\n%1\n\n").arg(to_qstring(json_str(semantic, "summary", "No semantic summary stored.")));
    overview += QStringLiteral("Call Context:\n%1\n\n").arg(json_pretty(callctx));
    overview += QStringLiteral("Taint Paths:\n%1").arg(json_pretty(taint));

    render_text_browser(m_graphOverviewBrowser, overview.toStdString(), QStringLiteral("Current Function Graph View"));
}

void AiDAWorkbenchPanel::refresh_graph_search_results(const nlohmann::json& results)
{
    m_graphResultsTable->setRowCount(0);
    if (!results.is_array())
        return;

    int row = 0;
    for (const auto& entry : results)
    {
        m_graphResultsTable->insertRow(row);
        m_graphResultsTable->setItem(row, 0, new QTableWidgetItem(to_qstring(json_str(entry, "function_name", json_str(entry, "name", "unknown")))));
        m_graphResultsTable->setItem(row, 1, new QTableWidgetItem(format_ea(entry.value("address", ea_t(BADADDR)))));
        m_graphResultsTable->setItem(row, 2, new QTableWidgetItem(to_qstring(json_str(entry, "risk_level", json_str(entry, "reason", "")))));
        m_graphResultsTable->setItem(row, 3, new QTableWidgetItem(to_qstring(json_str(entry, "summary", ""))));
        ++row;
    }
}

void AiDAWorkbenchPanel::index_current_function()
{
    if (!has_function_context() || m_binaryHash.empty())
        return;

    graphrag::StructureExtractor extractor(graphrag::GraphStore::instance());
    auto* node = extractor.extract_function(current_function_ea(), m_binaryHash);
    graphrag::save_graph(m_binaryHash);
    if (node != nullptr)
    {
        append_actions_log(
            QStringLiteral("Index Current Function"),
            (QStringLiteral("Indexed %1 at %2").arg(to_qstring(node->name)).arg(format_ea(node->address))).toStdString(),
            false);
    }
    refresh_all_tabs();
}

void AiDAWorkbenchPanel::reindex_binary()
{
    if (m_binaryHash.empty())
        return;

    show_wait_box("HIDECANCEL\nRe-indexing binary for GraphRAG...");
    graphrag::StructureExtractor extractor(graphrag::GraphStore::instance());
    auto result = extractor.extract_all(m_binaryHash, [](int current, int total, const std::string& name) {
        if (current == 1 || (current % 50) == 0 || current == total)
            replace_wait_box("Re-indexing %d / %d: %s", current, total, name.c_str());
    });
    hide_wait_box();

    graphrag::save_graph(m_binaryHash);
    append_actions_log(
        QStringLiteral("ReIndex Binary"),
        (QStringLiteral("Extracted %1 functions for the active binary graph.").arg(result.functions_extracted)).toStdString(),
        false);
    refresh_all_tabs();
}

void AiDAWorkbenchPanel::run_graph_security_overview()
{
    if (m_binaryHash.empty())
        return;

    graphrag::QueryEngine qe(graphrag::GraphStore::instance());
    nlohmann::json security = qe.get_security_analysis(m_binaryHash, 20);
    render_text_browser(m_graphOverviewBrowser, json_dump_safe(security, 2), QStringLiteral("Binary Security Overview"));
}

void AiDAWorkbenchPanel::run_graph_communities()
{
    if (m_binaryHash.empty())
        return;

    show_wait_box("HIDECANCEL\nDetecting communities...");
    graphrag::CommunityDetector detector(graphrag::GraphStore::instance());
    detector.detect(m_binaryHash, 2, 50, true, [](int iteration, int total) {
        replace_wait_box("Detecting communities: iteration %d / %d", iteration, total);
    });
    hide_wait_box();

    graphrag::save_graph(m_binaryHash);
    refresh_all_tabs();
}

void AiDAWorkbenchPanel::run_graph_network_flow()
{
    if (m_binaryHash.empty())
        return;

    show_wait_box("HIDECANCEL\nAnalyzing network flow...");
    graphrag::NetworkFlowAnalyzer analyzer(graphrag::GraphStore::instance());
    auto result = analyzer.analyze(m_binaryHash, [](int current, int total, const std::string& message) {
        if (current == 1 || (current % 25) == 0 || current == total)
            replace_wait_box("Network flow %d / %d: %s", current, total, message.c_str());
    });
    hide_wait_box();

    graphrag::save_graph(m_binaryHash);
    std::ostringstream summary;
    summary
        << "Send functions: " << result.send_functions.size() << "\n"
        << "Receive functions: " << result.recv_functions.size() << "\n"
        << "Send edges created: " << result.send_edges_created << "\n"
        << "Receive edges created: " << result.recv_edges_created;
    render_text_browser(m_graphOverviewBrowser, summary.str(), QStringLiteral("Network Flow Analysis"));
    refresh_header();
}

void AiDAWorkbenchPanel::run_graph_search()
{
    if (m_binaryHash.empty())
        return;

    const std::string query = m_graphSearchEdit->text().trimmed().toStdString();
    if (query.empty())
        return;

    graphrag::QueryEngine qe(graphrag::GraphStore::instance());
    nlohmann::json results = qe.search_semantic(m_binaryHash, query, m_graphLimitSpin->value());
    refresh_graph_search_results(results);
}

void AiDAWorkbenchPanel::build_rag_tab()
{
    QWidget* tab = new QWidget(m_tabs);
    QVBoxLayout* layout = new QVBoxLayout(tab);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(8);

    m_ragContextLabel = new QLabel(tab);
    layout->addWidget(m_ragContextLabel);

    QHBoxLayout* controls = new QHBoxLayout();
    m_ragRefreshBtn = new QPushButton(QStringLiteral("Refresh Retrieval Context"), tab);
    QObject::connect(m_ragRefreshBtn, &QPushButton::clicked, [this]() { refresh_rag_tab(); });
    controls->addWidget(m_ragRefreshBtn);

    m_ragQueryEdit = new QLineEdit(tab);
    m_ragQueryEdit->setPlaceholderText(QStringLiteral("Semantic retrieval query..."));
    QObject::connect(m_ragQueryEdit, &QLineEdit::returnPressed, [this]() { run_rag_search(); });
    controls->addWidget(m_ragQueryEdit, 1);

    m_ragSearchBtn = new QPushButton(QStringLiteral("Search"), tab);
    QObject::connect(m_ragSearchBtn, &QPushButton::clicked, [this]() { run_rag_search(); });
    controls->addWidget(m_ragSearchBtn);
    layout->addLayout(controls);

    QSplitter* splitter = new QSplitter(Qt::Vertical, tab);
    m_ragContextBrowser = new QTextBrowser(splitter);
    m_ragContextBrowser->setOpenLinks(false);
    QObject::connect(m_ragContextBrowser, &QTextBrowser::anchorClicked, [this](const QUrl& url) { handle_browser_link(url); });
    splitter->addWidget(m_ragContextBrowser);

    m_ragResultsTable = new QTableWidget(splitter);
    m_ragResultsTable->setColumnCount(4);
    m_ragResultsTable->setHorizontalHeaderLabels({QStringLiteral("Function"), QStringLiteral("Address"), QStringLiteral("Risk"), QStringLiteral("Summary")});
    m_ragResultsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_ragResultsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_ragResultsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_ragResultsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_ragResultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_ragResultsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    QObject::connect(m_ragResultsTable, &QTableWidget::cellDoubleClicked, [this](int row, int) {
        QTableWidgetItem* item = m_ragResultsTable->item(row, 1);
        if (item == nullptr)
            return;
        ea_t ea = BADADDR;
        if (parse_hex_ea(item->text(), &ea) && ea != BADADDR)
            jumpto(ea);
    });
    splitter->addWidget(m_ragResultsTable);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 1);
    layout->addWidget(splitter, 1);

    m_tabs->addTab(tab, QStringLiteral("RAG"));
}

void AiDAWorkbenchPanel::refresh_rag_tab()
{
    m_ragContextLabel->setText(current_function_display_name());

    if (!has_function_context())
    {
        render_text_browser(m_ragContextBrowser,
            "AiDA's retrieval context is binary-native. Select a function to inspect the metadata, imports, and type context that will be injected into analysis prompts.",
            QStringLiteral("Active Retrieval Context"));
        return;
    }

    nlohmann::json rag = ida_utils::get_rag_context(current_function_ea(), g_settings, nullptr);
    QString combined;
    combined += QStringLiteral("Binary Metadata:\n%1\n\n").arg(to_qstring(json_str(rag, "binary_metadata", "")));
    combined += QStringLiteral("Imports Context:\n%1\n\n").arg(to_qstring(json_str(rag, "imports_context", "")));
    combined += QStringLiteral("Type Context:\n%1").arg(to_qstring(json_str(rag, "type_context", "")));
    render_text_browser(m_ragContextBrowser, combined.toStdString(), QStringLiteral("Active Retrieval Context"));
}

void AiDAWorkbenchPanel::run_rag_search()
{
    if (m_binaryHash.empty())
        return;

    const std::string query = m_ragQueryEdit->text().trimmed().toStdString();
    if (query.empty())
        return;

    graphrag::QueryEngine qe(graphrag::GraphStore::instance());
    nlohmann::json results = qe.search_semantic(m_binaryHash, query, 16);

    m_ragResultsTable->setRowCount(0);
    if (!results.is_array())
        return;

    int row = 0;
    for (const auto& entry : results)
    {
        m_ragResultsTable->insertRow(row);
        m_ragResultsTable->setItem(row, 0, new QTableWidgetItem(to_qstring(json_str(entry, "function_name", "unknown"))));
        m_ragResultsTable->setItem(row, 1, new QTableWidgetItem(format_ea(entry.value("address", ea_t(BADADDR)))));
        m_ragResultsTable->setItem(row, 2, new QTableWidgetItem(to_qstring(json_str(entry, "risk_level", ""))));
        m_ragResultsTable->setItem(row, 3, new QTableWidgetItem(to_qstring(json_str(entry, "summary", ""))));
        ++row;
    }
}

void AiDAWorkbenchPanel::build_settings_tab()
{
    QWidget* tab = new QWidget(m_tabs);
    QVBoxLayout* layout = new QVBoxLayout(tab);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(8);

    QHBoxLayout* controls = new QHBoxLayout();
    m_settingsOpenBtn = new QPushButton(QStringLiteral("Open Advanced Settings"), tab);
    QObject::connect(m_settingsOpenBtn, &QPushButton::clicked, [this]() { SettingsForm::show_and_apply(m_plugin); refresh_all_tabs(); });
    controls->addWidget(m_settingsOpenBtn);

    m_settingsPromptMgrBtn = new QPushButton(QStringLiteral("Prompt Manager"), tab);
    QObject::connect(m_settingsPromptMgrBtn, &QPushButton::clicked, [this]() { show_prompt_manager_dialog(); refresh_all_tabs(); });
    controls->addWidget(m_settingsPromptMgrBtn);

    m_settingsToggleMcpBtn = new QPushButton(QStringLiteral("Toggle MCP"), tab);
    QObject::connect(m_settingsToggleMcpBtn, &QPushButton::clicked, [this]() {
        if (m_plugin != nullptr)
        {
            m_plugin->toggle_mcp_server();
            refresh_all_tabs();
        }
    });
    controls->addWidget(m_settingsToggleMcpBtn);

    m_settingsRefreshBtn = new QPushButton(QStringLiteral("Refresh Overview"), tab);
    QObject::connect(m_settingsRefreshBtn, &QPushButton::clicked, [this]() { refresh_settings_tab(); });
    controls->addWidget(m_settingsRefreshBtn);
    controls->addStretch();
    layout->addLayout(controls);

    m_settingsBrowser = new QTextBrowser(tab);
    m_settingsBrowser->setOpenLinks(false);
    QObject::connect(m_settingsBrowser, &QTextBrowser::anchorClicked, [this](const QUrl& url) { handle_browser_link(url); });
    layout->addWidget(m_settingsBrowser, 1);

    m_tabs->addTab(tab, QStringLiteral("Settings"));
}

void AiDAWorkbenchPanel::refresh_settings_tab()
{
    std::ostringstream text;
    text << "Active provider: " << (g_settings.api_provider.empty() ? std::string("unconfigured") : g_settings.api_provider) << "\n";
    text << "Active model: " << (current_model_name().empty() ? std::string("n/a") : current_model_name()) << "\n";
    text << "Context window: " << g_settings.get_active_context_window() << " tokens\n";
    text << "MCP server: " << (m_plugin && m_plugin->mcp_server && m_plugin->mcp_server->is_running() ? "running" : "stopped") << "\n";
    text << "MCP configured port: " << g_settings.mcp_port << "\n";
    text << "Check for updates: " << (g_settings.check_for_updates ? "enabled" : "disabled") << "\n";
    text << "Custom prompt: " << (g_settings.active_prompt_name.empty() ? std::string("default") : g_settings.active_prompt_name) << "\n";
    text << "Data path: " << data_path_summary() << "\n";

    if (!m_binaryHash.empty())
    {
        auto graph_stats = graphrag::GraphStore::instance().get_stats(m_binaryHash);
        text << "Graph stats: " << graph_stats.nodes << " nodes, " << graph_stats.edges << " edges, "
             << graph_stats.communities << " communities\n";
    }

    auto rlhf_stats = rlhf::FeedbackStore::instance().get_stats();
    text << "RLHF feedback: " << rlhf_stats.total << " total, "
         << rlhf_stats.upvotes << " upvotes, " << rlhf_stats.downvotes << " downvotes\n";

    render_text_browser(m_settingsBrowser, text.str(), QStringLiteral("Runtime Configuration Overview"));

    if (m_plugin && m_plugin->mcp_server && m_plugin->mcp_server->is_running())
        m_settingsToggleMcpBtn->setText(QStringLiteral("Stop MCP"));
    else
        m_settingsToggleMcpBtn->setText(QStringLiteral("Start MCP"));
}