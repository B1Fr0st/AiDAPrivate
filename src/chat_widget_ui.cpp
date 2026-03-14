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
#include "chat_widget.hpp"
#include "chat_widget_ui.hpp"
#include "subagents.hpp"

#include <regex>
#include <sstream>
#include <algorithm>

static inline QString colorToRgba(const QColor& c)
{
    return QStringLiteral("rgba(%1,%2,%3,%4)")
        .arg(c.red()).arg(c.green()).arg(c.blue()).arg(c.alpha());
}

static inline QString colorToRgb(const QColor& c)
{
    return QStringLiteral("rgb(%1,%2,%3)")
        .arg(c.red()).arg(c.green()).arg(c.blue());
}

static inline QString colorToHex(const QColor& c)
{
    return c.name(QColor::HexRgb);
}

static inline QColor blendColor(const QColor& a, const QColor& b, double t)
{
    const double ratio = qBound(0.0, t, 1.0);
    const double inv = 1.0 - ratio;
    return QColor(
        static_cast<int>(a.red()   * inv + b.red()   * ratio),
        static_cast<int>(a.green() * inv + b.green() * ratio),
        static_cast<int>(a.blue()  * inv + b.blue()  * ratio),
        static_cast<int>(a.alpha() * inv + b.alpha() * ratio));
}

static inline bool isLikelyDarkSurface(const QColor& c)
{
    return c.lightnessF() < 0.58;
}

static inline QColor contrastSafeTextColor(const QColor& preferred, const QColor& background, bool darkSurface)
{
    QColor out = preferred;
    const int contrast = qAbs(out.lightness() - background.lightness());

    if (contrast < 105)
    {
        out = darkSurface ? QColor(241, 244, 248) : QColor(26, 30, 35);
    }

    if (darkSurface && out.lightness() < 190)
        out = QColor(236, 240, 245);
    if (!darkSurface && out.lightness() > 115)
        out = QColor(30, 34, 38);

    return out;
}

static QFont createChatUiFont()
{
    QFont font(QStringLiteral("Segoe UI Variable Text"));
    font.setStyleHint(QFont::SansSerif);
    font.setPointSize(10);
    return font;
}

static QString formatElapsedTime(qint64 seconds)
{
    if (seconds < 60)
        return QStringLiteral("%1s").arg(seconds);
    if (seconds < 3600)
        return QStringLiteral("%1m %2s").arg(seconds / 60).arg(seconds % 60);
    return QStringLiteral("%1h %2m").arg(seconds / 3600).arg((seconds % 3600) / 60);
}

static std::string normalized_provider_name()
{
    qstring provider = g_settings.api_provider.c_str();
    provider = ida_utils::qstring_tolower(provider.c_str());
    return provider.c_str();
}

static const std::vector<std::string>& provider_models(const std::string& provider)
{
    if (provider == "gemini")
        return settings_t::gemini_models;
    if (provider == "openai")
        return settings_t::openai_models;
    if (provider == "openrouter")
        return settings_t::openrouter_models;
    if (provider == "anthropic")
        return settings_t::anthropic_models;
    if (provider == "copilot")
        return settings_t::copilot_models;
    if (provider == "local_llm" || provider == "local llm")
        return settings_t::local_llm_models;
    return settings_t::openai_models;
}

static std::string current_provider_model(const std::string& provider)
{
    if (provider == "gemini")
        return g_settings.gemini_model_name;
    if (provider == "openai")
        return g_settings.openai_model_name;
    if (provider == "openrouter")
        return g_settings.openrouter_model_name;
    if (provider == "anthropic")
        return g_settings.anthropic_model_name;
    if (provider == "copilot")
        return g_settings.copilot_model_name;
    if (provider == "local_llm" || provider == "local llm")
        return g_settings.local_llm_model_name;
    return {};
}

static void set_current_provider_model(const std::string& provider, const std::string& model)
{
    if (provider == "gemini")
        g_settings.gemini_model_name = model;
    else if (provider == "openai")
        g_settings.openai_model_name = model;
    else if (provider == "openrouter")
        g_settings.openrouter_model_name = model;
    else if (provider == "anthropic")
        g_settings.anthropic_model_name = model;
    else if (provider == "copilot")
        g_settings.copilot_model_name = model;
    else if (provider == "local_llm" || provider == "local llm")
        g_settings.local_llm_model_name = model;
}

static QString stripCodeFences(const QString& text);
static bool looksLikeToolStatusNoiseLine(const QString& line);
static bool looksLikeStructuredProtocolText(const QString& text);
static QString sanitizeAssistantDisplayText(const QString& raw);

static bool isActiveAgentStatusText(const QString& status)
{
    const QString normalized = status.trimmed().toLower();
    return normalized == QStringLiteral("accepted")
        || normalized == QStringLiteral("queued")
        || normalized == QStringLiteral("running");
}

static QString humanizeAgentStatus(const QString& status)
{
    QString normalized = status.trimmed().toLower();
    if (normalized.isEmpty())
        return QStringLiteral("idle");

    normalized.replace(QChar('_'), QChar(' '));
    if (!normalized.isEmpty())
        normalized[0] = normalized[0].toUpper();
    return normalized;
}

static QString formatRuntimeMsForAgent(uint64_t runtimeMs)
{
    const qint64 seconds = runtimeMs > 0
        ? static_cast<qint64>((runtimeMs + 999) / 1000)
        : 0;
    return formatElapsedTime(seconds);
}

static QString jsonStringValue(const nlohmann::json& obj, const char* key)
{
    if (!obj.is_object())
        return QString();
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_string())
        return QString();
    return QString::fromUtf8(it->get_ref<const std::string&>().c_str());
}

static uint64_t jsonUint64Value(const nlohmann::json& obj, const char* key)
{
    if (!obj.is_object())
        return 0;
    auto it = obj.find(key);
    if (it == obj.end())
        return 0;
    if (it->is_number_unsigned())
        return it->get<uint64_t>();
    if (it->is_number_integer())
        return static_cast<uint64_t>((std::max)(it->get<long long>(), 0LL));
    return 0;
}

static bool isActiveAgentSessionSummary(const nlohmann::json& session)
{
    const QString sessionId = jsonStringValue(session, "sessionId");
    if (sessionId == QStringLiteral("main"))
        return true;
    return isActiveAgentStatusText(jsonStringValue(session, "status"));
}

static int activeAgentSortPriority(const nlohmann::json& session)
{
    const QString sessionId = jsonStringValue(session, "sessionId");
    if (sessionId == QStringLiteral("main"))
        return -1;

    const QString status = jsonStringValue(session, "status").trimmed().toLower();
    if (status == QStringLiteral("running"))
        return 0;
    if (status == QStringLiteral("queued"))
        return 1;
    if (status == QStringLiteral("accepted"))
        return 2;
    return 3;
}

static QString targetDisplayNameForSession(const nlohmann::json& session)
{
    if (!session.is_object())
        return QString();
    auto it = session.find("targetInstance");
    if (it == session.end() || !it->is_object())
        return QString();

    QString display = jsonStringValue(*it, "displayName");
    if (!display.isEmpty())
        return display;
    return jsonStringValue(*it, "instanceId");
}

static QString buildActiveAgentSummaryText(
    const nlohmann::json& session,
    bool rootIsWaiting,
    const QString& currentToolStatus,
    const QString& typingStatus)
{
    const QString sessionId = jsonStringValue(session, "sessionId");
    const QString label = jsonStringValue(session, "label").isEmpty()
        ? (sessionId.isEmpty() ? QStringLiteral("agent") : sessionId)
        : jsonStringValue(session, "label");
    QString status = humanizeAgentStatus(jsonStringValue(session, "status"));
    if (sessionId == QStringLiteral("main") && rootIsWaiting)
        status = QStringLiteral("Running");

    QStringList lines;
    QString header = QStringLiteral("%1 | %2 | %3")
        .arg(label, status, formatRuntimeMsForAgent(jsonUint64Value(session, "runtimeMs")));
    lines.push_back(header);

    if (sessionId == QStringLiteral("main"))
    {
        const QString rootDetail = !currentToolStatus.trimmed().isEmpty()
            ? currentToolStatus.trimmed()
            : typingStatus.trimmed();
        if (!rootDetail.isEmpty())
            lines.push_back(QStringLiteral("Status: %1").arg(rootDetail));
    }
    else
    {
        const QString taskPreview = jsonStringValue(session, "taskPreview").trimmed();
        if (!taskPreview.isEmpty())
            lines.push_back(QStringLiteral("Task: %1").arg(taskPreview));
    }

    const QString target = targetDisplayNameForSession(session).trimmed();
    if (!target.isEmpty())
        lines.push_back(QStringLiteral("Target: %1").arg(target));

    const QString model = jsonStringValue(session, "model").trimmed();
    const uint64_t totalTokens = jsonUint64Value(session, "totalTokens");
    if (!model.isEmpty() || totalTokens > 0)
    {
        QStringList metrics;
        if (!model.isEmpty())
            metrics.push_back(QStringLiteral("Model %1").arg(model));
        if (totalTokens > 0)
            metrics.push_back(QStringLiteral("Tokens %1").arg(static_cast<qulonglong>(totalTokens)));
        lines.push_back(metrics.join(QStringLiteral(" | ")));
    }

    return lines.join(QChar('\n'));
}

enum class chat_action_icon_t
{
    undo,
    copy,
    send,
};

static QByteArray chat_action_svg(chat_action_icon_t icon, bool dark_theme)
{
    const char* stroke = dark_theme ? "#E8EAED" : "#1F2937";

    switch (icon)
    {
    case chat_action_icon_t::undo:
        return QByteArray(
            "<svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\">"
            "<path d=\"M9 7L5 11L9 15\" fill=\"none\" stroke=\"" + QByteArray(stroke) + "\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
            "<path d=\"M6 11H14C16.7614 11 19 13.2386 19 16\" fill=\"none\" stroke=\"" + QByteArray(stroke) + "\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
            "</svg>");
    case chat_action_icon_t::copy:
        return QByteArray(
            "<svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\">"
            "<rect x=\"8\" y=\"8\" width=\"10\" height=\"11\" rx=\"2\" fill=\"none\" stroke=\"" + QByteArray(stroke) + "\" stroke-width=\"1.8\"/>"
            "<path d=\"M6 15V6C6 4.89543 6.89543 4 8 4H15\" fill=\"none\" stroke=\"" + QByteArray(stroke) + "\" stroke-width=\"1.8\" stroke-linecap=\"round\"/>"
            "</svg>");
    case chat_action_icon_t::send:
        return QByteArray(
            "<svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\">"
            "<path d=\"M12 19V5\" fill=\"none\" stroke=\"" + QByteArray(stroke) + "\" stroke-width=\"2\" stroke-linecap=\"round\"/>"
            "<path d=\"M5 12L12 5L19 12\" fill=\"none\" stroke=\"" + QByteArray(stroke) + "\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
            "</svg>");
    }

    return {};
}

static QIcon make_chat_action_icon(chat_action_icon_t icon, bool dark_theme)
{
    const QByteArray svg = chat_action_svg(icon, dark_theme);
    QPixmap pixmap;
    if (pixmap.loadFromData(svg, "SVG"))
    {
        const qreal dpr = qApp != nullptr ? qApp->devicePixelRatio() : 1.0;
        const QSize logicalSize(20, 20);
        const QSize pixelSize(
            qMax(20, qRound(logicalSize.width() * dpr)),
            qMax(20, qRound(logicalSize.height() * dpr)));
        QPixmap scaled = pixmap.scaled(pixelSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
        scaled.setDevicePixelRatio(dpr);
        return QIcon(scaled);
    }
    return QIcon();
}


FunctionCompleterPopup::FunctionCompleterPopup(QWidget* parent)
    : QFrame(parent, Qt::ToolTip | Qt::FramelessWindowHint)
{
    setFont(createChatUiFont());
    setObjectName(QStringLiteral("functionCompleter"));
    setAttribute(Qt::WA_ShowWithoutActivating, true);
    setFocusPolicy(Qt::NoFocus);
    setFixedSize(280, 210);

    QVBoxLayout* lay = new QVBoxLayout(this);
    lay->setContentsMargins(4, 4, 4, 4);
    lay->setSpacing(2);

    m_list = new QListWidget(this);
    m_list->setFont(createChatUiFont());
    m_list->setFocusPolicy(Qt::NoFocus);
    m_list->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_list->installEventFilter(this);
    lay->addWidget(m_list);

    QObject::connect(m_list, &QListWidget::itemClicked,
        [this](QListWidgetItem*) {
            QString sel = currentSelection();
            if (!sel.isEmpty() && m_completionCallback)
                m_completionCallback(sel);
            dismiss();
        });
}

void FunctionCompleterPopup::refreshFunctionList()
{
    m_allFunctions.clear();

    size_t count = get_func_qty();
    m_allFunctions.reserve(count);

    for (size_t i = 0; i < count; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;

        qstring fname;
        if (get_func_name(&fname, pfn->start_ea) > 0 && !fname.empty())
        {
            FuncEntry entry;
            entry.name = QString::fromLatin1(fname.c_str());
            entry.ea   = pfn->start_ea;
            m_allFunctions.push_back(std::move(entry));
        }
    }

    std::sort(m_allFunctions.begin(), m_allFunctions.end(),
        [](const FuncEntry& a, const FuncEntry& b) {
            return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
        });
}

void FunctionCompleterPopup::showForPrefix(const QString& prefix, const QPoint& globalPos)
{
    if (m_allFunctions.empty())
        refreshFunctionList();

    bool isAddress = !prefix.isEmpty()
                  && (prefix.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
                   || prefix.startsWith(QStringLiteral("0X"), Qt::CaseInsensitive));

    if (isAddress && prefix.length() < 3)
    {
        hide();
        return;
    }

    applyFilter(prefix);

    if (m_list->count() == 0)
    {
        hide();
        return;
    }

    if (!isAddress && prefix.length() >= 1 && prefix.length() < 3)
    {
        int subCount = 0;
        int total = m_list->count();
        for (int i = 0; i < total; ++i)
        {
            if (m_list->item(i)->text().startsWith(QStringLiteral("sub_"), Qt::CaseInsensitive))
                ++subCount;
        }
        if (total > 0 && subCount * 100 / total > 60)
        {
            hide();
            return;
        }
    }

    m_list->setCurrentRow(0);
    move(globalPos);
    show();
    raise();
}

QString FunctionCompleterPopup::currentSelection() const
{
    QListWidgetItem* item = m_list->currentItem();
    if (item == nullptr)
        return QString();
    QString text = item->text();
    int parenIdx = static_cast<int>(text.indexOf(QStringLiteral("  (")));
    if (parenIdx > 0)
        return text.left(parenIdx);
    return text;
}

void FunctionCompleterPopup::moveSelection(int delta)
{
    if (m_list->count() == 0)
        return;
    int row = m_list->currentRow() + delta;
    if (row < 0)
        row = 0;
    if (row >= m_list->count())
        row = m_list->count() - 1;
    m_list->setCurrentRow(row);
}

bool FunctionCompleterPopup::isActive() const
{
    return isVisible();
}

void FunctionCompleterPopup::dismiss()
{
    hide();
}

bool FunctionCompleterPopup::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type() == QEvent::MouseButtonPress)
    {
        QMouseEvent* me = static_cast<QMouseEvent*>(event);
        if (!rect().contains(mapFromGlobal(me->globalPosition().toPoint())))
        {
            dismiss();
            return true;
        }
    }
    return QFrame::eventFilter(obj, event);
}

void FunctionCompleterPopup::applyFilter(const QString& prefix)
{
    m_list->clear();

    int added = 0;
    const int maxItems = 80;

    for (const auto& entry : m_allFunctions)
    {
        if (added >= maxItems)
            break;

        if (prefix.isEmpty() || entry.name.contains(prefix, Qt::CaseInsensitive))
        {
            QString display = QStringLiteral("%1  (0x%2)")
                .arg(entry.name)
                .arg(QString::number(static_cast<quint64>(entry.ea), 16).toUpper());
            m_list->addItem(display);
            ++added;
        }
    }
}

void FunctionCompleterPopup::setCompletionCallback(std::function<void(const QString&)> cb)
{
    m_completionCallback = std::move(cb);
}

AiDAChatPanel::AiDAChatPanel(QWidget* parent,
                             aida_plugin_t* plugin,
                             ea_t context_ea,
                             const QString& context_func_name)
    : QWidget(parent)
    , m_plugin(plugin)
    , m_contextEa(context_ea)
    , m_contextFuncName(context_func_name)
    , m_isWaiting(false)
    , m_updatingTheme(false)
    , m_activeConversationIndex(-1)
    , m_headerBar(nullptr)
    , m_headerLabel(nullptr)
    , m_contextLabel(nullptr)
    , m_historyBtn(nullptr)
    , m_newChatBtn(nullptr)
    , m_chatDisplay(nullptr)
    , m_chatDisplayViewport(nullptr)
    , m_chatMessagesLayout(nullptr)
    , m_inputField(nullptr)
    , m_sendBtn(nullptr)
    , m_cancelBtn(nullptr)
    , m_modelPicker(nullptr)
    , m_tagBtn(nullptr)
    , m_currentToolStatus()
    , m_typingStatus(QStringLiteral("Thinking"))
    , m_activeThinkingRound(-1)
    , m_liveThinkingBlock(nullptr)
    , m_liveStreamLabel(nullptr)
    , m_liveStatusLabel(nullptr)
    , m_historyPanel(nullptr)
    , m_historyList(nullptr)
    , m_historyVisible(false)
    , m_toastLabel(nullptr)
    , m_toastTimer(nullptr)
    , m_completer(nullptr)
    , m_completerActive(false)
    , m_thinkingElapsedTimer(nullptr)
    , m_typewriterTimer(nullptr)
    , m_userScrolledChat(false)
    , m_editingIndex(-1)
    , m_editingField(nullptr)
    , m_rebuildDebounceTimer(nullptr)
{
    setObjectName(QString::fromStdString(OBFSTR("aidaChatPanel")));
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setFont(createChatUiFont());
    loadFromDisk();
    setupUI();
    setupStyle();
    rebuildChatDisplay();
}

AiDAChatPanel::~AiDAChatPanel()
{
    if (m_rebuildDebounceTimer != nullptr)
        m_rebuildDebounceTimer->stop();
    if (m_typewriterTimer != nullptr)
        m_typewriterTimer->stop();
    if (m_thinkingElapsedTimer != nullptr)
        m_thinkingElapsedTimer->stop();
    if (m_toastTimer != nullptr)
        m_toastTimer->stop();
    saveCurrentConversation();
    saveToDisk();
}

void AiDAChatPanel::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    m_headerBar = new QWidget(this);
    m_headerBar->setObjectName(QStringLiteral("headerBar"));
    QVBoxLayout* hdrOuterLayout = new QVBoxLayout(m_headerBar);
    hdrOuterLayout->setContentsMargins(0, 0, 0, 0);
    hdrOuterLayout->setSpacing(0);

    QHBoxLayout* hdrTopRow = new QHBoxLayout();
    hdrTopRow->setContentsMargins(10, 8, 10, 2);
    hdrTopRow->setSpacing(8);

    m_headerLabel = new QLabel(QString::fromStdString(OBFSTR("AiDA Chat")), m_headerBar);
    m_headerLabel->setObjectName(QStringLiteral("headerLabel"));
    hdrTopRow->addWidget(m_headerLabel);
    hdrTopRow->addStretch();

    m_newChatBtn = new QPushButton(QStringLiteral("New"), m_headerBar);
    m_newChatBtn->setObjectName(QStringLiteral("newChatBtn"));
    m_newChatBtn->setToolTip(QStringLiteral("Start New Conversation"));
    m_newChatBtn->setMinimumWidth(52);
    m_newChatBtn->setFixedHeight(24);
    QObject::connect(m_newChatBtn, &QPushButton::clicked, [this]() {
        startNewConversation();
    });
    hdrTopRow->addWidget(m_newChatBtn);

    m_historyBtn = new QPushButton(QStringLiteral("History"), m_headerBar);
    m_historyBtn->setObjectName(QStringLiteral("historyBtn"));
    m_historyBtn->setToolTip(QStringLiteral("Toggle Chat History"));
    m_historyBtn->setCheckable(true);
    m_historyBtn->setChecked(false);
    m_historyBtn->setMinimumWidth(66);
    m_historyBtn->setFixedHeight(24);
    QObject::connect(m_historyBtn, &QPushButton::clicked, [this]() {
        toggleHistoryPanel();
    });
    hdrTopRow->addWidget(m_historyBtn);

    hdrOuterLayout->addLayout(hdrTopRow);

    QHBoxLayout* hdrContextRow = new QHBoxLayout();
    hdrContextRow->setContentsMargins(10, 2, 10, 6);

    m_contextLabel = new QLabel(m_headerBar);
    m_contextLabel->setObjectName(QStringLiteral("contextLabel"));
    updateContextLabel();
    hdrContextRow->addWidget(m_contextLabel);
    hdrContextRow->addStretch();

    hdrOuterLayout->addLayout(hdrContextRow);

    mainLayout->addWidget(m_headerBar);

    QWidget* bodyContainer = new QWidget(this);
    QHBoxLayout* bodyLayout = new QHBoxLayout(bodyContainer);
    bodyLayout->setContentsMargins(8, 6, 8, 6);
    bodyLayout->setSpacing(8);

    m_historyPanel = new QWidget(bodyContainer);
    m_historyPanel->setObjectName(QStringLiteral("historyPanel"));
    m_historyPanel->setFixedWidth(220);
    m_historyPanel->setVisible(false);
    QVBoxLayout* histLayout = new QVBoxLayout(m_historyPanel);
    histLayout->setContentsMargins(0, 0, 0, 0);
    histLayout->setSpacing(0);

    QLabel* histTitle = new QLabel(QStringLiteral("History"), m_historyPanel);
    histTitle->setObjectName(QStringLiteral("historyTitle"));
    histLayout->addWidget(histTitle);

    m_historyList = new QListWidget(m_historyPanel);
    m_historyList->setObjectName(QStringLiteral("historyList"));
    QObject::connect(m_historyList, &QListWidget::itemClicked, [this](QListWidgetItem* item) {
        int idx = item->data(Qt::UserRole).toInt();
        loadConversation(idx);
    });
    m_historyList->setContextMenuPolicy(Qt::CustomContextMenu);
    QObject::connect(
        m_historyList,
        &QListWidget::customContextMenuRequested,
        [this](const QPoint& pos)
        {
            QListWidgetItem* item = m_historyList->itemAt(pos);
            if (item == nullptr)
                return;

            int idx = item->data(Qt::UserRole).toInt();
            QMenu menu(m_historyList);
            QAction* loadAction = menu.addAction(QStringLiteral("Load Conversation"));
            QAction* deleteAction = menu.addAction(QStringLiteral("Delete Conversation"));
            QAction* selected = menu.exec(m_historyList->viewport()->mapToGlobal(pos));

            if (selected == loadAction)
                loadConversation(idx);
            else if (selected == deleteAction)
                deleteConversation(idx);
        });
    histLayout->addWidget(m_historyList, 1);
    bodyLayout->addWidget(m_historyPanel);

    QWidget* chatArea = new QWidget(bodyContainer);
    QVBoxLayout* chatAreaLayout = new QVBoxLayout(chatArea);
    chatAreaLayout->setContentsMargins(2, 2, 2, 2);
    chatAreaLayout->setSpacing(6);

    m_chatDisplay = new QScrollArea(chatArea);
    m_chatDisplay->setObjectName(QStringLiteral("chatDisplay"));
    m_chatDisplay->setFrameShape(QFrame::NoFrame);
    m_chatDisplay->setWidgetResizable(true);
    m_chatDisplay->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    m_chatDisplayViewport = new QWidget(m_chatDisplay);
    m_chatDisplayViewport->setObjectName(QStringLiteral("chatDisplayViewport"));
    m_chatMessagesLayout = new QVBoxLayout(m_chatDisplayViewport);
    m_chatMessagesLayout->setContentsMargins(8, 6, 8, 8);
    m_chatMessagesLayout->setSpacing(10);
    m_chatMessagesLayout->addStretch();
    m_chatDisplay->setWidget(m_chatDisplayViewport);

    chatAreaLayout->addWidget(m_chatDisplay, 1);

    QObject::connect(m_chatDisplay->verticalScrollBar(), &QScrollBar::sliderPressed, [this]() {
        m_userScrolledChat = true;
    });
    QObject::connect(m_chatDisplay->verticalScrollBar(), &QScrollBar::valueChanged, [this](int value) {
        QScrollBar* sb = m_chatDisplay->verticalScrollBar();
        if (value >= sb->maximum() - 4)
            m_userScrolledChat = false;
    });
    bodyLayout->addWidget(chatArea, 1);

    mainLayout->addWidget(bodyContainer, 1);

    QWidget* inputContainer = new QWidget(this);
    inputContainer->setObjectName(QStringLiteral("inputContainer"));
    QVBoxLayout* inputOuterLay = new QVBoxLayout(inputContainer);
    inputOuterLay->setContentsMargins(8, 6, 8, 8);
    inputOuterLay->setSpacing(6);

    m_inputField = new QTextEdit(inputContainer);
    m_inputField->setObjectName(QStringLiteral("chatInput"));
    m_inputField->setPlaceholderText(
        QString::fromStdString(OBFSTR("Ask AiDA anything... (Ctrl+Enter)")));
    m_inputField->setAcceptRichText(false);
    m_inputField->setTabChangesFocus(true);
    m_inputField->document()->setDocumentMargin(6);
    m_inputField->setFixedHeight(40);
    m_inputField->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_inputField->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_inputField->installEventFilter(this);
    QObject::connect(m_inputField, &QTextEdit::textChanged, [this]() {
        QTextDocument* doc = m_inputField->document();
        int docHeight = static_cast<int>(doc->size().height());
        int newHeight = docHeight + 10;
        newHeight = qBound(40, newHeight, 140);
        m_inputField->setFixedHeight(newHeight);
        m_inputField->setVerticalScrollBarPolicy(
            newHeight >= 140 ? Qt::ScrollBarAsNeeded : Qt::ScrollBarAlwaysOff);
    });
    inputOuterLay->addWidget(m_inputField, 0);

    QHBoxLayout* btnRow = new QHBoxLayout();
    btnRow->setSpacing(8);

    m_tagBtn = new QPushButton(QStringLiteral("@ Tag Function"), inputContainer);
    m_tagBtn->setObjectName(QStringLiteral("tagBtn"));
    m_tagBtn->setToolTip(QStringLiteral("Tag a function to include its code in context"));
    QObject::connect(m_tagBtn, &QPushButton::clicked, [this]() {
        m_inputField->insertPlainText(QStringLiteral("@"));
        m_inputField->setFocus();
        handleAtTrigger();
    });
    btnRow->addWidget(m_tagBtn);

    m_modelPicker = new QComboBox(inputContainer);
    m_modelPicker->setObjectName(QStringLiteral("modelPicker"));
    m_modelPicker->setEditable(false);
    m_modelPicker->setMinimumWidth(220);
    m_modelPicker->setMaximumWidth(340);
    m_modelPicker->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    m_modelPicker->setToolTip(QStringLiteral("Select the active AI model"));
    refreshModelPicker();
    QObject::connect(m_modelPicker, &QComboBox::currentTextChanged, [this](const QString&) {
        applySelectedModel();
    });
    btnRow->addWidget(m_modelPicker);

    btnRow->addStretch();

    m_sendBtn = new QPushButton(QStringLiteral("Send"), inputContainer);
    m_sendBtn->setObjectName(QStringLiteral("sendBtn"));
    m_sendBtn->setToolTip(QStringLiteral("Send message (Ctrl+Enter)"));
    m_sendBtn->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
    m_sendBtn->setMinimumSize(84, 30);
    QObject::connect(m_sendBtn, &QPushButton::clicked, [this]() {
        sendMessage();
    });
    btnRow->addWidget(m_sendBtn);

    m_cancelBtn = new QPushButton(QStringLiteral("Cancel"), inputContainer);
    m_cancelBtn->setObjectName(QStringLiteral("cancelBtn"));
    m_cancelBtn->setToolTip(QStringLiteral("Cancel current AI request"));
    m_cancelBtn->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
    m_cancelBtn->setMinimumSize(84, 30);
    m_cancelBtn->setVisible(false);
    QObject::connect(m_cancelBtn, &QPushButton::clicked, [this]() {
        cancelRequest();
    });
    btnRow->addWidget(m_cancelBtn);

    inputOuterLay->addLayout(btnRow);

    mainLayout->addWidget(inputContainer);

    m_completer = new FunctionCompleterPopup(this);
    m_completerActive = false;
    m_completer->setCompletionCallback([this](const QString& funcName) {
        insertCompletion(funcName);
        m_completerActive = false;
    });

    m_typewriterTimer = new QTimer(this);
    m_typewriterTimer->setInterval(8);
    QObject::connect(m_typewriterTimer, &QTimer::timeout, [this]() {
        if (m_typewriterQueue.isEmpty())
        {
            m_typewriterTimer->stop();
            return;
        }
        m_typewriterQueue.clear();
    });

    m_thinkingElapsedTimer = new QTimer(this);
    m_thinkingElapsedTimer->setInterval(1000);
    QObject::connect(m_thinkingElapsedTimer, &QTimer::timeout, [this]() {
        if (!m_isWaiting)
            return;
        refreshThinkingPanelView();
    });

    m_toastLabel = new QLabel(this);
    m_toastLabel->setObjectName(QStringLiteral("toastLabel"));
    m_toastLabel->setAlignment(Qt::AlignCenter);
    m_toastLabel->setVisible(false);
    m_toastLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
    m_toastLabel->setFixedHeight(24);

    m_toastTimer = new QTimer(this);
    m_toastTimer->setSingleShot(true);
    QObject::connect(m_toastTimer, &QTimer::timeout, [this]() {
        m_toastLabel->setVisible(false);
    });

    applyResponsiveMetrics();
}

QSize AiDAChatPanel::sizeHint() const
{
    return QSize(360, 600);
}

QSize AiDAChatPanel::minimumSizeHint() const
{
    return QSize(240, 300);
}

void AiDAChatPanel::applyResponsiveMetrics()
{
    const int panelWidth = qMax(260, width());
    const qreal scale = panelWidth < 520 ? 0.92 : (panelWidth < 760 ? 0.97 : 1.0);
    const auto scaledPointSize = [scale](qreal base) {
        return qMax(7, qRound(base * scale));
    };

    QFont baseFont = createChatUiFont();
    baseFont.setPointSize(scaledPointSize(9.5));

    if (m_headerLabel != nullptr)
    {
        QFont font = baseFont;
        font.setBold(true);
        font.setPointSize(scaledPointSize(10.0));
        m_headerLabel->setFont(font);
    }

    if (m_contextLabel != nullptr)
    {
        QFont font = baseFont;
        font.setPointSize(scaledPointSize(8.5));
        m_contextLabel->setFont(font);
    }

    if (m_inputField != nullptr)
        m_inputField->setFont(baseFont);

    const QList<QPushButton*> buttons = {m_newChatBtn, m_historyBtn, m_tagBtn, m_sendBtn, m_cancelBtn};
    for (QPushButton* button : buttons)
    {
        if (button == nullptr)
            continue;
        QFont font = baseFont;
        font.setPointSize(scaledPointSize(8.5));
        if (button == m_sendBtn || button == m_cancelBtn)
            font.setBold(true);
        button->setFont(font);
    }

    if (m_newChatBtn != nullptr)
    {
        m_newChatBtn->setMinimumWidth(panelWidth < 500 ? 44 : 52);
        m_newChatBtn->setFixedHeight(panelWidth < 500 ? 22 : 24);
    }
    if (m_historyBtn != nullptr)
    {
        m_historyBtn->setMinimumWidth(panelWidth < 500 ? 54 : 66);
        m_historyBtn->setFixedHeight(panelWidth < 500 ? 22 : 24);
    }
    if (m_sendBtn != nullptr)
    {
        m_sendBtn->setMinimumSize(panelWidth < 500 ? QSize(72, 28) : QSize(84, 30));
        m_sendBtn->setMaximumHeight(panelWidth < 500 ? 28 : 30);
    }
    if (m_cancelBtn != nullptr)
    {
        m_cancelBtn->setMinimumSize(panelWidth < 500 ? QSize(72, 28) : QSize(84, 30));
        m_cancelBtn->setMaximumHeight(panelWidth < 500 ? 28 : 30);
    }
    if (m_tagBtn != nullptr)
        m_tagBtn->setMinimumHeight(panelWidth < 500 ? 26 : 30);
    if (m_modelPicker != nullptr)
    {
        QFont font = baseFont;
        font.setPointSize(scaledPointSize(8.5));
        m_modelPicker->setFont(font);
        m_modelPicker->setMinimumHeight(panelWidth < 500 ? 26 : 30);
    }
}

void AiDAChatPanel::refreshModelPicker()
{
    if (m_modelPicker == nullptr)
        return;

    QSignalBlocker blocker(m_modelPicker);

    const std::string provider = normalized_provider_name();
    const auto& models = provider_models(provider);
    std::string current = current_provider_model(provider);

    m_modelPicker->clear();
    for (const std::string& model : models)
        m_modelPicker->addItem(QString::fromStdString(model));

    if (!current.empty() && m_modelPicker->findText(QString::fromStdString(current)) < 0)
        m_modelPicker->addItem(QString::fromStdString(current));

    if (!current.empty())
    {
        const int currentIdx = m_modelPicker->findText(QString::fromStdString(current));
        if (currentIdx >= 0)
            m_modelPicker->setCurrentIndex(currentIdx);
    }
    else if (m_modelPicker->count() > 0)
    {
        m_modelPicker->setCurrentIndex(0);
    }

    const QString providerLabel = QString::fromStdString(provider.empty() ? std::string("unknown") : provider);
    m_modelPicker->setToolTip(QStringLiteral("Active provider: %1").arg(providerLabel));
}

void AiDAChatPanel::applySelectedModel()
{
    if (m_modelPicker == nullptr || m_isWaiting)
        return;

    const QString selected = m_modelPicker->currentText().trimmed();
    if (selected.isEmpty())
        return;

    const std::string provider = normalized_provider_name();
    const std::string selectedModel = selected.toStdString();
    if (selectedModel == current_provider_model(provider))
        return;

    set_current_provider_model(provider, selectedModel);
    g_settings.save();

    if (m_plugin != nullptr)
        m_plugin->reinit_ai_client();

    showToast(QStringLiteral("Model switched to %1").arg(selected));
}

ThemeColors AiDAChatPanel::detectThemeColors() const
{
    ThemeColors t;
    QWidget* idaParent = parentWidget();
    QPalette p = idaParent ? idaParent->palette() : palette();

    QColor windowColor = p.color(QPalette::Window);
    QColor baseColor = p.color(QPalette::Base);
    QColor highlightColor = p.color(QPalette::Highlight);

    const QColor windowTextColor = p.color(QPalette::WindowText);
    const qreal avgLightness = (windowColor.lightnessF() + baseColor.lightnessF()) * 0.5;
    const bool palettePrefersLightText = windowTextColor.isValid() && windowTextColor.lightnessF() > 0.62;
    bool isDark = palettePrefersLightText || avgLightness < 0.57;

    QColor textColor = windowTextColor.isValid()
        ? windowTextColor
        : (isDark ? QColor(255, 255, 255) : QColor(0, 0, 0));
    textColor = contrastSafeTextColor(textColor, windowColor, isDark);

    QColor fallbackAccent = isDark ? QColor(110, 110, 110) : QColor(140, 140, 140);
    QColor accent = highlightColor.isValid() ? highlightColor : fallbackAccent;

    QColor yellowCodeBg = isDark ? QColor(55, 50, 12) : QColor(255, 248, 180);
    QColor yellowCodeBorder = isDark ? QColor(85, 75, 18) : QColor(215, 205, 100);
    QColor yellowInlineBg = isDark ? QColor(62, 56, 15) : QColor(255, 245, 165);

    if (isDark)
    {
        QColor base = blendColor(windowColor, QColor(24, 24, 24), 0.72);
        QColor elevated = blendColor(base, QColor(38, 38, 38), 0.58);
        QColor stroke = blendColor(base, QColor(72, 72, 72), 0.74);
        QColor brightAccent = blendColor(accent, QColor(235, 235, 235), 0.12);

        t.panelBg = base;
        t.headerBg = blendColor(base, QColor(18, 18, 18), 0.56);
        t.headerBorder = stroke;
        t.textPrimary = textColor;
        t.textSecondary = blendColor(textColor, base, 0.22);
        t.textMuted = blendColor(textColor, base, 0.34);
        t.inputBg = elevated;
        t.inputBorder = stroke;
        t.inputBorderFocus = blendColor(brightAccent, QColor(220, 220, 220), 0.18);
        t.buttonPrimary = blendColor(brightAccent, base, 0.26);
        t.buttonPrimaryHover = blendColor(t.buttonPrimary, QColor(220, 220, 220), 0.14);
        t.buttonPrimaryPressed = blendColor(t.buttonPrimary, QColor(24, 24, 24), 0.24);
        t.buttonSecondaryBg = QColor(0, 0, 0, 0);
        t.buttonSecondaryBorder = blendColor(base, stroke, 0.9);
        t.buttonSecondaryHover = blendColor(base, elevated, 0.86);
        t.messageBgUser = blendColor(brightAccent, base, 0.46);
        t.messageBgAi = blendColor(base, QColor(54, 54, 54), 0.72);
        t.messageBgSystem = blendColor(base, QColor(40, 40, 40), 0.62);
        t.messageBorder = blendColor(base, stroke, 0.86);
        t.bubbleAiText = textColor;
        t.codeBlockBg = yellowCodeBg;
        t.codeBlockBorder = yellowCodeBorder;
        t.codeBlockText = textColor;
        t.inlineCodeBg = yellowInlineBg;
        t.inlineCodeText = textColor;
        t.accentColor = brightAccent;
        t.selectionBg = blendColor(brightAccent, QColor(28, 28, 28), 0.36);
        t.linkColor = blendColor(brightAccent, QColor(245, 245, 245), 0.14);
        t.historyItemHover = blendColor(base, elevated, 0.82);
        t.historyItemSelected = blendColor(brightAccent, QColor(90, 90, 90), 0.30);
    }
    else
    {
        QColor base = blendColor(windowColor, QColor(248, 248, 248), 0.78);
        QColor elevated = blendColor(base, QColor(238, 238, 238), 0.62);
        QColor stroke = blendColor(base, QColor(208, 208, 208), 0.84);
        QColor softAccent = blendColor(accent, QColor(255, 255, 255), 0.30);

        t.panelBg = base;
        t.headerBg = blendColor(base, QColor(240, 240, 240), 0.6);
        t.headerBorder = stroke;
        t.textPrimary = textColor;
        t.textSecondary = blendColor(textColor, base, 0.20);
        t.textMuted = blendColor(textColor, base, 0.34);
        t.inputBg = blendColor(baseColor, elevated, 0.54);
        t.inputBorder = stroke;
        t.inputBorderFocus = blendColor(softAccent, QColor(120, 120, 120), 0.26);
        t.buttonPrimary = blendColor(softAccent, QColor(110, 110, 110), 0.20);
        t.buttonPrimaryHover = blendColor(t.buttonPrimary, QColor(255, 255, 255), 0.12);
        t.buttonPrimaryPressed = blendColor(t.buttonPrimary, QColor(50, 50, 50), 0.14);
        t.buttonSecondaryBg = QColor(0, 0, 0, 0);
        t.buttonSecondaryBorder = stroke;
        t.buttonSecondaryHover = blendColor(base, elevated, 0.68);
        t.messageBgUser = blendColor(softAccent, QColor(235, 240, 246), 0.52);
        t.messageBgAi = blendColor(base, QColor(233, 236, 240), 0.78);
        t.messageBgSystem = blendColor(base, QColor(235, 235, 235), 0.66);
        t.messageBorder = blendColor(base, stroke, 0.9);
        t.bubbleAiText = textColor;
        t.codeBlockBg = yellowCodeBg;
        t.codeBlockBorder = yellowCodeBorder;
        t.codeBlockText = textColor;
        t.inlineCodeBg = yellowInlineBg;
        t.inlineCodeText = textColor;
        t.accentColor = accent;
        t.selectionBg = blendColor(t.buttonPrimary, QColor(225, 225, 225), 0.68);
        t.linkColor = blendColor(accent, QColor(20, 20, 20), 0.12);
        t.historyItemHover = blendColor(base, elevated, 0.66);
        t.historyItemSelected = blendColor(t.buttonPrimary, QColor(105, 105, 105), 0.26);
    }

    return t;
}

void AiDAChatPanel::updateThemeColors()
{
    if (m_updatingTheme)
        return;
    m_updatingTheme = true;

    ThemeColors newTheme = detectThemeColors();

    const bool palette_same =
        newTheme.panelBg == m_theme.panelBg
        && newTheme.textPrimary == m_theme.textPrimary
        && newTheme.inputBg == m_theme.inputBg
        && newTheme.messageBgAi == m_theme.messageBgAi
        && newTheme.headerBg == m_theme.headerBg;

    if (palette_same)
    {
        m_updatingTheme = false;
        return;
    }

    m_theme = newTheme;
    setStyleSheet(buildWidgetStylesheet());
    QPalette chatPal = m_chatDisplay->palette();
    chatPal.setColor(QPalette::Base, m_theme.panelBg);
    chatPal.setColor(QPalette::Window, m_theme.panelBg);
    m_chatDisplay->setPalette(chatPal);
    m_chatDisplay->viewport()->setPalette(chatPal);
    if (m_chatDisplayViewport != nullptr)
        m_chatDisplayViewport->setPalette(chatPal);

    if (m_inputField != nullptr)
    {
        QPalette inputPal = m_inputField->palette();
        inputPal.setColor(QPalette::Base, m_theme.inputBg);
        inputPal.setColor(QPalette::Text, m_theme.textPrimary);
#if QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)
        inputPal.setColor(
            QPalette::PlaceholderText,
            blendColor(m_theme.textSecondary, m_theme.inputBg, 0.48));
#endif
        m_inputField->setPalette(inputPal);
    }

    rebuildChatDisplay();
    m_updatingTheme = false;
}

QString AiDAChatPanel::buildWidgetStylesheet() const
{
    const ThemeColors& t = m_theme;
    const bool darkTheme = isLikelyDarkSurface(t.panelBg)
        || isLikelyDarkSurface(t.messageBgAi)
        || t.textPrimary.lightnessF() > 0.60;
    const QColor aiCardBg = blendColor(t.messageBgAi, t.panelBg, 0.30);
    const QColor aiCardBorder = blendColor(t.messageBorder, t.panelBg, 0.18);
    const QColor contentText = contrastSafeTextColor(t.bubbleAiText, aiCardBg, darkTheme);
    const QColor bodyText = contrastSafeTextColor(t.textPrimary, t.panelBg, darkTheme);
    const QColor subtleText = contrastSafeTextColor(t.textSecondary, t.panelBg, darkTheme);

    QString css;
    css.reserve(6000);

    css += QStringLiteral(
        "QWidget#aidaChatPanel, QWidget#aidaChatPanel * {"
        "  font-family: 'Segoe UI Variable Text', 'Segoe UI', 'Nirmala UI', sans-serif;"
        "  font-size: 9pt;"
        "}");

    css += QStringLiteral("QWidget#aidaChatPanel { background-color: %1; }")
        .arg(colorToRgb(t.panelBg));

    css += QStringLiteral("QWidget#headerBar { background-color: %1; border: 1px solid %2; border-radius: 9px; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.headerBorder));

    css += QStringLiteral(
        "QLabel#headerLabel { color: %1; font-size: 10pt; font-weight: 700; padding: 0px; background: transparent; letter-spacing: 0.35px; }")
        .arg(colorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QLabel#contextLabel { color: %1; font-size: 8.5pt; padding: 0px; background: transparent; }")
        .arg(colorToRgb(t.textSecondary));

    css += QStringLiteral(
        "QPushButton#historyBtn, QPushButton#newChatBtn {"
        "  background-color: transparent; color: %1; border: 1px solid %2; border-radius: 9px;"
        "  padding: 3px 10px; font-size: 8pt; min-height: 22px; }")
        .arg(colorToRgb(t.textMuted), colorToRgb(t.buttonSecondaryBorder));
    css += QStringLiteral(
        "QPushButton#historyBtn:hover, QPushButton#newChatBtn:hover {"
        "  background-color: %1; color: %2; border-color: %3; }")
        .arg(colorToRgb(t.buttonSecondaryHover), colorToRgb(t.textPrimary), colorToRgb(t.inputBorder));
    css += QStringLiteral(
        "QPushButton#historyBtn:pressed, QPushButton#newChatBtn:pressed { background-color: %1; }")
        .arg(colorToRgb(t.buttonSecondaryHover.darker(108)));
    css += QStringLiteral(
        "QPushButton#historyBtn:checked { background-color: %1; color: %2; border-color: %1; }")
        .arg(colorToRgb(t.historyItemSelected), colorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QScrollArea#chatDisplay { background-color: %1; border: 1px solid %2; border-radius: 10px; }")
        .arg(colorToRgb(t.panelBg), colorToRgb(t.headerBorder));
    css += QStringLiteral(
        "QScrollArea#chatDisplay QScrollBar:vertical {"
        " background: %1; width: 8px; margin: 4px 2px; border-radius: 4px; }"
        "QScrollArea#chatDisplay QScrollBar::handle:vertical {"
        " background: %2; min-height: 30px; border-radius: 4px; }"
        "QScrollArea#chatDisplay QScrollBar::handle:vertical:hover {"
        " background: %3; }"
        "QScrollArea#chatDisplay QScrollBar::add-line:vertical,"
        "QScrollArea#chatDisplay QScrollBar::sub-line:vertical {"
        " height: 0px; }")
        .arg(colorToRgb(t.panelBg), colorToRgb(t.headerBorder), colorToRgb(t.textSecondary));
    css += QStringLiteral(
        "QWidget#chatDisplayViewport { background-color: %1; }")
        .arg(colorToRgb(t.panelBg));
    css += QStringLiteral(
        "QWidget#chatMessageRow, QWidget#chatMessageIntro, QWidget#chatMessageActions, QWidget#chatMessageSpacer {"
        " background: transparent; border: none; }");
    css += QStringLiteral(
        "QWidget#chatThinkingContent { background: transparent; border: none; }");
    css += QStringLiteral(
        "QWidget#chatAiContent {"
        " background-color: %1; border: 1px solid %2; border-radius: 12px;"
        "}")
        .arg(colorToRgb(aiCardBg), colorToRgb(aiCardBorder));
    css += QStringLiteral(
        "QWidget#chatAiFooter {"
        " background: transparent; border: none; }");
    css += QStringLiteral(
        "QFrame#userBubble { background-color: %1; border: 1px solid %2; border-radius: 8px; }")
        .arg(colorToRgb(t.messageBgUser), colorToRgb(t.messageBorder));
    css += QStringLiteral(
        "QFrame#systemBubble { background-color: %1; border: 1px solid %2; border-radius: 8px; }")
        .arg(colorToRgb(t.messageBgSystem), colorToRgb(t.messageBorder));
    css += QStringLiteral(
        "QLabel#chatSenderLabel { color: %1; font-size: 7.5pt; font-weight: 700; padding: 0px; background: transparent; }")
        .arg(colorToRgb(t.textPrimary));
    css += QStringLiteral(
        "QLabel#chatTextLabel { color: %1; font-size: 8.5pt; background: transparent; }")
        .arg(colorToRgb(bodyText));
    QColor thinkingColor = subtleText;
    thinkingColor.setAlpha(darkTheme ? 155 : 170);
    QColor thinkingHeaderColor = bodyText;
    thinkingHeaderColor.setAlpha(darkTheme ? 188 : 205);
    css += QStringLiteral(
        "QLabel#chatThinkingHeaderLabel { color: %1; font-size: 8pt; font-weight: 600; background: transparent; }")
        .arg(colorToRgba(thinkingHeaderColor));
    css += QStringLiteral(
        "QPushButton#chatThinkingHeaderBtn {"
        " color: %1; background: transparent; border: none;"
        " text-align: left; padding: 0px 2px; font-size: 7pt; font-weight: 500; }")
        .arg(colorToRgba(thinkingHeaderColor));
    css += QStringLiteral(
        "QPushButton#chatThinkingHeaderBtn:hover { color: %1; text-decoration: underline; }")
        .arg(colorToRgba(contrastSafeTextColor(t.textPrimary, t.panelBg, darkTheme)));
    css += QStringLiteral(
        "QLabel#chatThinkingLabel { color: %1; font-size: 7.2pt; background: transparent; }")
        .arg(colorToRgba(thinkingColor));
    css += QStringLiteral(
        "QPushButton#chatActionBtn { background: transparent; border: 1px solid transparent; border-radius: 7px; color: %1; padding: 3px; min-width: 28px; min-height: 28px; max-width: 28px; max-height: 28px; }")
        .arg(colorToRgb(t.linkColor));
    css += QStringLiteral(
        "QPushButton#chatActionBtn:hover { background: %1; border-color: %2; }")
        .arg(colorToRgba(blendColor(t.buttonSecondaryHover, t.panelBg, 0.18)), colorToRgb(blendColor(t.messageBorder, t.panelBg, 0.18)));
    css += QStringLiteral(
        "QPushButton#chatActionBtn:pressed { background: %1; }")
        .arg(colorToRgba(blendColor(t.buttonSecondaryHover, t.panelBg, 0.30)));
    css += QStringLiteral(
        "QTextEdit#chatEditField { background: %1; border: 1px solid %2; border-radius: 6px;"
        " color: %3; font-size: 8.5pt; padding: 4px 6px; }")
        .arg(colorToRgb(t.inputBg), colorToRgb(t.inputBorder), colorToRgb(t.textPrimary));
    css += QStringLiteral(
        "QTextBrowser#chatMessageBrowser, ChatTextBrowser#chatMessageBrowser, QWidget#chatMessageBrowser {"
        " background: transparent; border: none; color: %1; selection-background-color: %2; padding: 0px;"
        "}")
        .arg(colorToRgb(contentText), colorToRgb(t.selectionBg));

    css += QStringLiteral(
        "QLabel#chatLiveStatusLabel { color: %1; font-size: 7.5pt; font-weight: 500; padding: 1px 0px; background: transparent; }")
        .arg(colorToRgb(t.accentColor));

    css += QStringLiteral(
        "QWidget#inputContainer { background-color: %1; border-top: 1px solid %2; }")
        .arg(colorToRgb(t.panelBg), colorToRgb(t.headerBorder));

    css += QStringLiteral(
        "QTextEdit#chatInput { background-color: %1; border: 1.5px solid %2; border-radius: 12px;"
        "  color: %3; font-size: 9pt; padding: 5px 11px; selection-background-color: %4; }")
        .arg(colorToRgb(t.inputBg), colorToRgb(t.inputBorder), colorToRgb(t.textPrimary), colorToRgb(t.selectionBg));
    css += QStringLiteral(
        "QTextEdit#chatInput:focus { border: 1px solid %1; }")
        .arg(colorToRgb(t.inputBorderFocus));

    css += QStringLiteral(
        "QPushButton#sendBtn { background-color: %1; color: %3; border: 1px solid %2; border-radius: 12px;"
        "  padding: 4px 14px; font-size: 9pt; font-weight: 700; min-height: 30px; min-width: 84px; letter-spacing: 0.25px; }")
        .arg(colorToRgb(t.buttonPrimary), colorToRgb(t.buttonPrimary.darker(112)), colorToRgb(t.textPrimary));
    css += QStringLiteral("QPushButton#sendBtn:hover { background-color: %1; }")
        .arg(colorToRgb(t.buttonPrimaryHover));
    css += QStringLiteral("QPushButton#sendBtn:pressed { background-color: %1; }")
        .arg(colorToRgb(t.buttonPrimaryPressed));
    css += QStringLiteral(
        "QPushButton#sendBtn:disabled { background-color: %1; color: %2; border-color: %3; }")
        .arg(colorToRgb(t.inputBorder), colorToRgb(t.textSecondary), colorToRgb(t.inputBorder));

    css += QStringLiteral(
        "QPushButton#cancelBtn { background-color: %1; color: %2; border: 1px solid %3; border-radius: 12px;"
        "  padding: 4px 14px; font-size: 9pt; font-weight: 700; min-height: 30px; min-width: 84px; letter-spacing: 0.25px; }")
        .arg(colorToRgb(blendColor(QColor(160, 55, 55), t.panelBg, 0.40)),
             colorToRgb(t.textPrimary),
             colorToRgb(blendColor(QColor(160, 55, 55), t.panelBg, 0.50)));
    css += QStringLiteral(
        "QPushButton#cancelBtn:hover { background-color: %1; }")
        .arg(colorToRgb(blendColor(QColor(175, 65, 65), t.panelBg, 0.32)));
    css += QStringLiteral(
        "QPushButton#cancelBtn:pressed { background-color: %1; }")
        .arg(colorToRgb(blendColor(QColor(145, 50, 50), t.panelBg, 0.45)));

    css += QStringLiteral(
        "QPushButton#tagBtn { background-color: transparent; color: %1;"
        "  border: 1px solid %2; border-radius: 10px; padding: 3px 10px; font-size: 8pt; min-height: 30px; }")
        .arg(colorToRgb(t.textSecondary), colorToRgb(t.buttonSecondaryBorder));
    css += QStringLiteral(
        "QPushButton#tagBtn:hover {"
        "  background-color: %1; color: %2; border-color: %3; }")
        .arg(colorToRgb(t.buttonSecondaryHover), colorToRgb(t.textPrimary), colorToRgb(t.inputBorder));

    css += QStringLiteral(
        "QComboBox#modelPicker {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: 10px;"
        "  padding: 3px 26px 3px 10px; min-height: 30px;"
        "}")
        .arg(colorToRgb(blendColor(t.inputBg, t.panelBg, 0.25)),
             colorToRgb(t.textPrimary),
             colorToRgb(t.buttonSecondaryBorder));
    css += QStringLiteral(
        "QComboBox#modelPicker:hover { border-color: %1; background-color: %2; }")
        .arg(colorToRgb(t.inputBorder), colorToRgb(t.buttonSecondaryHover));
    css += QStringLiteral(
        "QComboBox#modelPicker:focus { border-color: %1; }")
        .arg(colorToRgb(t.inputBorderFocus));
    css += QStringLiteral(
        "QComboBox#modelPicker::drop-down {"
        "  width: 20px; border: none;"
        "  background: transparent;"
        "}");
    css += QStringLiteral(
        "QComboBox#modelPicker QAbstractItemView {"
        "  background: %1; color: %2;"
        "  border: 1px solid %3;"
        "  selection-background-color: %4;"
        "  selection-color: %2;"
        "}")
        .arg(colorToRgb(t.headerBg),
             colorToRgb(t.textPrimary),
             colorToRgb(t.headerBorder),
             colorToRgb(t.historyItemSelected));

    css += QStringLiteral("QWidget#historyPanel { background-color: %1; border-right: 1px solid %2; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.headerBorder));

    css += QStringLiteral(
        "QListWidget#historyList { background-color: %1; color: %2; border: none; font-size: 8pt; outline: none; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.textPrimary));
    css += QStringLiteral(
        "QListWidget#historyList::item { padding: 6px 8px; border-bottom: 1px solid %1; }")
        .arg(colorToRgb(t.messageBorder));
    css += QStringLiteral(
        "QListWidget#historyList::item:selected { background-color: %1; color: %2; }")
        .arg(colorToRgb(t.historyItemSelected), colorToRgb(t.textPrimary));
    css += QStringLiteral(
        "QListWidget#historyList::item:hover { background-color: %1; }")
        .arg(colorToRgb(t.historyItemHover));

    css += QStringLiteral(
        "QLabel#historyTitle { padding: 7px 9px; font-weight: 650; font-size: 8pt;"
        "  color: %1; background-color: %2; border-bottom: 1px solid %3; }")
        .arg(colorToRgb(t.textPrimary), colorToRgb(t.headerBg), colorToRgb(t.headerBorder));

    css += QStringLiteral(
        "FunctionCompleterPopup { background-color: %1; border: 1px solid %2; border-radius: 12px; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.inputBorderFocus));
    css += QStringLiteral(
        "FunctionCompleterPopup QListWidget { background-color: %1; color: %2; border: none;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace; font-size: 7.5pt; outline: none; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.textPrimary));
    css += QStringLiteral("FunctionCompleterPopup QListWidget::item { padding: 4px 8px; }");
    css += QStringLiteral(
        "FunctionCompleterPopup QListWidget::item:selected { background-color: %1; color: %2; }")
        .arg(colorToRgb(t.historyItemSelected), colorToRgb(t.textPrimary));
    css += QStringLiteral(
        "FunctionCompleterPopup QListWidget::item:hover { background-color: %1; }")
        .arg(colorToRgb(t.historyItemHover));

    css += QStringLiteral(
        "QLabel#toastLabel {"
        "  background-color: %1;"
        "  color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 8px;"
        "  padding: 3px 12px;"
        "  font-size: 8pt;"
        "  font-weight: 600;"
        "}")
        .arg(colorToRgb(t.headerBg),
             colorToRgb(t.textPrimary),
             colorToRgb(t.messageBorder));

    return css;
}

QString AiDAChatPanel::buildDocumentCss() const
{
    const ThemeColors& t = m_theme;
    const bool darkTheme = isLikelyDarkSurface(t.panelBg)
        || isLikelyDarkSurface(t.messageBgAi)
        || t.textPrimary.lightnessF() > 0.60;
    const QColor mainTextColor = contrastSafeTextColor(
        darkTheme ? QColor(244, 247, 250) : t.bubbleAiText,
        t.messageBgAi,
        darkTheme);
    const QColor mutedTextColor = contrastSafeTextColor(
        darkTheme ? QColor(214, 220, 228) : t.textSecondary,
        t.messageBgAi,
        darkTheme);
    const QColor headingTextColor = contrastSafeTextColor(
        darkTheme ? QColor(248, 250, 252) : t.accentColor,
        t.messageBgAi,
        darkTheme);
    const QColor linkTextColor = contrastSafeTextColor(
        darkTheme ? QColor(220, 232, 247) : t.linkColor,
        t.messageBgAi,
        darkTheme);
    const QString mainText = colorToHex(mainTextColor);
    const QString mutedText = colorToHex(mutedTextColor);
    const QString headingText = colorToHex(headingTextColor);
    const QString linkText = colorToHex(linkTextColor);
    const QString inlineBg = darkTheme ? QStringLiteral("rgba(255,255,255,0.12)") : colorToHex(t.inlineCodeBg);
    const QString preBg = darkTheme ? QStringLiteral("rgba(255,255,255,0.08)") : colorToHex(t.codeBlockBg);
    const QString preBorder = darkTheme ? QStringLiteral("rgba(255,255,255,0.18)") : colorToHex(t.codeBlockBorder);

    QString css;
    css.reserve(6000);

    css += QStringLiteral(
        "body {"
        "  background-color: transparent;"
        "  color: %2;"
        "  font-family: 'Segoe UI Variable Text', 'Segoe UI', 'Nirmala UI', sans-serif;"
        "  font-size: 9pt;"
        "  line-height: 1.25;"
        "  margin: 0;"
        "  padding: 0;"
        "}")
        .arg(colorToHex(t.panelBg), mainText);

    css += QStringLiteral(
        ".assistant-content { color: %1; }"
        ".assistant-content p { margin: 0 0 1px 0; }"
        ".assistant-content p:last-child { margin-bottom: 0; }"
        ".assistant-content ul, .assistant-content ol { margin: 1px 0 1px 18px; padding: 0; }"
        ".assistant-content li { margin: 0; }"
        ".assistant-content table, .assistant-content td, .assistant-content th, .assistant-content span, .assistant-content div, .assistant-content a { color: %1; }")
        .arg(mainText);

    css += QStringLiteral(
        "table.msg-row { width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 6px 0; }");
    css += QStringLiteral("table.msg-row td { vertical-align: top; padding: 0 4px; }");
    css += QStringLiteral("td.msg-side { width: 16%; }");
    css += QStringLiteral("td.msg-cell-right { text-align: right; }");
    css += QStringLiteral("td.msg-cell-left { text-align: left; }");

    css += QStringLiteral(
        ".bubble-user, .bubble-ai {"
        "  display: inline-block;"
        "  max-width: 84%;"
        "  text-align: left;"
        "  word-wrap: break-word;"
        "  overflow-wrap: anywhere;"
        "}")
        .arg(colorToHex(t.messageBorder));

    css += QStringLiteral(
        ".bubble-user {"
        "  border: 1px solid %1;"
        "  border-radius: 8px;"
        "  padding: 4px 12px 3px 12px;"
        "  background-color: %2;"
        "  color: %3;"
        "}")
        .arg(colorToHex(t.messageBorder),
             colorToHex(t.messageBgUser),
             colorToHex(t.textPrimary));

    css += QStringLiteral(
        ".bubble-ai {"
        "  border: 1px solid %1;"
        "  border-left-width: 3px;"
        "  border-radius: 2px 12px 12px 2px;"
        "  padding: 6px 10px 4px 10px;"
        "  background-color: %2;"
        "  color: %3;"
        "}")
        .arg(colorToHex(t.accentColor),
             colorToHex(t.messageBgAi),
             colorToHex(t.bubbleAiText));

    css += QStringLiteral(
        ".msg-system {"
        "  margin: 4px auto 8px auto;"
        "  max-width: 88%;"
        "  padding: 4px 8px;"
        "  background-color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 6px;"
        "  color: %1;"
        "  font-size: 7.5pt;"
        "  text-align: center;"
        "}")
        .arg(colorToHex(t.textSecondary), colorToHex(t.messageBgSystem), colorToHex(t.messageBorder));

    css += QStringLiteral(".msg-content { line-height: 1.38; margin: 0; }");
    css += QStringLiteral(".msg-actions { text-align: right; padding-top: 4px; margin-top: 4px; margin-bottom: 0; }");

    css += QStringLiteral(
        ".msg-sender-label {"
        "  font-size: 7pt;"
        "  font-weight: 700;"
        "  color: %1;"
        "  padding: 0 2px 2px 2px;"
        "  margin: 0;"
        "  letter-spacing: 0.2px;"
        "}")
        .arg(colorToHex(t.textMuted));

    css += QStringLiteral(
        ".copy-btn-user, .copy-btn {"
        "  color: %1;"
        "  font-size: 7pt;"
        "  font-weight: 600;"
        "  text-decoration: none;"
        "}")
        .arg(linkText);
    css += QStringLiteral(".copy-btn-user { color: %1; }")
        .arg(colorToHex(t.textPrimary));
    css += QStringLiteral(
        ".copy-btn-outline {"
        "  border: 1px solid %1;"
        "  border-radius: 8px;"
        "  padding: 1px 6px;"
        "  margin: 0 1px;"
        "}")
        .arg(colorToHex(blendColor(t.messageBorder, t.panelBg, 0.5)));

    css += QStringLiteral(
        ".tag-ref {"
        "  color: %1;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace;"
        "  background-color: %2;"
        "  padding: 1px 6px;"
        "  border-radius: 4px;"
        "  text-decoration: none;"
        "}")
        .arg(mainText, inlineBg);

    css += QStringLiteral(
        "pre {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 6px;"
        "  padding: 4px 6px;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace;"
        "  font-size: 7.5pt;"
        "  color: %3;"
        "  margin: 2px 0 2px 0;"
        "  white-space: pre-wrap;"
        "  word-wrap: break-word;"
        "  overflow-wrap: anywhere;"
        "  line-height: 1.2;"
        "}")
        .arg(preBg, preBorder, mainText);

    css += QStringLiteral(
        ".bubble-user pre, .bubble-ai pre { max-width: 100%; box-sizing: border-box; }");

    css += QStringLiteral(
        "code {"
        "  background-color: %1;"
        "  color: %2;"
        "  padding: 1px 4px;"
        "  border-radius: 3px;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace;"
        "  font-size: 7.5pt;"
        "}")
        .arg(inlineBg, mainText);

    css += QStringLiteral(
        ".nav-link {"
        "  color: %1;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace;"
        "  font-size: 7.5pt;"
        "  background-color: %2;"
        "  padding: 1px 4px;"
        "  border-radius: 3px;"
        "  text-decoration: none;"
        "  border-bottom: 1px dashed %1;"
        "}")
        .arg(linkText, inlineBg);
    css += QStringLiteral(
        ".nav-link:hover { text-decoration: underline; background-color: %1; }")
        .arg(colorToHex(t.selectionBg));

    css += QStringLiteral(
        ".md-heading { font-weight: 700; color: %1; display: block; margin: 1px 0 2px 0; }")
        .arg(headingText);
    css += QStringLiteral(".md-h1 { font-size: 11pt; }");
    css += QStringLiteral(".md-h2 { font-size: 10pt; }");
    css += QStringLiteral(".md-h3 { font-size: 9pt; }");

    css += QStringLiteral(
        "table.md-table { border-collapse: collapse; margin: 2px 0; width: auto; }");
    css += QStringLiteral(
        "table.md-table th, table.md-table td {"
        "  border: 1px solid %1;"
        "  padding: 2px 5px;"
        "  text-align: left;"
        "  font-size: 7.5pt;"
        "}")
        .arg(colorToHex(blendColor(t.messageBorder, t.panelBg, 0.6)));
    css += QStringLiteral(
        "table.md-table th {"
        "  background-color: %1;"
        "  font-weight: 700;"
        "}")
        .arg(darkTheme ? QStringLiteral("rgba(255,255,255,0.10)") : colorToHex(blendColor(t.headerBg, t.panelBg, 0.5)));
    css += QStringLiteral(
        "table.md-table tr:nth-child(even) {"
        "  background-color: %1;"
        "}")
        .arg(darkTheme ? QStringLiteral("rgba(255,255,255,0.05)") : colorToHex(blendColor(t.messageBgAi, t.panelBg, 0.3)));

    return css;
}

void AiDAChatPanel::setupStyle()
{
    m_theme = detectThemeColors();
    setStyleSheet(buildWidgetStylesheet());
    applyResponsiveMetrics();
    QPalette chatPal = m_chatDisplay->palette();
    chatPal.setColor(QPalette::Base, m_theme.panelBg);
    chatPal.setColor(QPalette::Window, m_theme.panelBg);
    m_chatDisplay->setPalette(chatPal);
    m_chatDisplay->viewport()->setPalette(chatPal);
    if (m_chatDisplayViewport != nullptr)
        m_chatDisplayViewport->setPalette(chatPal);

    QPalette inputPal = m_inputField->palette();
    inputPal.setColor(QPalette::Base, m_theme.inputBg);
    inputPal.setColor(QPalette::Text, m_theme.textPrimary);
#if QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)
    inputPal.setColor(
        QPalette::PlaceholderText,
        blendColor(m_theme.textSecondary, m_theme.inputBg, 0.48));
#endif
    m_inputField->setPalette(inputPal);
}

bool AiDAChatPanel::event(QEvent* ev)
{
    if (ev->type() == QEvent::PaletteChange || ev->type() == QEvent::StyleChange)
    {
        if (!m_updatingTheme)
            updateThemeColors();
    }
    if (ev->type() == QEvent::WindowActivate)
        refreshModelPicker();
    const bool resized = ev->type() == QEvent::Resize;
    const bool shown = ev->type() == QEvent::Show;
    const bool result = QWidget::event(ev);
    if (resized || shown)
    {
        if (shown)
            refreshModelPicker();
        applyResponsiveMetrics();

        if (m_rebuildDebounceTimer == nullptr)
        {
            m_rebuildDebounceTimer = new QTimer(this);
            m_rebuildDebounceTimer->setSingleShot(true);
            m_rebuildDebounceTimer->setInterval(50);
            QObject::connect(m_rebuildDebounceTimer, &QTimer::timeout, this, [this]() {
                rebuildChatDisplay();
            });
        }
        if (!m_rebuildDebounceTimer->isActive())
            m_rebuildDebounceTimer->start();
    }
    return result;
}

void AiDAChatPanel::updateContextLabel()
{
    if (m_contextEa != BADADDR && !m_contextFuncName.isEmpty())
    {
        m_contextLabel->setText(
            QStringLiteral("Context: @%1 (0x%2)")
                .arg(m_contextFuncName)
                .arg(QString::number(static_cast<quint64>(m_contextEa), 16).toUpper()));
    }
    else
    {
        m_contextLabel->setText(
            QStringLiteral("No function context \u2014 select a function first"));
    }
}

bool AiDAChatPanel::eventFilter(QObject* obj, QEvent* event)
{
    if (obj == m_inputField && event->type() == QEvent::KeyPress)
    {
        QKeyEvent* ke = static_cast<QKeyEvent*>(event);

        if (m_completerActive && m_completer->isActive())
        {
            if (ke->key() == Qt::Key_Up)
            {
                m_completer->moveSelection(-1);
                return true;
            }
            if (ke->key() == Qt::Key_Down)
            {
                m_completer->moveSelection(1);
                return true;
            }
            if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter
                || ke->key() == Qt::Key_Tab)
            {
                QString sel = m_completer->currentSelection();
                if (!sel.isEmpty())
                    insertCompletion(sel);
                m_completer->dismiss();
                m_completerActive = false;
                return true;
            }
            if (ke->key() == Qt::Key_Escape)
            {
                m_completer->dismiss();
                m_completerActive = false;
                return true;
            }
        }

        if ((ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter)
            && (ke->modifiers() & Qt::ControlModifier))
        {
            sendMessage();
            return true;
        }

        if (ke->key() == Qt::Key_Escape && m_isWaiting)
        {
            cancelRequest();
            return true;
        }

        if (ke->text() == QStringLiteral("@"))
        {
            QTimer::singleShot(0, [this]() { handleAtTrigger(); });
        }

        if (m_completerActive
            && !ke->text().isEmpty()
            && (ke->text().at(0).isLetterOrNumber() || ke->text().at(0) == QChar('_')))
        {
            QTimer::singleShot(0, [this]() {
                int atPos = findAtPosition();
                if (atPos >= 0)
                {
                    QString text = m_inputField->toPlainText();
                    QString prefix = text.mid(atPos + 1);
                    int end = static_cast<int>(prefix.indexOf(QChar(' ')));
                    if (end >= 0)
                        prefix = prefix.left(end);

                    QTextCursor cursor = m_inputField->textCursor();
                    QRect cursorRect = m_inputField->cursorRect(cursor);
                    QPoint globalPos = m_inputField->mapToGlobal(
                        cursorRect.bottomLeft() + QPoint(0, 4));

                    m_completer->showForPrefix(prefix, globalPos);
                }
                else
                {
                    m_completer->dismiss();
                    m_completerActive = false;
                }
            });
        }

        if (m_completerActive && ke->key() == Qt::Key_Backspace)
        {
            QTimer::singleShot(0, [this]() {
                int atPos = findAtPosition();
                if (atPos < 0)
                {
                    m_completer->dismiss();
                    m_completerActive = false;
                }
                else
                {
                    QString text = m_inputField->toPlainText();
                    QString prefix = text.mid(atPos + 1);
                    int end = static_cast<int>(prefix.indexOf(QChar(' ')));
                    if (end >= 0)
                        prefix = prefix.left(end);

                    QTextCursor cursor = m_inputField->textCursor();
                    QRect cursorRect = m_inputField->cursorRect(cursor);
                    QPoint globalPos = m_inputField->mapToGlobal(
                        cursorRect.bottomLeft() + QPoint(0, 4));

                    m_completer->showForPrefix(prefix, globalPos);
                }
            });
        }
    }

    if (obj == m_inputField && event->type() == QEvent::FocusOut)
    {
        if (m_completerActive)
        {
            QTimer::singleShot(150, [this]() {
                if (m_completerActive && !m_inputField->hasFocus())
                {
                    m_completer->dismiss();
                    m_completerActive = false;
                }
            });
        }
    }

    if (obj == m_editingField && event->type() == QEvent::KeyPress)
    {
        QKeyEvent* ke = static_cast<QKeyEvent*>(event);
        if (ke->key() == Qt::Key_Escape)
        {
            cancelEditMode();
            return true;
        }
        if ((ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter)
            && (ke->modifiers() & Qt::ControlModifier))
        {
            int idx = m_editingIndex;
            if (idx >= 0)
                commitEdit(idx);
            return true;
        }
    }

    if (obj == m_editingField && event->type() == QEvent::FocusOut)
    {
        QTimer::singleShot(200, this, [this]() {
            if (m_editingIndex >= 0 && m_editingField != nullptr
                && !m_editingField->hasFocus())
            {
                cancelEditMode();
            }
        });
    }

    if (event->type() == QEvent::MouseButtonPress && obj != m_editingField)
    {
        QVariant indexProp = obj->property("historyIndex");
        if (indexProp.isValid() && m_editingIndex < 0 && !m_isWaiting)
        {
            enterEditMode(indexProp.toInt());
            return true;
        }

        if (m_editingIndex >= 0 && m_editingField != nullptr)
        {
            QWidget* target = qobject_cast<QWidget*>(obj);
            bool insideEdit = false;
            while (target != nullptr)
            {
                if (target == m_editingField
                    || (target->objectName() == QStringLiteral("chatActionBtn")
                        && target->parentWidget() != nullptr
                        && target->parentWidget()->objectName() == QStringLiteral("userBubble")))
                {
                    insideEdit = true;
                    break;
                }
                target = target->parentWidget();
            }
            if (!insideEdit)
            {
                cancelEditMode();
                return false;
            }
        }
    }

    return QWidget::eventFilter(obj, event);
}

void AiDAChatPanel::handleAtTrigger()
{
    int atPos = findAtPosition();
    if (atPos < 0)
        return;

    m_completerActive = true;

    QString text = m_inputField->toPlainText();
    QString prefix = text.mid(atPos + 1);
    int end = static_cast<int>(prefix.indexOf(QChar(' ')));
    if (end >= 0)
        prefix = prefix.left(end);

    QTextCursor cursor = m_inputField->textCursor();
    QRect cursorRect = m_inputField->cursorRect(cursor);
    QPoint globalPos = m_inputField->mapToGlobal(
        cursorRect.bottomLeft() + QPoint(0, 4));

    m_completer->showForPrefix(prefix, globalPos);
}

void AiDAChatPanel::insertCompletion(const QString& funcName)
{
    int atPos = findAtPosition();
    if (atPos < 0)
        return;

    QTextCursor cursor = m_inputField->textCursor();
    QString text = m_inputField->toPlainText();

    int afterAt = atPos + 1;
    int endPos = afterAt;
    while (endPos < text.length()
           && (text[endPos].isLetterOrNumber()
               || text[endPos] == QChar('_')
               || text[endPos] == QChar('$')))
        ++endPos;

    cursor.setPosition(afterAt);
    cursor.setPosition(endPos, QTextCursor::KeepAnchor);
    cursor.insertText(funcName);
    m_inputField->setTextCursor(cursor);
}

int AiDAChatPanel::findAtPosition() const
{
    QTextCursor cursor = m_inputField->textCursor();
    int pos = cursor.position();
    QString text = m_inputField->toPlainText();

    for (int i = pos - 1; i >= 0; --i)
    {
        if (text[i] == QChar('@'))
            return i;
        if (text[i] == QChar(' ') || text[i] == QChar('\n'))
            return -1;
    }
    return -1;
}

void AiDAChatPanel::sendMessage()
{
    if (m_isWaiting) return;

    refreshModelPicker();

    if (m_completerActive)
    {
        m_completer->dismiss();
        m_completerActive = false;
    }

    QString text = m_inputField->toPlainText().trimmed();
    if (text.isEmpty()) return;

    if (text == QStringLiteral("/help"))
    {
        m_history.emplace_back("System",
            "Commands:\n"
            "  /help  \u2014 Show this help\n\n"
            "Tagging:\n"
            "  @function_name \u2014 Include function code in context\n"
            "  @0xADDRESS     \u2014 Include code at address\n\n"
            "Shortcuts:\n"
            "  Ctrl+Enter \u2014 Send message\n\n"
            "The conversation is persistent \u2014 ask follow-up questions "
            "and AiDA will remember the context of earlier messages.");
        rebuildChatDisplay();
        m_inputField->clear();
        return;
    }

    auto tags = parseTags(text);

    for (const auto& tag : tags)
    {
        if (!tag.resolved)
            continue;

        bool alreadyTracked = false;
        for (const auto& existing : m_conversationTags)
        {
            if (existing.resolved_ea == tag.resolved_ea)
            {
                alreadyTracked = true;
                break;
            }
        }
        if (!alreadyTracked)
            m_conversationTags.push_back(tag);
    }

    QString tagContext = buildTagContext(m_conversationTags);

    std::string aiMessage = text.toStdString();
    if (!tagContext.isEmpty())
        aiMessage += "\n\n[Tagged References]\n" + tagContext.toStdString();

    m_history.emplace_back("User", text.toStdString());
    m_userScrolledChat = false;
    rebuildChatDisplay();
    m_inputField->clear();

    if (!m_plugin || !m_plugin->ai_client)
    {
        m_history.emplace_back("System",
            "Error: No AI client available. Configure your API key in Settings.");
        rebuildChatDisplay();
        return;
    }

    setThinkingState(true, false);

    std::vector<std::pair<std::string, std::string>> apiHistory;
    for (const auto& entry : m_history)
    {
        if (entry.first == "User" || entry.first == "AiDA")
            apiHistory.push_back(entry);
    }

    m_plugin->ai_client->agentic_chat(
        m_contextEa, aiMessage, apiHistory,
        [](const std::string& response) {
            AiDAChatPanel* panel = chat_widget::get_panel();
            if (panel != nullptr)
                panel->onAiResponse(response);
        });
}

void AiDAChatPanel::onAiResponse(const std::string& response)
{
    setThinkingState(false, false);

    for (const ThinkingRound& round : m_thinkingRounds)
    {
        QString header = round.header.trimmed();
        if (header.isEmpty())
            header = QStringLiteral("Planning (Round %1)").arg(round.round > 0 ? round.round : 1);
        m_history.emplace_back("ThinkingHeader", header.toStdString());

        const QString details = round.details.trimmed();
        if (!details.isEmpty() && details != header)
            m_history.emplace_back("Thinking", details.toStdString());
    }

    clearThinkingStatus();

    if (response.empty())
    {
        m_history.emplace_back("System", "No response received from AI.");
    }
    else if (response.rfind("Error:", 0) == 0)
    {
        m_history.emplace_back("System", response);
    }
    else
    {
        const QString sanitized = sanitizeAssistantDisplayText(QString::fromStdString(response));
        if (sanitized.isEmpty())
            m_history.emplace_back("AiDA", std::string("No displayable assistant text after sanitization."));
        else
            m_history.emplace_back("AiDA", sanitized.toStdString());
    }
    rebuildChatDisplay();
    saveCurrentConversation();
    saveToDisk();
}

void AiDAChatPanel::setThinkingState(bool thinking, bool rebuildDisplay)
{
    m_isWaiting = thinking;
    m_sendBtn->setVisible(!thinking);
    m_cancelBtn->setVisible(thinking);
    if (m_modelPicker != nullptr)
        m_modelPicker->setEnabled(!thinking);

    if (thinking)
    {
        refreshModelPicker();
        m_typingStatus = QStringLiteral("Thinking");
        m_currentToolStatus.clear();
        m_thinkingStopwatch.start();
        m_thinkingElapsedTimer->start();
        clearThinkingStatus();
    }
    else
    {
        refreshModelPicker();
        m_typewriterTimer->stop();
        m_thinkingElapsedTimer->stop();

        if (!m_typewriterQueue.isEmpty())
            m_typewriterQueue.clear();

        m_currentToolStatus.clear();
        m_activeThinkingRound = -1;
    }

    if (rebuildDisplay)
        rebuildChatDisplay();
}

QString AiDAChatPanel::summarizeThinkingHeader(const QString& reasoning) const
{
    QString cleaned = stripCodeFences(reasoning);
    if (looksLikeStructuredProtocolText(cleaned))
        return QStringLiteral("Planning");

    cleaned.replace(QRegularExpression(QStringLiteral("[\\{\\}\\[\\]\"]")), QStringLiteral(" "));
    cleaned.replace(QRegularExpression(QStringLiteral("\\s+")), QStringLiteral(" "));
    cleaned = cleaned.trimmed();

    if (cleaned.startsWith(QStringLiteral("reasoning:"), Qt::CaseInsensitive))
        cleaned = cleaned.mid(10).trimmed();

    qsizetype punct = static_cast<qsizetype>(-1);
    for (qsizetype i = 0; i < cleaned.size(); ++i)
    {
        const QChar ch = cleaned[i];
        if (ch == QChar('.') || ch == QChar('!') || ch == QChar('?'))
        {
            if (ch == QChar('.') && i + 1 < cleaned.size() && cleaned[i + 1].isLetter())
                continue;
            punct = i;
            break;
        }
    }
    if (punct > 40)
        cleaned = cleaned.left(punct + 1).trimmed();

    if (cleaned.length() > 200)
        cleaned = cleaned.left(200).trimmed() + QStringLiteral("...");

    if (cleaned.isEmpty())
        return QStringLiteral("Planning");

    return cleaned;
}

void AiDAChatPanel::appendThinkingDetail(int round, const QString& line)
{
    QString normalized = line.trimmed();
    if (normalized.isEmpty())
        return;
    if (looksLikeToolStatusNoiseLine(normalized))
        return;

    for (ThinkingRound& entry : m_thinkingRounds)
    {
        if (entry.round != round)
            continue;

        const QStringList lines = entry.details.split(QChar('\n'), Qt::SkipEmptyParts);
        if (!lines.isEmpty() && lines.back().trimmed() == normalized)
            return;

        if (!entry.details.isEmpty())
            entry.details += QChar('\n');
        entry.details += normalized;
        return;
    }
}

void AiDAChatPanel::beginThinkingRound(int round, const QString& statusMessage)
{
    int resolvedRound = round > 0 ? round : (m_activeThinkingRound > 0 ? (m_activeThinkingRound + 1) : 1);
    m_activeThinkingRound = resolvedRound;

    for (ThinkingRound& entry : m_thinkingRounds)
        entry.expanded = false;

    for (ThinkingRound& entry : m_thinkingRounds)
    {
        if (entry.round != resolvedRound)
            continue;

        if (!statusMessage.trimmed().isEmpty() && entry.header.trimmed().isEmpty())
            entry.header = statusMessage.trimmed();
        entry.expanded = true;
        return;
    }

    ThinkingRound entry;
    entry.round = resolvedRound;
    entry.header = statusMessage.trimmed();
    if (entry.header.isEmpty())
        entry.header = QStringLiteral("Planning (Round %1)").arg(resolvedRound);
    entry.expanded = true;
    m_thinkingRounds.push_back(std::move(entry));
    refreshThinkingPanelView();
}

static bool isRoundProgressStatus(const QString& text)
{
    const QString normalized = text.trimmed();
    if (normalized.isEmpty())
        return false;

    if (normalized.startsWith(QStringLiteral("Calling AI (round "), Qt::CaseInsensitive))
        return true;

    static const QRegularExpression roundRe(
        QStringLiteral("^Round\\s+\\d+\\s+of\\s+\\d+$"),
        QRegularExpression::CaseInsensitiveOption);
    return roundRe.match(normalized).hasMatch();
}

void AiDAChatPanel::updateThinkingStatus(int round, const QString& reasoning, const QStringList& pendingTools, const QString& currentTool, const QString& statusMessage)
{
    if (!m_isWaiting)
        return;

    beginThinkingRound(round, statusMessage);

    int resolvedRound = round > 0 ? round : m_activeThinkingRound;
    if (resolvedRound <= 0)
        return;

    const QString normalizedStatus = statusMessage.trimmed();
    const bool statusIsRoundMeta = isRoundProgressStatus(normalizedStatus);

    if (!reasoning.isEmpty())
    {
        QString cleanedReasoning = stripCodeFences(reasoning).trimmed();
        if (!cleanedReasoning.isEmpty() && !looksLikeStructuredProtocolText(cleanedReasoning))
        {
            QString headerText;
            for (ThinkingRound& entry : m_thinkingRounds)
            {
                if (entry.round == resolvedRound)
                {
                    headerText = summarizeThinkingHeader(cleanedReasoning);
                    entry.header = headerText;
                    break;
                }
            }

            if (!headerText.isEmpty()
                && cleanedReasoning.compare(headerText, Qt::CaseInsensitive) != 0
                && !isRoundProgressStatus(cleanedReasoning))
            {
                appendThinkingDetail(resolvedRound, cleanedReasoning);
            }
        }
    }
    else if (!normalizedStatus.isEmpty() && !statusIsRoundMeta && !looksLikeToolStatusNoiseLine(normalizedStatus))
    {
        appendThinkingDetail(resolvedRound, normalizedStatus);
    }

    if (!currentTool.isEmpty())
    {
        m_currentToolStatus = QStringLiteral("Running tool: %1").arg(currentTool);
        m_typingStatus = QStringLiteral("Thinking");
    }
    else if (!pendingTools.isEmpty())
    {
        const qsizetype pendingCount = pendingTools.size();
        m_currentToolStatus = QStringLiteral("%1 tool%2 queued")
                .arg(static_cast<qlonglong>(pendingCount))
                .arg(pendingCount == 1 ? QString() : QStringLiteral("s"));
        m_typingStatus = QStringLiteral("Thinking");
    }
    else
    {
        m_currentToolStatus.clear();
        if (!normalizedStatus.isEmpty())
            m_typingStatus = normalizedStatus;
        else
            m_typingStatus = QStringLiteral("Thinking");
    }

    if (!reasoning.isEmpty())
        refreshThinkingPanelView();
    else
        updateLiveStatusLabel();
}

void AiDAChatPanel::addToolResult(int round, const QString& toolName, bool success, const QString& message)
{
    if (!m_isWaiting)
        return;

    int resolvedRound = round > 0 ? round : m_activeThinkingRound;
    if (resolvedRound <= 0)
        return;

    QString status;
    if (!toolName.trimmed().isEmpty())
    {
        status = success
            ? QStringLiteral("Completed tool: %1").arg(toolName)
            : QStringLiteral("Tool issue: %1").arg(toolName);
    }
    else
    {
        status = success ? QStringLiteral("Tool completed") : QStringLiteral("Tool failed");
    }

    if (!message.trimmed().isEmpty() && !looksLikeToolStatusNoiseLine(message))
        appendThinkingDetail(resolvedRound, message.trimmed());

    m_currentToolStatus = status;
    updateLiveStatusLabel();
}

void AiDAChatPanel::clearThinkingStatus()
{
    m_streamBuffer.clear();
    m_typewriterQueue.clear();
    setProperty("aida_stream_rebuild_pending", false);
    setProperty("aida_status_rebuild_pending", false);
    m_thinkingRounds.clear();
    m_activeThinkingRound = -1;
    m_liveThinkingBlock = nullptr;
    m_liveStreamLabel = nullptr;
    m_liveStatusLabel = nullptr;
    m_currentToolStatus.clear();
}

QString AiDAChatPanel::buildLiveThinkingPreview() const
{
    QString preview = m_streamBuffer.trimmed();
    if (preview.isEmpty())
        return QString();
    if (looksLikeStructuredProtocolText(preview))
        return QString();

    preview.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
    preview.replace(QRegularExpression(QStringLiteral("[\\t ]+")), QStringLiteral(" "));
    preview.replace(QRegularExpression(QStringLiteral("\\n{3,}")), QStringLiteral("\n\n"));
    if (preview.length() > 1400)
        preview = preview.left(1400).trimmed() + QStringLiteral("...");
    return preview;
}

void AiDAChatPanel::refreshThinkingPanelView()
{
    if (!m_isWaiting)
        return;

    if (property("aida_status_rebuild_pending").toBool())
        return;

    setProperty("aida_status_rebuild_pending", true);
    QTimer::singleShot(120, this, [this]() {
        setProperty("aida_status_rebuild_pending", false);
        if (!m_isWaiting)
            return;
        if (m_liveThinkingBlock != nullptr)
            rebuildLiveThinkingBlock();
        else
            rebuildChatDisplay();
    });
}

void AiDAChatPanel::rebuildLiveThinkingBlock()
{
    if (m_liveThinkingBlock == nullptr || !m_isWaiting)
        return;

    QVBoxLayout* blockLayout = qobject_cast<QVBoxLayout*>(m_liveThinkingBlock->layout());
    if (blockLayout == nullptr)
        return;

    m_chatDisplayViewport->setUpdatesEnabled(false);

    QLayoutItem* item = nullptr;
    while ((item = blockLayout->takeAt(0)) != nullptr)
    {
        if (QWidget* w = item->widget())
            delete w;
        delete item;
    }
    m_liveStreamLabel = nullptr;
    m_liveStatusLabel = nullptr;

    const int viewportWidth = m_chatDisplay->viewport()->width() > 0
        ? m_chatDisplay->viewport()->width()
        : qMax(320, width() - 24);
    const int maxBubbleWidth = qMax(260, (viewportWidth * 78) / 100);

    auto addEntry = [&](const QString& role, const QString& msg, int index) {
        if (role == QStringLiteral("ThinkingHeader"))
        {
            bool expanded = false;
            for (const ThinkingRound& entry : m_thinkingRounds)
            {
                if (entry.round == index)
                {
                    expanded = entry.expanded;
                    break;
                }
            }
            QPushButton* headerBtn = new QPushButton(m_liveThinkingBlock);
            headerBtn->setObjectName(QStringLiteral("chatThinkingHeaderBtn"));
            headerBtn->setFlat(true);
            headerBtn->setAutoDefault(false);
            headerBtn->setDefault(false);
            headerBtn->setCursor(Qt::PointingHandCursor);
            headerBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
            headerBtn->setText((expanded ? QStringLiteral("v ") : QStringLiteral("> ")) + msg);
            headerBtn->setToolTip(QStringLiteral("Toggle round thinking details"));
            headerBtn->setMinimumHeight(14);
            headerBtn->setMaximumHeight(18);
            QObject::connect(headerBtn, &QPushButton::clicked, this, [this, index]() {
                for (ThinkingRound& entry : m_thinkingRounds)
                {
                    if (entry.round == index)
                    {
                        entry.expanded = !entry.expanded;
                        break;
                    }
                }
                rebuildLiveThinkingBlock();
            });
            blockLayout->addWidget(headerBtn);
        }
        else
        {
            QLabel* thinkingLabel = new QLabel(msg, m_liveThinkingBlock);
            thinkingLabel->setObjectName(QStringLiteral("chatThinkingLabel"));
            thinkingLabel->setTextFormat(Qt::PlainText);
            thinkingLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
            thinkingLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
            thinkingLabel->setWordWrap(true);
            thinkingLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            thinkingLabel->setMaximumWidth(maxBubbleWidth - 12);
            blockLayout->addWidget(thinkingLabel);
        }
    };

    for (const ThinkingRound& round : m_thinkingRounds)
    {
        QString header = round.header.trimmed();
        if (header.isEmpty())
            header = QStringLiteral("Planning (Round %1)").arg(round.round > 0 ? round.round : 1);

        addEntry(QStringLiteral("ThinkingHeader"), header, round.round);

        if (round.expanded)
        {
            const QString details = round.details.trimmed();
            if (!details.isEmpty())
                addEntry(QStringLiteral("Thinking"), details, round.round);
        }
    }

    {
        nlohmann::json visibleSessions = subagents::list_visible_sessions();
        std::vector<nlohmann::json> activeSessions;
        if (visibleSessions.is_array())
        {
            activeSessions.reserve(visibleSessions.size());
            for (const auto& session : visibleSessions)
            {
                if (session.is_object() && isActiveAgentSessionSummary(session))
                    activeSessions.push_back(session);
            }
        }

        std::sort(activeSessions.begin(), activeSessions.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
            const int ap = activeAgentSortPriority(a);
            const int bp = activeAgentSortPriority(b);
            if (ap != bp)
                return ap < bp;
            return jsonStringValue(a, "label").compare(jsonStringValue(b, "label"), Qt::CaseInsensitive) < 0;
        });

        if (!activeSessions.empty())
        {
            QLabel* agentsHeader = new QLabel(
                QStringLiteral("Active Agents (%1)").arg(static_cast<qlonglong>(activeSessions.size())),
                m_liveThinkingBlock);
            agentsHeader->setObjectName(QStringLiteral("chatThinkingHeaderLabel"));
            blockLayout->addWidget(agentsHeader);

            for (const auto& session : activeSessions)
            {
                QLabel* agentLabel = new QLabel(
                    buildActiveAgentSummaryText(session, m_isWaiting, m_currentToolStatus, m_typingStatus),
                    m_liveThinkingBlock);
                agentLabel->setObjectName(QStringLiteral("chatThinkingLabel"));
                agentLabel->setTextFormat(Qt::PlainText);
                agentLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
                agentLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
                agentLabel->setWordWrap(true);
                agentLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
                agentLabel->setMaximumWidth(maxBubbleWidth - 12);
                blockLayout->addWidget(agentLabel);
            }
        }
    }

    m_liveStreamLabel = new QLabel(m_liveThinkingBlock);
    m_liveStreamLabel->setObjectName(QStringLiteral("chatThinkingLabel"));
    m_liveStreamLabel->setTextFormat(Qt::PlainText);
    m_liveStreamLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    m_liveStreamLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    m_liveStreamLabel->setWordWrap(true);
    m_liveStreamLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_liveStreamLabel->setMaximumWidth(maxBubbleWidth - 12);
    const QString preview = buildLiveThinkingPreview();
    if (!preview.isEmpty())
        m_liveStreamLabel->setText(preview);
    blockLayout->addWidget(m_liveStreamLabel);

    m_liveStatusLabel = new QLabel(m_liveThinkingBlock);
    m_liveStatusLabel->setObjectName(QStringLiteral("chatLiveStatusLabel"));
    m_liveStatusLabel->setTextFormat(Qt::PlainText);
    m_liveStatusLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_liveStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    m_liveStatusLabel->setMinimumHeight(16);
    updateLiveStatusLabel();
    blockLayout->addWidget(m_liveStatusLabel);

    m_chatDisplayViewport->setUpdatesEnabled(true);
    scrollToBottom();
}

void AiDAChatPanel::updateLiveStatusLabel()
{
    if (m_liveStatusLabel == nullptr)
        return;
    qint64 elapsed = m_thinkingStopwatch.elapsed() / 1000;
    QString statusText = m_currentToolStatus.isEmpty()
        ? m_typingStatus : m_currentToolStatus;
    if (elapsed > 0)
        statusText += QStringLiteral("  ") + formatElapsedTime(elapsed);
    m_liveStatusLabel->setText(statusText);
}

static QString stripCodeFences(const QString& text)
{
    QString result;
    result.reserve(text.size());
    QStringList lines = text.split(QChar('\n'));
    for (int i = 0; i < lines.size(); ++i)
    {
        QString trimmed = lines[i].trimmed();
        if (trimmed.startsWith(QStringLiteral("```")))
            continue;
        if (i > 0)
            result += QChar('\n');
        result += lines[i];
    }
    return result;
}

static bool looksLikeToolStatusNoiseLine(const QString& line)
{
    const QString t = line.trimmed();
    if (t.isEmpty())
        return false;

    static const QRegularExpression noiseRe(
        QStringLiteral("^(?:Pending\\s*:|Executing\\s*:|Executing\\b|Running\\s+[A-Za-z0-9_./:-]+|[\\x{2713}\\x{2714}\\x{2717}]\\s*\\S+|OK\\s+\\S+|Failed\\s+\\S+)") ,
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::UseUnicodePropertiesOption);
    if (noiseRe.match(t).hasMatch())
        return true;

    if (t.contains(QStringLiteral("listed"), Qt::CaseInsensitive)
        && t.contains(QStringLiteral("functions"), Qt::CaseInsensitive))
    {
        return true;
    }

    return false;
}

static bool looksLikeStructuredProtocolText(const QString& text)
{
    const QString t = text.trimmed();
    if (t.isEmpty())
        return false;

    if (t.startsWith(QStringLiteral("```json"), Qt::CaseInsensitive)
        || t.startsWith(QStringLiteral("```")))
    {
        return true;
    }

    if (t.startsWith(QChar('{')) || t.startsWith(QChar('[')))
        return true;

    if (t.contains(QStringLiteral("\"tool_calls\""), Qt::CaseInsensitive)
        || t.contains(QStringLiteral("\"reasoning\""), Qt::CaseInsensitive))
    {
        return true;
    }

    if (t.startsWith(QStringLiteral("tool_calls"), Qt::CaseInsensitive)
        || t.startsWith(QStringLiteral("reasoning:"), Qt::CaseInsensitive))
    {
        return true;
    }

    return false;
}

static QString sanitizeAssistantDisplayText(const QString& raw)
{
    QString s = raw;
    s.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
    s.replace(QRegularExpression(QStringLiteral("\\n{3,}")), QStringLiteral("\n\n"));
    return s.trimmed();
}

void AiDAChatPanel::appendStreamChunk(const QString& chunk)
{
    if (!m_isWaiting)
        return;

    QString incoming = chunk;
    incoming.replace(QChar('\r'), QChar('\n'));
    if (incoming.isEmpty())
        return;

    m_streamBuffer += incoming;
    if (m_streamBuffer.size() > 16000)
        m_streamBuffer = m_streamBuffer.right(16000);

    if (m_activeThinkingRound <= 0)
        beginThinkingRound(1, QStringLiteral("Thinking"));

    if (m_liveStreamLabel != nullptr)
    {
        QString preview = buildLiveThinkingPreview();
        if (!preview.isEmpty())
            m_liveStreamLabel->setText(preview);
    }
}

void AiDAChatPanel::resetStreamBuffer()
{
    m_streamBuffer.clear();
    m_typewriterQueue.clear();
}

void AiDAChatPanel::cancelRequest()
{
    if (!m_isWaiting || !m_plugin || !m_plugin->ai_client)
        return;

    m_plugin->ai_client->cancel_current_request();
    setThinkingState(false, false);
    m_history.emplace_back("System", "Request cancelled.");
    rebuildChatDisplay();
}

void AiDAChatPanel::setContextFunction(ea_t ea, const QString& func_name)
{
    m_contextEa        = ea;
    m_contextFuncName  = func_name;
    updateContextLabel();
}

void AiDAChatPanel::clearHistory()
{
    m_history.clear();
    m_conversationTags.clear();
    clearThinkingStatus();
    m_history.emplace_back("System", "Conversation cleared.");
    rebuildChatDisplay();
}

void AiDAChatPanel::setHistory(
    const std::vector<std::pair<std::string, std::string>>& history)
{
    m_history = history;
    rebuildChatDisplay();
}

std::vector<std::pair<std::string, std::string>> AiDAChatPanel::getHistory() const
{
    return m_history;
}

void AiDAChatPanel::copyMessageToClipboard(int index)
{
    if (index < 0 || index >= static_cast<int>(m_history.size()))
        return;

    const auto& entry = m_history[index];
    QString text = QString::fromStdString(entry.second);
    QApplication::clipboard()->setText(text);
    showToast(QString(QChar(0x2713)) + QStringLiteral(" Copied to clipboard"));
}

void AiDAChatPanel::showToast(const QString& message)
{
    m_toastLabel->setText(message);
    m_toastLabel->setFixedWidth(qMin(280, width() - 40));
    int x = (width() - m_toastLabel->width()) / 2;
    int y = height() - 90;
    m_toastLabel->move(x, y);
    m_toastLabel->setVisible(true);
    m_toastLabel->raise();
    m_toastTimer->start(1800);
}

void AiDAChatPanel::undoToMessage(int index)
{
    if (index < 0 || index >= static_cast<int>(m_history.size()))
        return;

    int answer = ask_yn(ASKBTN_NO,
        "HIDECANCEL\n"
        "Undo conversation to this message?\n\n"
        "All messages after this point will be removed.\n"
        "This action cannot be undone.");

    if (answer != ASKBTN_YES)
        return;

    m_history.erase(m_history.begin() + index + 1, m_history.end());

    rebuildChatDisplay();
    saveCurrentConversation();
    saveToDisk();
    showToast(QStringLiteral("Conversation rewound"));
}

void AiDAChatPanel::enterEditMode(int index)
{
    if (index < 0 || index >= static_cast<int>(m_history.size()))
        return;
    if (m_history[index].first != "User")
        return;

    m_editingIndex = index;
    m_userScrolledChat = true;
    rebuildChatDisplay();

    if (m_editingField != nullptr)
    {
        m_chatDisplay->ensureWidgetVisible(m_editingField, 50, 50);
        m_editingField->setFocus();
        QTextCursor cursor = m_editingField->textCursor();
        cursor.movePosition(QTextCursor::End);
        m_editingField->setTextCursor(cursor);
    }
}

void AiDAChatPanel::cancelEditMode()
{
    if (m_editingIndex < 0)
        return;
    m_editingIndex = -1;
    m_editingField = nullptr;
    rebuildChatDisplay();
}

void AiDAChatPanel::commitEdit(int index)
{
    if (m_editingField == nullptr || index < 0)
        return;

    QString newText = m_editingField->toPlainText().trimmed();
    if (newText.isEmpty())
    {
        cancelEditMode();
        return;
    }

    m_editingIndex = -1;
    m_editingField = nullptr;

    m_history.erase(m_history.begin() + index, m_history.end());

    m_inputField->setPlainText(newText);
    sendMessage();
}

void AiDAChatPanel::rebuildChatDisplay()
{
    if (m_chatMessagesLayout == nullptr)
        return;

    m_liveThinkingBlock = nullptr;
    m_liveStreamLabel = nullptr;
    m_liveStatusLabel = nullptr;
    m_editingField = nullptr;

    m_chatDisplayViewport->setUpdatesEnabled(false);

    QLayoutItem* item = nullptr;
    while ((item = m_chatMessagesLayout->takeAt(0)) != nullptr)
    {
        if (QWidget* widget = item->widget())
            delete widget;
        delete item;
    }

    const int viewportWidth = m_chatDisplay->viewport()->width() > 0
        ? m_chatDisplay->viewport()->width()
        : qMax(320, width() - 24);
    const int maxBubbleWidth = qMax(260, (viewportWidth * 78) / 100);
    const int userMinBubbleWidth = qMin(maxBubbleWidth, qMax(240, (viewportWidth * 46) / 100));

    auto handleNavUrl = [this](const QUrl& url) {
        if (url.scheme() != QStringLiteral("nav"))
            return;
        QString path = url.path();
        if (path.startsWith(QChar('/')))
            path.remove(0, 1);
        bool ok = false;
        ea_t ea = static_cast<ea_t>(path.toULongLong(&ok, 16));
        if (ok && ea != BADADDR)
            jumpto(ea);
    };

    auto makeActionButton = [this](const QString& tooltip, chat_action_icon_t icon_type, const std::function<void()>& handler, QWidget* parent) {
        QPushButton* btn = new QPushButton(parent);
        btn->setObjectName(QStringLiteral("chatActionBtn"));
        btn->setCursor(Qt::PointingHandCursor);
        btn->setFlat(true);
        btn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        btn->setFixedSize(24, 24);
        btn->setToolTip(tooltip);
        btn->setAccessibleName(tooltip);
        btn->setIcon(make_chat_action_icon(icon_type, m_theme.panelBg.lightnessF() < 0.5));
        btn->setIconSize(QSize(16, 16));
        if (btn->icon().isNull())
            btn->setText(tooltip.left(1));
        QObject::connect(btn, &QPushButton::clicked, this, [handler]() { handler(); });
        return btn;
    };

    auto makeMessageBrowser = [&](const QString& markdown, QWidget* parent, bool no_bubble = false) {
        const int browserWidth = no_bubble ? (maxBubbleWidth - 12) : (maxBubbleWidth - 20);
        const int docWidth = no_bubble ? qMax(180, browserWidth - 12) : qMax(160, browserWidth - 26);

        ChatTextBrowser* browser = new ChatTextBrowser(parent);
        browser->setObjectName(QStringLiteral("chatMessageBrowser"));
        browser->setFrameStyle(QFrame::NoFrame);
        browser->setReadOnly(true);
        browser->setMarkdownSource(markdown);
        browser->setOpenLinks(false);
        browser->setAutoFillBackground(false);
        browser->setAttribute(Qt::WA_NoSystemBackground, true);
        browser->setAttribute(Qt::WA_TranslucentBackground, true);
        browser->setContentsMargins(0, 0, 0, 0);
        browser->setStyleSheet(QStringLiteral(
            "QTextBrowser { background: transparent; border: none; padding: 0px; margin: 0px; }"
            "QTextBrowser::viewport { background: transparent; border: none; }"));
        browser->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        browser->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        browser->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContents);
        browser->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        browser->setFixedWidth(browserWidth);
        browser->setMinimumHeight(0);
        browser->document()->setDocumentMargin(0);
        browser->viewport()->setAutoFillBackground(false);
        browser->viewport()->setStyleSheet(QStringLiteral("background: transparent;"));
        QPalette browserPalette = browser->palette();
        browserPalette.setColor(QPalette::Base, Qt::transparent);
        browserPalette.setColor(QPalette::Window, Qt::transparent);
        browserPalette.setColor(QPalette::Text, m_theme.bubbleAiText);
        browserPalette.setColor(QPalette::WindowText, m_theme.bubbleAiText);
        browser->setPalette(browserPalette);
        QPalette viewportPalette = browser->viewport()->palette();
        viewportPalette.setColor(QPalette::Base, Qt::transparent);
        viewportPalette.setColor(QPalette::Window, Qt::transparent);
        browser->viewport()->setPalette(viewportPalette);
        browser->onAnchorClicked = [handleNavUrl](const QUrl& url) { handleNavUrl(url); };
        browser->onAnchorDoubleClicked = [handleNavUrl](const QUrl& url) { handleNavUrl(url); };

        const QString contentHtml = markdownToHtml(markdown);

        QString html;
        html.reserve(markdown.size() * 2 + 256);
        html += QStringLiteral("<!DOCTYPE html><html><head><style>");
        html += buildDocumentCss();
        html += QStringLiteral("</style></head><body><div class='assistant-content'>");
        html += contentHtml;
        html += QStringLiteral("</div></body></html>");
        browser->setHtml(html);
        browser->document()->setTextWidth(docWidth);
        browser->document()->adjustSize();

        auto updateBrowserHeight = [browser]() {
            qreal docHeight = browser->document()->size().height();
            if (browser->document()->documentLayout() != nullptr)
                docHeight = browser->document()->documentLayout()->documentSize().height();
            const int measuredHeight = qMax(18, qCeil(docHeight) + 2);
            browser->setFixedHeight(measuredHeight);
        };
        updateBrowserHeight();

        if (QAbstractTextDocumentLayout* layout = browser->document()->documentLayout())
        {
            QObject::connect(layout, &QAbstractTextDocumentLayout::documentSizeChanged,
                browser, [browser](const QSizeF& size) {
                    browser->setFixedHeight(qMax(18, qCeil(size.height()) + 2));
                });
        }

        return browser;
    };

    auto makePlainLabel = [&](const QString& text, QWidget* parent) {
        QLabel* label = new QLabel(text, parent);
        label->setObjectName(QStringLiteral("chatTextLabel"));
        label->setWordWrap(true);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label->setMaximumWidth(maxBubbleWidth - 24);
        return label;
    };

    auto addMessageRow = [&](const QString& role, const QString& msg, int index) {
        QWidget* row = new QWidget(m_chatDisplayViewport);
        row->setObjectName(QStringLiteral("chatMessageRow"));
        row->setAttribute(Qt::WA_StyledBackground, false);
        row->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
        QHBoxLayout* rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(0, 0, 0, 0);
        rowLayout->setSpacing(8);

        if (role == QStringLiteral("ThinkingHeader") || role == QStringLiteral("Thinking"))
        {
            QWidget* thinkingContent = new QWidget(row);
            thinkingContent->setObjectName(QStringLiteral("chatThinkingContent"));
            thinkingContent->setAttribute(Qt::WA_StyledBackground, false);
            thinkingContent->setAutoFillBackground(false);
            thinkingContent->setMaximumWidth(maxBubbleWidth);
            thinkingContent->setFixedWidth(maxBubbleWidth);
            thinkingContent->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Maximum);

            QVBoxLayout* thinkingLayout = new QVBoxLayout(thinkingContent);
            thinkingLayout->setContentsMargins(0, 0, 0, 0);
            thinkingLayout->setSpacing(1);

            if (role == QStringLiteral("ThinkingHeader"))
            {
                bool expanded = false;
                for (const ThinkingRound& entry : m_thinkingRounds)
                {
                    if (entry.round == index)
                    {
                        expanded = entry.expanded;
                        break;
                    }
                }

                QPushButton* headerBtn = new QPushButton(thinkingContent);
                headerBtn->setObjectName(QStringLiteral("chatThinkingHeaderBtn"));
                headerBtn->setFlat(true);
                headerBtn->setAutoDefault(false);
                headerBtn->setDefault(false);
                headerBtn->setCursor(Qt::PointingHandCursor);
                headerBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
                headerBtn->setText((expanded ? QStringLiteral("v ") : QStringLiteral("> ")) + msg);
                headerBtn->setToolTip(QStringLiteral("Toggle round thinking details"));
                headerBtn->setMinimumHeight(14);
                headerBtn->setMaximumHeight(16);
                QObject::connect(headerBtn, &QPushButton::clicked, this, [this, index]() {
                    for (ThinkingRound& entry : m_thinkingRounds)
                    {
                        if (entry.round == index)
                        {
                            entry.expanded = !entry.expanded;
                            break;
                        }
                    }
                    rebuildChatDisplay();
                });
                thinkingLayout->addWidget(headerBtn);
            }
            else
            {
                QLabel* thinkingLabel = new QLabel(msg, thinkingContent);
                thinkingLabel->setObjectName(QStringLiteral("chatThinkingLabel"));
                thinkingLabel->setTextFormat(Qt::PlainText);
                thinkingLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
                thinkingLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
                thinkingLabel->setWordWrap(true);
                thinkingLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
                thinkingLabel->setMaximumWidth(maxBubbleWidth - 12);
                thinkingLayout->addWidget(thinkingLabel);
            }

            rowLayout->addWidget(thinkingContent, 0, Qt::AlignLeft);
            rowLayout->addStretch();
            m_chatMessagesLayout->addWidget(row);
            return;
        }

        if (role == QStringLiteral("AiDA"))
        {
            QWidget* aiContent = new QWidget(row);
            aiContent->setObjectName(QStringLiteral("chatAiContent"));
            aiContent->setAttribute(Qt::WA_StyledBackground, false);
            aiContent->setAttribute(Qt::WA_NoSystemBackground, true);
            aiContent->setAttribute(Qt::WA_TranslucentBackground, true);
            aiContent->setAutoFillBackground(false);
            aiContent->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
            aiContent->setMaximumWidth(maxBubbleWidth);

            QVBoxLayout* aiLayout = new QVBoxLayout(aiContent);
            aiLayout->setContentsMargins(10, 8, 10, 6);
            aiLayout->setSpacing(4);
            aiLayout->addWidget(makeMessageBrowser(msg, aiContent, true));

            QWidget* aiFooter = new QWidget(aiContent);
            aiFooter->setObjectName(QStringLiteral("chatAiFooter"));
            aiFooter->setAttribute(Qt::WA_StyledBackground, false);
            aiFooter->setAttribute(Qt::WA_NoSystemBackground, true);
            aiFooter->setAutoFillBackground(false);
            aiFooter->setStyleSheet(QStringLiteral("background: transparent; border: none;"));

            QHBoxLayout* footerLayout = new QHBoxLayout(aiFooter);
            footerLayout->setContentsMargins(0, 2, 0, 0);
            footerLayout->setSpacing(4);
            footerLayout->addStretch();
            footerLayout->addWidget(makeActionButton(QStringLiteral("Copy"), chat_action_icon_t::copy, [this, index]() {
                copyMessageToClipboard(index);
            }, aiContent));
            aiLayout->addWidget(aiFooter);

            rowLayout->addWidget(aiContent, 0, Qt::AlignLeft);
            rowLayout->addStretch();
            m_chatMessagesLayout->addWidget(row);
            return;
        }

        QFrame* bubble = new QFrame(row);
        bubble->setObjectName(role == QStringLiteral("User")
            ? QStringLiteral("userBubble")
            : QStringLiteral("systemBubble"));
        bubble->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);
        bubble->setMaximumWidth(maxBubbleWidth);
        if (role == QStringLiteral("User"))
            bubble->setMinimumWidth(userMinBubbleWidth);

        QVBoxLayout* bubbleLayout = new QVBoxLayout(bubble);
        bubbleLayout->setContentsMargins(14, 3, 14, 3);
        bubbleLayout->setSpacing(2);

        if (role == QStringLiteral("User") && m_editingIndex == index)
        {
            m_editingField = new QTextEdit(bubble);
            m_editingField->setObjectName(QStringLiteral("chatEditField"));
            m_editingField->setPlainText(msg);
            m_editingField->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);
            m_editingField->setMaximumWidth(maxBubbleWidth - 28);
            m_editingField->setMinimumHeight(36);
            m_editingField->setMaximumHeight(200);
            m_editingField->installEventFilter(this);
            bubbleLayout->addWidget(m_editingField);

            QHBoxLayout* editFooter = new QHBoxLayout();
            editFooter->setContentsMargins(0, 4, 0, 0);
            editFooter->setSpacing(4);
            editFooter->addStretch();
            editFooter->addWidget(makeActionButton(QStringLiteral("Send"), chat_action_icon_t::send, [this, index]() {
                commitEdit(index);
            }, bubble));
            bubbleLayout->addLayout(editFooter);
        }
        else
        {
            QLabel* label = makePlainLabel(msg, bubble);
            if (role == QStringLiteral("User"))
                label->setTextInteractionFlags(Qt::NoTextInteraction);
            bubbleLayout->addWidget(label);

            if (role == QStringLiteral("User"))
            {
                QHBoxLayout* footerLayout = new QHBoxLayout();
                footerLayout->setContentsMargins(0, 2, 0, 0);
                footerLayout->setSpacing(4);
                footerLayout->addStretch();
                footerLayout->addWidget(makeActionButton(QStringLiteral("Copy"), chat_action_icon_t::copy, [this, index]() {
                    copyMessageToClipboard(index);
                }, bubble));
                bubbleLayout->addLayout(footerLayout);

                bubble->setCursor(Qt::PointingHandCursor);
                bubble->setProperty("historyIndex", index);
                bubble->installEventFilter(this);
            }
        }

        if (role == QStringLiteral("User"))
        {
            rowLayout->addStretch();
            rowLayout->addWidget(bubble, 0, Qt::AlignRight);
        }
        else
        {
            rowLayout->addStretch();
            rowLayout->addWidget(bubble, 0, Qt::AlignHCenter);
            rowLayout->addStretch();
        }

        m_chatMessagesLayout->addWidget(row);
    };

    if (m_history.empty())
    {
        QWidget* intro = new QWidget(m_chatDisplayViewport);
        intro->setObjectName(QStringLiteral("chatMessageIntro"));
        intro->setAttribute(Qt::WA_StyledBackground, false);
        QVBoxLayout* introLayout = new QVBoxLayout(intro);
        introLayout->setContentsMargins(24, 24, 24, 24);
        introLayout->setSpacing(8);

        QLabel* title = new QLabel(QStringLiteral("Welcome to AiDA"), intro);
        title->setObjectName(QStringLiteral("chatSenderLabel"));
        title->setAlignment(Qt::AlignCenter);
        QFont titleFont = title->font();
        titleFont.setPointSize(11);
        titleFont.setBold(true);
        title->setFont(titleFont);
        introLayout->addWidget(title);

        QLabel* desc = new QLabel(
            QStringLiteral("Ask about the current function or address. Use @function_name or @0xADDRESS to include context."),
            intro);
        desc->setObjectName(QStringLiteral("chatTextLabel"));
        desc->setWordWrap(true);
        desc->setAlignment(Qt::AlignCenter);
        introLayout->addWidget(desc);

        m_chatMessagesLayout->addWidget(intro);
    }
    else
    {
        auto addThinkingEntry = [&](QVBoxLayout* targetLayout, const QString& role, const QString& msg, int index) {
            QWidget* parent = targetLayout->parentWidget();
            if (role == QStringLiteral("ThinkingHeader"))
            {
                bool expanded = false;
                for (const ThinkingRound& entry : m_thinkingRounds)
                {
                    if (entry.round == index)
                    {
                        expanded = entry.expanded;
                        break;
                    }
                }
                QPushButton* headerBtn = new QPushButton(parent);
                headerBtn->setObjectName(QStringLiteral("chatThinkingHeaderBtn"));
                headerBtn->setFlat(true);
                headerBtn->setAutoDefault(false);
                headerBtn->setDefault(false);
                headerBtn->setCursor(Qt::PointingHandCursor);
                headerBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
                headerBtn->setText((expanded ? QStringLiteral("v ") : QStringLiteral("> ")) + msg);
                headerBtn->setToolTip(QStringLiteral("Toggle round thinking details"));
                headerBtn->setMinimumHeight(14);
                headerBtn->setMaximumHeight(18);
                QObject::connect(headerBtn, &QPushButton::clicked, this, [this, index]() {
                    for (ThinkingRound& entry : m_thinkingRounds)
                    {
                        if (entry.round == index)
                        {
                            entry.expanded = !entry.expanded;
                            break;
                        }
                    }
                    rebuildChatDisplay();
                });
                targetLayout->addWidget(headerBtn);
            }
            else
            {
                QLabel* thinkingLabel = new QLabel(msg, parent);
                thinkingLabel->setObjectName(QStringLiteral("chatThinkingLabel"));
                thinkingLabel->setTextFormat(Qt::PlainText);
                thinkingLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
                thinkingLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
                thinkingLabel->setWordWrap(true);
                thinkingLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
                thinkingLabel->setMaximumWidth(maxBubbleWidth - 12);
                targetLayout->addWidget(thinkingLabel);
            }
        };

        auto createThinkingBlock = [&]() -> std::pair<QWidget*, QVBoxLayout*> {
            QWidget* block = new QWidget(m_chatDisplayViewport);
            block->setObjectName(QStringLiteral("chatThinkingContent"));
            block->setAttribute(Qt::WA_StyledBackground, false);
            block->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Maximum);
            block->setFixedWidth(maxBubbleWidth);
            QVBoxLayout* layout = new QVBoxLayout(block);
            layout->setContentsMargins(0, 0, 0, 0);
            layout->setSpacing(1);
            return {block, layout};
        };

        {
            int i = 0;
            while (i < static_cast<int>(m_history.size()))
            {
                if (m_history[i].first == "ThinkingHeader" || m_history[i].first == "Thinking")
                {
                    auto [block, blockLayout] = createThinkingBlock();
                    while (i < static_cast<int>(m_history.size())
                           && (m_history[i].first == "ThinkingHeader" || m_history[i].first == "Thinking"))
                    {
                        addThinkingEntry(blockLayout,
                            QString::fromStdString(m_history[i].first),
                            QString::fromStdString(m_history[i].second), i);
                        ++i;
                    }
                    m_chatMessagesLayout->addWidget(block, 0, Qt::AlignLeft);
                }
                else
                {
                    addMessageRow(QString::fromStdString(m_history[i].first),
                                  QString::fromStdString(m_history[i].second), i);
                    ++i;
                }
            }
        }

        if (m_isWaiting)
        {
            auto [block, blockLayout] = createThinkingBlock();
            bool hasContent = false;

            for (const ThinkingRound& round : m_thinkingRounds)
            {
                QString header = round.header.trimmed();
                if (header.isEmpty())
                    header = QStringLiteral("Planning (Round %1)").arg(round.round > 0 ? round.round : 1);

                addThinkingEntry(blockLayout, QStringLiteral("ThinkingHeader"), header, round.round);
                hasContent = true;

                if (round.expanded)
                {
                    const QString details = round.details.trimmed();
                    if (!details.isEmpty())
                        addThinkingEntry(blockLayout, QStringLiteral("Thinking"), details, round.round);
                }
            }

            m_liveStreamLabel = new QLabel(block);
            m_liveStreamLabel->setObjectName(QStringLiteral("chatThinkingLabel"));
            m_liveStreamLabel->setTextFormat(Qt::PlainText);
            m_liveStreamLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
            m_liveStreamLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
            m_liveStreamLabel->setWordWrap(true);
            m_liveStreamLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            m_liveStreamLabel->setMaximumWidth(maxBubbleWidth - 12);
            const QString preview = buildLiveThinkingPreview();
            if (!preview.isEmpty())
                m_liveStreamLabel->setText(preview);
            blockLayout->addWidget(m_liveStreamLabel);

            m_liveStatusLabel = new QLabel(block);
            m_liveStatusLabel->setObjectName(QStringLiteral("chatLiveStatusLabel"));
            m_liveStatusLabel->setTextFormat(Qt::PlainText);
            m_liveStatusLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
            m_liveStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
            m_liveStatusLabel->setMinimumHeight(16);
            updateLiveStatusLabel();
            blockLayout->addWidget(m_liveStatusLabel);

            m_liveThinkingBlock = block;
            m_chatMessagesLayout->addWidget(block, 0, Qt::AlignLeft);
        }
    }

    m_chatMessagesLayout->addStretch();
    m_chatDisplayViewport->setUpdatesEnabled(true);
    scrollToBottom();
}

void AiDAChatPanel::scrollToBottom()
{
    if (m_userScrolledChat)
        return;
    QScrollBar* sb = m_chatDisplay->verticalScrollBar();
    sb->setValue(sb->maximum());
}

QString AiDAChatPanel::buildConversationMarkdown() const
{
    QString markdown;
    markdown.reserve(8192);

    if (m_history.empty())
    {
        markdown += QStringLiteral("# Welcome to AiDA\n\n");
        markdown += QStringLiteral("AiDA uses an IDAssist-style markdown conversation view.\n\n");
        markdown += QStringLiteral("## Getting Started\n\n");
        markdown += QStringLiteral("- Ask about the current function or address.\n");
        markdown += QStringLiteral("- Use `@function_name` or `@0xADDRESS` to include code context.\n");
        markdown += QStringLiteral("- Press `Ctrl+Enter` to send.\n\n");
        markdown += QStringLiteral("Type `/help` for commands.\n");
        return markdown;
    }

    for (int i = 0; i < static_cast<int>(m_history.size()); ++i)
    {
        markdown += formatMessageMarkdown(
            QString::fromStdString(m_history[i].first),
            QString::fromStdString(m_history[i].second),
            i);
    }

    return markdown;
}

QString AiDAChatPanel::formatMessageMarkdown(const QString& role, const QString& msg, int index) const
{
    QString markdown;

    if (role == QStringLiteral("User"))
    {
        markdown += QStringLiteral("## You\n\n");
        markdown += msg;
        markdown += QStringLiteral("\n\n[Copy](copy:%1)\n\n").arg(index);
        return markdown;
    }

    if (role == QStringLiteral("AiDA"))
    {
        markdown += QStringLiteral("## AiDA\n\n");
        markdown += msg;
        markdown += QStringLiteral("\n\n[Copy](copy:%1)\n\n").arg(index);
        return markdown;
    }

    if (role == QStringLiteral("Thinking"))
    {
        markdown += QStringLiteral("### Thinking\n\n");
        markdown += msg;
        markdown += QStringLiteral("\n\n");
        return markdown;
    }

    if (role == QStringLiteral("ThinkingHeader"))
    {
        markdown += QStringLiteral("*%1*\n\n").arg(msg);
        return markdown;
    }

    if (msg.startsWith(QStringLiteral("Error:"), Qt::CaseInsensitive))
        markdown += QStringLiteral("## Error\n\n");
    else
        markdown += QStringLiteral("## System\n\n");

    markdown += msg;
    markdown += QStringLiteral("\n\n");
    return markdown;
}

static QString linkifyCodeContent(const QString& codeContent);

QString AiDAChatPanel::markdownToHtml(const QString& md) const
{
    const bool darkTheme = m_theme.panelBg.lightnessF() < 0.5;
    const QString mdAccent = darkTheme ? QStringLiteral("#FFFFFF") : colorToHex(m_theme.accentColor);
    const QString mdSecondary = darkTheme ? QStringLiteral("rgba(255,255,255,0.92)") : colorToHex(m_theme.textSecondary);
    const QString mdLink = darkTheme ? QStringLiteral("#FFFFFF") : colorToHex(m_theme.linkColor);

    QString normalizedMd = md;
    normalizedMd.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
    normalizedMd.replace(QRegularExpression(QStringLiteral("\n{3,}")), QStringLiteral("\n\n"));

    QString result;
    result.reserve(normalizedMd.size() * 2);

    QStringList lines = normalizedMd.split(QChar('\n'));
    bool inCodeBlock = false;
    QString codeAccum;
    bool lastLineWasBlank = false;
    QStringList tableRows;

    auto flushTable = [&]() {
        if (tableRows.isEmpty()) return;
        int startRow = 0;
        bool hasSeparator = (tableRows.size() >= 2 &&
            QRegularExpression(QStringLiteral("^\\|?[\\s:]*-+[\\s:]*")).match(tableRows[1]).hasMatch());
        result += QStringLiteral("<table class='md-table'>");
        if (hasSeparator && tableRows.size() >= 1) {
            QStringList hdrCells = tableRows[0].split(QChar('|'), Qt::SkipEmptyParts);
            result += QStringLiteral("<tr>");
            for (const QString& cell : hdrCells)
                result += QStringLiteral("<th>") + escapeHtml(cell.trimmed()) + QStringLiteral("</th>");
            result += QStringLiteral("</tr>");
            startRow = 2;
        }
        for (int r = startRow; r < tableRows.size(); ++r) {
            QStringList cells = tableRows[r].split(QChar('|'), Qt::SkipEmptyParts);
            result += QStringLiteral("<tr>");
            for (const QString& cell : cells)
                result += QStringLiteral("<td>") + escapeHtml(cell.trimmed()) + QStringLiteral("</td>");
            result += QStringLiteral("</tr>");
        }
        result += QStringLiteral("</table>\n");
        tableRows.clear();
    };

    for (int i = 0; i < lines.size(); ++i)
    {
        const QString& line = lines[i];
        QString trimmed = line.trimmed();

        if (trimmed.startsWith(QStringLiteral("```")))
        {
            flushTable();
            if (inCodeBlock)
            {
                result += QStringLiteral("<pre>")
                       +  escapeHtml(codeAccum)
                       +  QStringLiteral("</pre>");
                codeAccum.clear();
                inCodeBlock = false;
                lastLineWasBlank = false;
            }
            else
            {
                inCodeBlock = true;
            }
            continue;
        }

        if (inCodeBlock)
        {
            if (!codeAccum.isEmpty())
                codeAccum += QChar('\n');
            codeAccum += line;
            continue;
        }

        if (trimmed.startsWith(QChar('|')) && trimmed.endsWith(QChar('|')))
        {
            tableRows.append(trimmed);
            lastLineWasBlank = false;
            continue;
        }
        flushTable();

        if (trimmed.isEmpty())
        {
            lastLineWasBlank = true;
            continue;
        }
        lastLineWasBlank = false;

        if (QRegularExpression(QStringLiteral("^-{3,}$|^\\*{3,}$|^_{3,}$")).match(trimmed).hasMatch())
        {
            result += QStringLiteral("<hr style='border:none;border-top:1px solid;opacity:0.20;margin:8px 0;'>\n");
            continue;
        }

        int headingLevel = 0;
        QString lineContent = trimmed;
        if (trimmed.startsWith(QStringLiteral("### ")))
        {
            headingLevel = 3;
            lineContent = trimmed.mid(4);
        }
        else if (trimmed.startsWith(QStringLiteral("## ")))
        {
            headingLevel = 2;
            lineContent = trimmed.mid(3);
        }
        else if (trimmed.startsWith(QStringLiteral("# ")))
        {
            headingLevel = 1;
            lineContent = trimmed.mid(2);
        }

        bool isBlockquote = false;
        if (headingLevel == 0 && trimmed.startsWith(QStringLiteral("> ")))
        {
            isBlockquote = true;
            lineContent = trimmed.mid(2);
        }
        else if (headingLevel == 0 && trimmed == QStringLiteral(">"))
        {
            isBlockquote = true;
            lineContent.clear();
        }

        bool isBulletItem = false;
        bool isNumberedItem = false;
        QString listNumber;
        if (headingLevel == 0 && !isBlockquote)
        {
            if (lineContent.startsWith(QStringLiteral("- ")) || lineContent.startsWith(QStringLiteral("* ")))
            {
                isBulletItem = true;
                lineContent = lineContent.mid(2);
            }
            else
            {
                QRegularExpression numListRe(QStringLiteral("^(\\d+)\\.\\s(.*)$"));
                auto numMatch = numListRe.match(lineContent);
                if (numMatch.hasMatch())
                {
                    isNumberedItem = true;
                    listNumber = numMatch.captured(1);
                    lineContent = numMatch.captured(2);
                }
            }
        }

        QString processed = escapeHtml(lineContent);

        struct InlineCodeSlot
        {
            QString marker;
            QString html;
        };
        std::vector<InlineCodeSlot> codeSlots;
        {
            QRegularExpression inlineCodeRe(QStringLiteral("`([^`]+)`"));
            QString out;
            qsizetype lastEnd = 0;
            int slotIdx = 0;
            auto matchIt = inlineCodeRe.globalMatch(processed);
            while (matchIt.hasNext())
            {
                auto match = matchIt.next();
                out += processed.mid(lastEnd, match.capturedStart() - lastEnd);
                QString codeContent = match.captured(1);
                QString marker = QStringLiteral("\x01IC%1\x01").arg(slotIdx++);
                codeSlots.push_back({marker, linkifyCodeContent(codeContent)});
                out += marker;
                lastEnd = static_cast<qsizetype>(match.capturedEnd());
            }
            out += processed.mid(lastEnd);
            processed = out;
        }

        processed.replace(
            QRegularExpression(QStringLiteral("\\*\\*\\*([^*]+)\\*\\*\\*")),
            QStringLiteral("<b><i>\\1</i></b>"));

        processed.replace(
            QRegularExpression(QStringLiteral("\\*\\*([^*]+)\\*\\*")),
            QStringLiteral("<b>\\1</b>"));

        processed.replace(
            QRegularExpression(QStringLiteral("~~([^~]+)~~")),
            QStringLiteral("<s>\\1</s>"));

        processed.replace(
            QRegularExpression(QStringLiteral("(?<!\\*)\\*([^*]+)\\*(?!\\*)")),
            QStringLiteral("<i>\\1</i>"));


        {
            QRegularExpression mdLinkRe(QStringLiteral("\\[([^\\]]+)\\]\\(([^\\)]+)\\)"));
            QString linkOut;
            qsizetype linkLast = 0;
            bool hasLinks = false;
            auto linkIt = mdLinkRe.globalMatch(processed);
            while (linkIt.hasNext())
            {
                hasLinks = true;
                auto lm = linkIt.next();
                linkOut += processed.mid(linkLast, lm.capturedStart() - linkLast);
                QString linkText = lm.captured(1);
                QString linkUrl = lm.captured(2);
                if (linkUrl.startsWith(QStringLiteral("nav:")))
                {
                    linkOut += QStringLiteral("<a href='%1' class='nav-link'>%2</a>")
                        .arg(linkUrl, linkText);
                }
                else
                {
                    linkOut += QStringLiteral("<a href='%1' style='color:%2;text-decoration:underline;'>%3</a>")
                        .arg(linkUrl, mdLink, linkText);
                }
                linkLast = static_cast<qsizetype>(lm.capturedEnd());
            }
            if (hasLinks)
            {
                linkOut += processed.mid(linkLast);
                processed = linkOut;
            }
        }

        for (const auto& slot : codeSlots)
            processed.replace(slot.marker, slot.html);

        {
            QRegularExpression bareHexRe(QStringLiteral("(?<!href=')(?<!>)(0x[0-9a-fA-F]{4,})(?!</a>)"));
            QString newProcessed;
            qsizetype lastEnd = 0;
            auto matchIt = bareHexRe.globalMatch(processed);
            while (matchIt.hasNext())
            {
                auto match = matchIt.next();
                QString before = processed.left(match.capturedStart());
                qsizetype lastOpenA = before.lastIndexOf(QStringLiteral("<a "));
                qsizetype lastCloseA = before.lastIndexOf(QStringLiteral("</a>"));
                qsizetype lastOpenCode = before.lastIndexOf(QStringLiteral("<code>"));
                qsizetype lastCloseCode = before.lastIndexOf(QStringLiteral("</code>"));
                qsizetype lastNavLink = before.lastIndexOf(QStringLiteral("nav-link"));

                bool insideAnchor = lastOpenA > lastCloseA;
                bool insideCode = lastOpenCode > lastCloseCode;
                bool alreadyLinked = lastNavLink > lastCloseA && lastNavLink > -1;

                if (insideAnchor || insideCode || alreadyLinked)
                {
                    newProcessed += processed.mid(lastEnd, match.capturedEnd() - lastEnd);
                    lastEnd = static_cast<qsizetype>(match.capturedEnd());
                    continue;
                }

                newProcessed += processed.mid(lastEnd, match.capturedStart() - lastEnd);
                QString addr = match.captured(1);
                QString hexOnly = addr.mid(2);
                newProcessed += QStringLiteral("<a href='nav:%1' class='nav-link'>%2</a>")
                    .arg(hexOnly).arg(addr);
                lastEnd = static_cast<qsizetype>(match.capturedEnd());
            }
            newProcessed += processed.mid(lastEnd);
            processed = newProcessed;
        }

        {
            QRegularExpression bareSubLocRe(QStringLiteral("(?<!href=')(?<!>)\\b((?:sub|loc|SUB|LOC|Sub|Loc)_[0-9a-fA-F]{4,})\\b(?!</a>)"));
            QString newProcessed;
            qsizetype lastEnd = 0;
            auto matchIt = bareSubLocRe.globalMatch(processed);
            while (matchIt.hasNext())
            {
                auto match = matchIt.next();
                QString before = processed.left(match.capturedStart());
                qsizetype lastOpenA = before.lastIndexOf(QStringLiteral("<a "));
                qsizetype lastCloseA = before.lastIndexOf(QStringLiteral("</a>"));
                qsizetype lastOpenCode = before.lastIndexOf(QStringLiteral("<code>"));
                qsizetype lastCloseCode = before.lastIndexOf(QStringLiteral("</code>"));
                qsizetype lastNavLink = before.lastIndexOf(QStringLiteral("nav-link"));

                bool insideAnchor = lastOpenA > lastCloseA;
                bool insideCode = lastOpenCode > lastCloseCode;
                bool alreadyLinked = lastNavLink > lastCloseA && lastNavLink > -1;

                if (insideAnchor || insideCode || alreadyLinked)
                {
                    newProcessed += processed.mid(lastEnd, match.capturedEnd() - lastEnd);
                    lastEnd = static_cast<qsizetype>(match.capturedEnd());
                    continue;
                }

                newProcessed += processed.mid(lastEnd, match.capturedStart() - lastEnd);
                QString name = match.captured(1);
                qsizetype underscorePos = name.indexOf(QChar('_'));
                if (underscorePos >= 0)
                {
                    QString hexPart = name.mid(underscorePos + 1);
                    newProcessed += QStringLiteral("<a href='nav:%1' class='nav-link'>%2</a>")
                        .arg(hexPart).arg(name);
                }
                else
                {
                    newProcessed += name;
                }
                lastEnd = static_cast<qsizetype>(match.capturedEnd());
            }
            newProcessed += processed.mid(lastEnd);
            processed = newProcessed;
        }

        processed.replace(
            QRegularExpression(QStringLiteral("@(\\w+)")),
            QStringLiteral("<span class='tag-ref'>@\\1</span>"));

        if (headingLevel > 0)
        {
            QString hClass = QStringLiteral("md-h%1").arg(headingLevel);
            result += QStringLiteral("<span class='md-heading %1'>%2</span>\n")
                .arg(hClass, processed);
        }
        else if (isBlockquote)
        {
            result += QStringLiteral(
                "<div style='border-left:3px solid %1;padding:2px 0 2px 12px;"
                "margin:4px 0;color:%2;'>%3</div>\n")
                .arg(mdAccent,
                     mdSecondary,
                     processed);
        }
        else if (isBulletItem)
        {
            result += QStringLiteral(
                "<div style='padding-left:18px;text-indent:-14px;margin:2px 0;'>"
                "<span style='color:%1;'>\u2022</span>&nbsp;%2</div>\n")
                .arg(mdAccent, processed);
        }
        else if (isNumberedItem)
        {
            result += QStringLiteral(
                "<div style='padding-left:18px;text-indent:-14px;margin:2px 0;'>"
                "<span style='color:%1;font-weight:600;'>%2.</span>&nbsp;%3</div>\n")
                .arg(mdAccent, listNumber, processed);
        }
        else
        {
            result += QStringLiteral("<div style='margin:0;padding:0;'>%1</div>\n").arg(processed);
        }
    }

    if (inCodeBlock && !codeAccum.isEmpty())
    {
        result += QStringLiteral("<pre>")
               +  escapeHtml(codeAccum)
               +  QStringLiteral("</pre>");
    }

    flushTable();

    return result;
}

QString AiDAChatPanel::escapeHtml(const QString& text) const
{
    QString r = text;
    r.replace(QChar('&'),  QStringLiteral("&amp;"));
    r.replace(QChar('<'),  QStringLiteral("&lt;"));
    r.replace(QChar('>'),  QStringLiteral("&gt;"));
    r.replace(QChar('"'),  QStringLiteral("&quot;"));
    return r;
}

static QString linkifyCodeContent(const QString& codeContent)
{
    QString content = codeContent;

    QRegularExpression hexAddrRe(QStringLiteral("^(0x[0-9a-fA-F]+)$"));
    QRegularExpressionMatch hexMatch = hexAddrRe.match(content);
    if (hexMatch.hasMatch())
    {
        QString addr = hexMatch.captured(1);
        QString hexOnly = addr.mid(2);
        return QStringLiteral("<a href='nav:%1' class='nav-link'>%2</a>")
            .arg(hexOnly)
            .arg(addr);
    }

    QRegularExpression subLocRe(QStringLiteral("^((?:sub|loc|SUB|LOC|Sub|Loc)_[0-9a-fA-F]+)$"));
    QRegularExpressionMatch subLocMatch = subLocRe.match(content);
    if (subLocMatch.hasMatch())
    {
        QString name = subLocMatch.captured(1);
        qsizetype underscorePos = name.indexOf(QChar('_'));
        if (underscorePos >= 0)
        {
            QString hexPart = name.mid(underscorePos + 1);
            return QStringLiteral("<a href='nav:%1' class='nav-link'>%2</a>")
                .arg(hexPart)
                .arg(name);
        }
    }

    QRegularExpression identRe(QStringLiteral("^([a-zA-Z_][a-zA-Z0-9_]*)$"));
    QRegularExpressionMatch identMatch = identRe.match(content);
    if (identMatch.hasMatch())
    {
        QString name = identMatch.captured(1);
        QByteArray nameBytes = name.toLatin1();
        ea_t ea = get_name_ea(BADADDR, nameBytes.constData());
        if (ea != BADADDR)
        {
            QString hexAddr = QString::number(static_cast<quint64>(ea), 16).toUpper();
            return QStringLiteral("<a href='nav:%1' class='nav-link'>%2</a>")
                .arg(hexAddr)
                .arg(name);
        }
    }

    return QStringLiteral("<code>%1</code>").arg(content);
}

std::vector<AiDAChatPanel::TagInfo> AiDAChatPanel::parseTags(
    const QString& message) const
{
    std::vector<TagInfo> tags;

    QRegularExpression tagRe(QStringLiteral("@(\\w+|0x[0-9a-fA-F]+)"));
    auto matchIt = tagRe.globalMatch(message);

    while (matchIt.hasNext())
    {
        auto match = matchIt.next();
        TagInfo tag;
        tag.tag_name = match.captured(1);
        QByteArray nameBytes = tag.tag_name.toLatin1();
        ea_t ea = get_name_ea(BADADDR, nameBytes.constData());

        if (ea == BADADDR)
        {
            QString hexStr = tag.tag_name;
            if (hexStr.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
                hexStr = hexStr.mid(2);
            bool ok = false;
            ea = static_cast<ea_t>(hexStr.toULongLong(&ok, 16));
            if (!ok)
                ea = BADADDR;
        }

        if (ea != BADADDR)
        {
            tag.resolved_ea = ea;
            func_t* pfn = get_func(ea);
            if (pfn != nullptr)
            {
                auto code_pair = ida_utils::get_function_code(ea);
                tag.resolved_code = QString::fromStdString(code_pair.first);
                tag.resolved = true;
            }
        }

        tags.push_back(std::move(tag));
    }

    return tags;
}

QString AiDAChatPanel::buildTagContext(
    const std::vector<TagInfo>& tags) const
{
    if (tags.empty())
        return QString();

    bool anyResolved = false;
    for (const auto& t : tags)
    {
        if (t.resolved)
        {
            anyResolved = true;
            break;
        }
    }
    if (!anyResolved)
        return QString();

    QString ctx;
    for (const auto& tag : tags)
    {
        if (tag.resolved)
        {
            ctx += QStringLiteral("--- @%1 (0x%2) ---\n```cpp\n%3\n```\n\n")
                .arg(tag.tag_name)
                .arg(QString::number(
                    static_cast<quint64>(tag.resolved_ea), 16).toUpper())
                .arg(tag.resolved_code);
        }
    }
    return ctx;
}

void AiDAChatPanel::toggleHistoryPanel()
{
    m_historyVisible = !m_historyVisible;
    if (m_historyVisible)
        rebuildHistoryList();
    m_historyPanel->setVisible(m_historyVisible);
    if (m_historyBtn != nullptr)
        m_historyBtn->setChecked(m_historyVisible);
}

void AiDAChatPanel::saveCurrentConversation()
{
    if (m_history.empty())
        return;

    SavedConversation conv;
    if (!m_history.empty())
    {
        QString firstMsg = QString::fromStdString(m_history.front().second);
        conv.title = firstMsg.left(40);
        if (firstMsg.length() > 40)
            conv.title += QStringLiteral("...");
    }
    conv.timestamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd hh:mm"));
    conv.messages = m_history;

    if (m_activeConversationIndex >= 0
        && m_activeConversationIndex < static_cast<int>(m_savedConversations.size()))
    {
        m_savedConversations[static_cast<size_t>(m_activeConversationIndex)] = std::move(conv);
    }
    else
    {
        m_savedConversations.push_back(std::move(conv));
        m_activeConversationIndex = static_cast<int>(m_savedConversations.size()) - 1;
    }

    if (m_historyVisible)
        rebuildHistoryList();

    saveToDisk();
}

void AiDAChatPanel::startNewConversation()
{
    saveCurrentConversation();
    m_history.clear();
    m_conversationTags.clear();
    clearThinkingStatus();
    m_editingIndex = -1;
    m_editingField = nullptr;
    m_activeConversationIndex = -1;
    rebuildChatDisplay();
    m_inputField->clear();
    m_inputField->setFocus();
}

void AiDAChatPanel::loadConversation(int index)
{
    if (index < 0 || index >= static_cast<int>(m_savedConversations.size()))
        return;

    saveCurrentConversation();
    m_activeConversationIndex = index;
    m_history = m_savedConversations[static_cast<size_t>(index)].messages;
    m_conversationTags.clear();
    m_editingIndex = -1;
    m_editingField = nullptr;
    rebuildChatDisplay();
}

void AiDAChatPanel::deleteConversation(int index)
{
    if (index < 0 || index >= static_cast<int>(m_savedConversations.size()))
        return;

    int answer = ask_yn(ASKBTN_NO,
        "HIDECANCEL\n"
        "Are you sure you want to delete this conversation?\n\n"
        "\"%s\"\n\n"
        "This action cannot be undone.",
        m_savedConversations[static_cast<size_t>(index)].title.toUtf8().constData());

    if (answer != ASKBTN_YES)
        return;

    m_savedConversations.erase(m_savedConversations.begin() + index);

    if (m_activeConversationIndex == index)
    {
        m_activeConversationIndex = -1;
        m_history.clear();
        m_conversationTags.clear();
        rebuildChatDisplay();
    }
    else if (m_activeConversationIndex > index)
    {
        --m_activeConversationIndex;
    }

    rebuildHistoryList();
    saveToDisk();
}

void AiDAChatPanel::rebuildHistoryList()
{
    if (m_historyList == nullptr)
        return;

    m_historyList->clear();

    for (int i = static_cast<int>(m_savedConversations.size()) - 1; i >= 0; --i)
    {
        const auto& conv = m_savedConversations[static_cast<size_t>(i)];
        auto* item = new QListWidgetItem(m_historyList);
        item->setText(conv.title + QStringLiteral("\n") + conv.timestamp);
        item->setData(Qt::UserRole, i);
        if (i == m_activeConversationIndex)
        {
            item->setBackground(m_theme.historyItemSelected);
        }
    }
}

qstring AiDAChatPanel::getHistoryFilePath()
{
    qstring path = get_user_idadir();
    path.append("/aida_chat_history.json");
    return path;
}

void AiDAChatPanel::saveToDisk() const
{
    try
    {
        nlohmann::json root;
        nlohmann::json convArray = nlohmann::json::array();

        for (const auto& conv : m_savedConversations)
        {
            nlohmann::json jconv;
            jconv[OBFSTR_C("title")] = conv.title.toStdString();
            jconv[OBFSTR_C("timestamp")] = conv.timestamp.toStdString();

            nlohmann::json msgs = nlohmann::json::array();
            for (const auto& msg : conv.messages)
            {
                nlohmann::json jmsg;
                jmsg[OBFSTR_C("role")] = msg.first;
                jmsg[OBFSTR_C("content")] = msg.second;
                msgs.push_back(std::move(jmsg));
            }
            jconv[OBFSTR_C("messages")] = std::move(msgs);
            convArray.push_back(std::move(jconv));
        }

        root[OBFSTR_C("conversations")] = std::move(convArray);

        std::string json_str = root.dump(2);
        qstring path = getHistoryFilePath();

        FILE* fp = qfopen(path.c_str(), "wb");
        if (fp == nullptr)
            return;

        file_janitor_t fj(fp);
        qfwrite(fp, json_str.c_str(), json_str.length());
    }
    catch (const std::exception&)
    {
    }
}

void AiDAChatPanel::loadFromDisk()
{
    qstring path = getHistoryFilePath();

    if (!qfileexist(path.c_str()))
        return;

    FILE* fp = qfopen(path.c_str(), "rb");
    if (fp == nullptr)
        return;

    file_janitor_t fj(fp);

    uint64 file_size = qfsize(fp);
    if (file_size == 0)
        return;

    qstring json_data;
    json_data.resize(static_cast<size_t>(file_size));
    if (qfread(fp, json_data.begin(), static_cast<size_t>(file_size)) != static_cast<ssize_t>(file_size))
        return;

    try
    {
        nlohmann::json root = nlohmann::json::parse(json_data.c_str());

        if (!root.contains(OBFSTR_C("conversations")) || !root[OBFSTR_C("conversations")].is_array())
            return;

        m_savedConversations.clear();

        for (const auto& jconv : root[OBFSTR_C("conversations")])
        {
            SavedConversation conv;
            conv.title = QString::fromStdString(jconv.value("title", ""));
            conv.timestamp = QString::fromStdString(jconv.value("timestamp", ""));

            if (jconv.contains(OBFSTR_C("messages")) && jconv[OBFSTR_C("messages")].is_array())
            {
                for (const auto& jmsg : jconv[OBFSTR_C("messages")])
                {
                    std::string role = jmsg.value("role", "");
                    std::string content = jmsg.value("content", "");
                    conv.messages.emplace_back(std::move(role), std::move(content));
                }
            }

            m_savedConversations.push_back(std::move(conv));
        }
    }
    catch (const std::exception&)
    {
    }
}
