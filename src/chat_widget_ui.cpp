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

static QFont createChatUiFont()
{
    QFont font(QStringLiteral("Segoe UI"));
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


FunctionCompleterPopup::FunctionCompleterPopup(QWidget* parent)
    : QFrame(parent, Qt::ToolTip | Qt::FramelessWindowHint)
{
    setFont(createChatUiFont());
    setObjectName(QStringLiteral("functionCompleter"));
    setAttribute(Qt::WA_ShowWithoutActivating, true);
    setFocusPolicy(Qt::NoFocus);
    setFixedSize(340, 260);

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
    , m_inputField(nullptr)
    , m_sendBtn(nullptr)
    , m_cancelBtn(nullptr)
    , m_clearBtn(nullptr)
    , m_tagBtn(nullptr)
    , m_typingWidget(nullptr)
    , m_typingLabel(nullptr)
    , m_typingTimer(nullptr)
    , m_typingDotCount(0)
    , m_typingOpacity(nullptr)
    , m_typingPulse(nullptr)
    , m_thinkingContainer(nullptr)
    , m_thinkingToggleBtn(nullptr)
    , m_thinkingDetails(nullptr)
    , m_streamingDisplay(nullptr)
    , m_currentToolLabel(nullptr)
    , m_thinkingElapsedLabel(nullptr)
    , m_thinkingExpanded(false)
    , m_historyPanel(nullptr)
    , m_historyList(nullptr)
    , m_historyVisible(false)
    , m_toastLabel(nullptr)
    , m_toastTimer(nullptr)
    , m_completer(nullptr)
    , m_completerActive(false)
    , m_thinkingElapsedTimer(nullptr)
    , m_typewriterTimer(nullptr)
    , m_userScrolledStreaming(false)
    , m_userScrolledChat(false)
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
    if (m_typingTimer != nullptr)
        m_typingTimer->stop();
    if (m_typingPulse != nullptr)
        m_typingPulse->stop();
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
    hdrTopRow->setContentsMargins(16, 12, 12, 2);
    hdrTopRow->setSpacing(8);

    m_headerLabel = new QLabel(QString::fromStdString(OBFSTR("AiDA Chat")), m_headerBar);
    m_headerLabel->setObjectName(QStringLiteral("headerLabel"));
    hdrTopRow->addWidget(m_headerLabel);
    hdrTopRow->addStretch();

    m_newChatBtn = new QPushButton(QStringLiteral("New"), m_headerBar);
    m_newChatBtn->setObjectName(QStringLiteral("newChatBtn"));
    m_newChatBtn->setToolTip(QStringLiteral("Start New Conversation"));
    m_newChatBtn->setMinimumWidth(58);
    m_newChatBtn->setFixedHeight(28);
    QObject::connect(m_newChatBtn, &QPushButton::clicked, [this]() {
        startNewConversation();
    });
    hdrTopRow->addWidget(m_newChatBtn);

    m_historyBtn = new QPushButton(QStringLiteral("History"), m_headerBar);
    m_historyBtn->setObjectName(QStringLiteral("historyBtn"));
    m_historyBtn->setToolTip(QStringLiteral("Toggle Chat History"));
    m_historyBtn->setCheckable(true);
    m_historyBtn->setChecked(false);
    m_historyBtn->setMinimumWidth(78);
    m_historyBtn->setFixedHeight(28);
    QObject::connect(m_historyBtn, &QPushButton::clicked, [this]() {
        toggleHistoryPanel();
    });
    hdrTopRow->addWidget(m_historyBtn);

    hdrOuterLayout->addLayout(hdrTopRow);

    QHBoxLayout* hdrContextRow = new QHBoxLayout();
    hdrContextRow->setContentsMargins(16, 4, 12, 10);

    m_contextLabel = new QLabel(m_headerBar);
    m_contextLabel->setObjectName(QStringLiteral("contextLabel"));
    updateContextLabel();
    hdrContextRow->addWidget(m_contextLabel);
    hdrContextRow->addStretch();

    hdrOuterLayout->addLayout(hdrContextRow);

    mainLayout->addWidget(m_headerBar);

    QWidget* bodyContainer = new QWidget(this);
    QHBoxLayout* bodyLayout = new QHBoxLayout(bodyContainer);
    bodyLayout->setContentsMargins(14, 4, 14, 6);
    bodyLayout->setSpacing(10);

    m_historyPanel = new QWidget(bodyContainer);
    m_historyPanel->setObjectName(QStringLiteral("historyPanel"));
    m_historyPanel->setFixedWidth(240);
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
    chatAreaLayout->setContentsMargins(6, 6, 6, 6);
    chatAreaLayout->setSpacing(6);

    m_chatDisplay = new ChatTextBrowser(chatArea);
    m_chatDisplay->setObjectName(QStringLiteral("chatDisplay"));
    m_chatDisplay->setReadOnly(true);

    m_chatDisplay->onAnchorClicked = [this](const QUrl& url) {
        QString scheme = url.scheme();
        if (scheme == QStringLiteral("copy"))
        {
            QString path = url.path();
            if (path.startsWith(QChar('/')))
                path.remove(0, 1);
            bool ok = false;
            int idx = path.toInt(&ok);
            if (ok)
                copyMessageToClipboard(idx);
        }
        else if (scheme == QStringLiteral("undo"))
        {
            QString path = url.path();
            if (path.startsWith(QChar('/')))
                path.remove(0, 1);
            bool ok = false;
            int idx = path.toInt(&ok);
            if (ok)
                undoToMessage(idx);
        }
        else if (scheme == QStringLiteral("nav"))
        {
            QString path = url.path();
            if (path.startsWith(QChar('/')))
                path.remove(0, 1);
            bool ok = false;
            ea_t ea = static_cast<ea_t>(path.toULongLong(&ok, 16));
            if (ok && ea != BADADDR)
                jumpto(ea);
        }
    };

    m_chatDisplay->onAnchorDoubleClicked = [this](const QUrl& url) {
        QString scheme = url.scheme();
        if (scheme == QStringLiteral("nav"))
        {
            QString path = url.path();
            if (path.startsWith(QChar('/')))
                path.remove(0, 1);
            bool ok = false;
            ea_t ea = static_cast<ea_t>(path.toULongLong(&ok, 16));
            if (ok && ea != BADADDR)
                jumpto(ea);
        }
    };

    chatAreaLayout->addWidget(m_chatDisplay, 1);

    QObject::connect(m_chatDisplay->verticalScrollBar(), &QScrollBar::sliderPressed, [this]() {
        m_userScrolledChat = true;
    });
    QObject::connect(m_chatDisplay->verticalScrollBar(), &QScrollBar::valueChanged, [this](int value) {
        QScrollBar* sb = m_chatDisplay->verticalScrollBar();
        if (value >= sb->maximum() - 4)
            m_userScrolledChat = false;
    });
    m_thinkingContainer = new QWidget(chatArea);
    m_thinkingContainer->setObjectName(QStringLiteral("thinkingContainer"));
    m_thinkingContainer->setVisible(false);
    QVBoxLayout* thinkingLayout = new QVBoxLayout(m_thinkingContainer);
    thinkingLayout->setContentsMargins(0, 0, 0, 0);
    thinkingLayout->setSpacing(0);

    QWidget* thinkingHeader = new QWidget(m_thinkingContainer);
    thinkingHeader->setObjectName(QStringLiteral("thinkingHeader"));
    thinkingHeader->setCursor(Qt::PointingHandCursor);
    QHBoxLayout* thinkingHeaderLayout = new QHBoxLayout(thinkingHeader);
    thinkingHeaderLayout->setContentsMargins(12, 8, 12, 8);
    thinkingHeaderLayout->setSpacing(6);

    m_thinkingToggleBtn = new QPushButton(thinkingHeader);
    m_thinkingToggleBtn->setObjectName(QStringLiteral("thinkingToggleBtn"));
    m_thinkingToggleBtn->setText(QString(QChar(0x25B6)));
    m_thinkingToggleBtn->setFixedSize(20, 20);
    m_thinkingToggleBtn->setCursor(Qt::PointingHandCursor);
    QObject::connect(m_thinkingToggleBtn, &QPushButton::clicked, [this]() {
        setThinkingExpanded(!m_thinkingExpanded);
    });
    thinkingHeaderLayout->addWidget(m_thinkingToggleBtn);

    m_typingWidget = new QWidget(thinkingHeader);
    m_typingWidget->setObjectName(QStringLiteral("typingWidget"));
    QHBoxLayout* typeLay = new QHBoxLayout(m_typingWidget);
    typeLay->setContentsMargins(0, 0, 0, 0);

    m_typingLabel = new QLabel(QStringLiteral("Thinking"), m_typingWidget);
    m_typingLabel->setObjectName(QStringLiteral("typingLabel"));
    typeLay->addWidget(m_typingLabel);

    m_typingOpacity = new QGraphicsOpacityEffect(m_typingLabel);
    m_typingLabel->setGraphicsEffect(m_typingOpacity);
    m_typingOpacity->setOpacity(1.0);

    m_typingPulse = new QPropertyAnimation(m_typingOpacity, QByteArrayLiteral("opacity"));
    m_typingPulse->setDuration(1400);
    m_typingPulse->setStartValue(0.35);
    m_typingPulse->setEndValue(1.0);
    m_typingPulse->setEasingCurve(QEasingCurve::InOutSine);
    m_typingPulse->setLoopCount(-1);

    m_typingTimer = new QTimer(this);
    QObject::connect(m_typingTimer, &QTimer::timeout, [this]() {
        m_typingDotCount = (m_typingDotCount + 1) % 4;
        QString dots;
        for (int i = 0; i < m_typingDotCount; ++i)
            dots += QChar('.');
        QString statusText = m_currentToolLabel->text().isEmpty()
            ? QStringLiteral("Thinking")
            : m_currentToolLabel->text();
        if (statusText.startsWith(QStringLiteral("Thinking")) || statusText.startsWith(QStringLiteral("Calling")))
            m_typingLabel->setText(statusText + dots);
    });

    thinkingHeaderLayout->addWidget(m_typingWidget);
    thinkingHeaderLayout->addStretch();

    m_thinkingElapsedLabel = new QLabel(thinkingHeader);
    m_thinkingElapsedLabel->setObjectName(QStringLiteral("thinkingElapsedLabel"));
    m_thinkingElapsedLabel->setVisible(false);
    thinkingHeaderLayout->addWidget(m_thinkingElapsedLabel);

    thinkingLayout->addWidget(thinkingHeader);

    m_thinkingDetails = new QWidget(m_thinkingContainer);
    m_thinkingDetails->setObjectName(QStringLiteral("thinkingDetails"));
    m_thinkingDetails->setVisible(false);
    QVBoxLayout* detailsLayout = new QVBoxLayout(m_thinkingDetails);
    detailsLayout->setContentsMargins(12, 4, 12, 10);
    detailsLayout->setSpacing(4);

    m_currentToolLabel = new QLabel(m_thinkingDetails);
    m_currentToolLabel->setObjectName(QStringLiteral("currentToolLabel"));
    m_currentToolLabel->setWordWrap(true);
    m_currentToolLabel->setVisible(false);
    detailsLayout->addWidget(m_currentToolLabel);

    m_streamingDisplay = new QTextEdit(m_thinkingDetails);
    m_streamingDisplay->setObjectName(QStringLiteral("streamingDisplay"));
    m_streamingDisplay->setReadOnly(true);
    m_streamingDisplay->setAcceptRichText(false);
    m_streamingDisplay->setMinimumHeight(60);
    m_streamingDisplay->setMaximumHeight(280);
    m_streamingDisplay->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_streamingDisplay->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_streamingDisplay->setLineWrapMode(QTextEdit::WidgetWidth);
    m_streamingDisplay->document()->setDocumentMargin(10);
    QObject::connect(m_streamingDisplay->verticalScrollBar(), &QScrollBar::sliderPressed, [this]() {
        m_userScrolledStreaming = true;
    });
    QObject::connect(m_streamingDisplay->verticalScrollBar(), &QScrollBar::valueChanged, [this](int value) {
        QScrollBar* sb = m_streamingDisplay->verticalScrollBar();
        if (value >= sb->maximum() - 4)
            m_userScrolledStreaming = false;
    });
    detailsLayout->addWidget(m_streamingDisplay);

    thinkingLayout->addWidget(m_thinkingDetails);

    chatAreaLayout->addWidget(m_thinkingContainer);
    bodyLayout->addWidget(chatArea, 1);

    mainLayout->addWidget(bodyContainer, 1);

    QWidget* inputContainer = new QWidget(this);
    inputContainer->setObjectName(QStringLiteral("inputContainer"));
    QVBoxLayout* inputOuterLay = new QVBoxLayout(inputContainer);
    inputOuterLay->setContentsMargins(14, 8, 14, 12);
    inputOuterLay->setSpacing(8);

    m_inputField = new QTextEdit(inputContainer);
    m_inputField->setObjectName(QStringLiteral("chatInput"));
    m_inputField->setPlaceholderText(
        QString::fromStdString(OBFSTR("Ask AiDA anything... (Ctrl+Enter)")));
    m_inputField->setAcceptRichText(false);
    m_inputField->setTabChangesFocus(true);
    m_inputField->document()->setDocumentMargin(6);
    m_inputField->setFixedHeight(50);
    m_inputField->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_inputField->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_inputField->installEventFilter(this);
    QObject::connect(m_inputField, &QTextEdit::textChanged, [this]() {
        QTextDocument* doc = m_inputField->document();
        int docHeight = static_cast<int>(doc->size().height());
        int newHeight = docHeight + 12;
        newHeight = qBound(50, newHeight, 158);
        m_inputField->setFixedHeight(newHeight);
        m_inputField->setVerticalScrollBarPolicy(
            newHeight >= 158 ? Qt::ScrollBarAsNeeded : Qt::ScrollBarAlwaysOff);
    });
    inputOuterLay->addWidget(m_inputField, 0);

    QHBoxLayout* btnRow = new QHBoxLayout();
    btnRow->setSpacing(12);

    m_tagBtn = new QPushButton(QStringLiteral("@ Tag Function"), inputContainer);
    m_tagBtn->setObjectName(QStringLiteral("tagBtn"));
    m_tagBtn->setToolTip(QStringLiteral("Tag a function to include its code in context"));
    QObject::connect(m_tagBtn, &QPushButton::clicked, [this]() {
        m_inputField->insertPlainText(QStringLiteral("@"));
        m_inputField->setFocus();
        handleAtTrigger();
    });
    btnRow->addWidget(m_tagBtn);

    m_clearBtn = new QPushButton(QStringLiteral("Clear Chat"), inputContainer);
    m_clearBtn->setObjectName(QStringLiteral("clearBtn"));
    m_clearBtn->setToolTip(QStringLiteral("Clear conversation history"));
    QObject::connect(m_clearBtn, &QPushButton::clicked, [this]() {
        clearHistory();
    });
    btnRow->addWidget(m_clearBtn);

    btnRow->addStretch();

    m_sendBtn = new QPushButton(QStringLiteral("Send"), inputContainer);
    m_sendBtn->setObjectName(QStringLiteral("sendBtn"));
    m_sendBtn->setToolTip(QStringLiteral("Send message (Ctrl+Enter)"));
    m_sendBtn->setFixedSize(90, 34);
    QObject::connect(m_sendBtn, &QPushButton::clicked, [this]() {
        sendMessage();
    });
    btnRow->addWidget(m_sendBtn);

    m_cancelBtn = new QPushButton(QStringLiteral("Cancel"), inputContainer);
    m_cancelBtn->setObjectName(QStringLiteral("cancelBtn"));
    m_cancelBtn->setToolTip(QStringLiteral("Cancel current AI request"));
    m_cancelBtn->setFixedSize(90, 34);
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


        int batchSize;
        int queueLen = static_cast<int>(m_typewriterQueue.length());
        if (queueLen > 2000)
            batchSize = queueLen;
        else if (queueLen > 500)
            batchSize = 200;
        else if (queueLen > 200)
            batchSize = 80;
        else if (queueLen > 100)
            batchSize = 40;
        else if (queueLen > 50)
            batchSize = 16;
        else
            batchSize = 6;

        QString batch = m_typewriterQueue.left(batchSize);
        m_typewriterQueue.remove(0, batchSize);

        QTextCursor cursor = m_streamingDisplay->textCursor();
        cursor.movePosition(QTextCursor::End);
        cursor.insertText(batch);
        if (!m_userScrolledStreaming)
        {
            m_streamingDisplay->setTextCursor(cursor);
            m_streamingDisplay->ensureCursorVisible();
        }
    });

    m_thinkingElapsedTimer = new QTimer(this);
    m_thinkingElapsedTimer->setInterval(1000);
    QObject::connect(m_thinkingElapsedTimer, &QTimer::timeout, [this]() {
        qint64 elapsed = m_thinkingStopwatch.elapsed() / 1000;
        m_thinkingElapsedLabel->setText(formatElapsedTime(elapsed));
        m_thinkingElapsedLabel->setVisible(true);
    });

    m_toastLabel = new QLabel(this);
    m_toastLabel->setObjectName(QStringLiteral("toastLabel"));
    m_toastLabel->setAlignment(Qt::AlignCenter);
    m_toastLabel->setVisible(false);
    m_toastLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
    m_toastLabel->setFixedHeight(34);

    m_toastTimer = new QTimer(this);
    m_toastTimer->setSingleShot(true);
    QObject::connect(m_toastTimer, &QTimer::timeout, [this]() {
        m_toastLabel->setVisible(false);
    });
}

QSize AiDAChatPanel::sizeHint() const
{
    return QSize(400, 600);
}

QSize AiDAChatPanel::minimumSizeHint() const
{
    return QSize(320, 300);
}

ThemeColors AiDAChatPanel::detectThemeColors() const
{
    ThemeColors t;
    QWidget* idaParent = parentWidget();
    QPalette p = idaParent ? idaParent->palette() : palette();

    QColor windowColor = p.color(QPalette::Window);
    QColor baseColor = p.color(QPalette::Base);
    QColor highlightColor = p.color(QPalette::Highlight);

    bool isDark = windowColor.lightnessF() < 0.5;

    QColor textColor = isDark ? QColor(255, 255, 255) : QColor(0, 0, 0);

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

        t.panelBg = base;
        t.headerBg = blendColor(base, QColor(18, 18, 18), 0.56);
        t.headerBorder = stroke;
        t.textPrimary = textColor;
        t.textSecondary = textColor;
        t.textMuted = textColor;
        t.inputBg = elevated;
        t.inputBorder = stroke;
        t.inputBorderFocus = blendColor(accent, QColor(200, 200, 200), 0.24);
        t.buttonPrimary = accent;
        t.buttonPrimaryHover = blendColor(accent, QColor(200, 200, 200), 0.16);
        t.buttonPrimaryPressed = blendColor(accent, QColor(24, 24, 24), 0.36);
        t.buttonSecondaryBg = QColor(0, 0, 0, 0);
        t.buttonSecondaryBorder = blendColor(base, stroke, 0.9);
        t.buttonSecondaryHover = blendColor(base, elevated, 0.86);
        t.messageBgUser = blendColor(accent, QColor(55, 55, 55), 0.28);
        t.messageBgAi = blendColor(base, QColor(48, 48, 48), 0.66);
        t.messageBgSystem = blendColor(base, QColor(40, 40, 40), 0.62);
        t.messageBorder = blendColor(base, stroke, 0.86);
        t.bubbleAiText = textColor;
        t.codeBlockBg = yellowCodeBg;
        t.codeBlockBorder = yellowCodeBorder;
        t.codeBlockText = textColor;
        t.inlineCodeBg = yellowInlineBg;
        t.inlineCodeText = textColor;
        t.accentColor = textColor;
        t.selectionBg = blendColor(accent, QColor(28, 28, 28), 0.36);
        t.linkColor = textColor;
        t.historyItemHover = blendColor(base, elevated, 0.82);
        t.historyItemSelected = blendColor(accent, QColor(90, 90, 90), 0.30);
    }
    else
    {
        QColor base = blendColor(windowColor, QColor(248, 248, 248), 0.78);
        QColor elevated = blendColor(base, QColor(238, 238, 238), 0.62);
        QColor stroke = blendColor(base, QColor(208, 208, 208), 0.84);

        t.panelBg = base;
        t.headerBg = blendColor(base, QColor(240, 240, 240), 0.6);
        t.headerBorder = stroke;
        t.textPrimary = textColor;
        t.textSecondary = textColor;
        t.textMuted = textColor;
        t.inputBg = blendColor(baseColor, elevated, 0.54);
        t.inputBorder = stroke;
        t.inputBorderFocus = blendColor(accent, QColor(140, 140, 140), 0.3);
        t.buttonPrimary = blendColor(accent, QColor(110, 110, 110), 0.26);
        t.buttonPrimaryHover = blendColor(t.buttonPrimary, QColor(255, 255, 255), 0.12);
        t.buttonPrimaryPressed = blendColor(t.buttonPrimary, QColor(50, 50, 50), 0.14);
        t.buttonSecondaryBg = QColor(0, 0, 0, 0);
        t.buttonSecondaryBorder = stroke;
        t.buttonSecondaryHover = blendColor(base, elevated, 0.68);
        t.messageBgUser = blendColor(t.buttonPrimary, QColor(120, 120, 120), 0.12);
        t.messageBgAi = blendColor(base, QColor(240, 240, 240), 0.7);
        t.messageBgSystem = blendColor(base, QColor(235, 235, 235), 0.66);
        t.messageBorder = blendColor(base, stroke, 0.9);
        t.bubbleAiText = textColor;
        t.codeBlockBg = yellowCodeBg;
        t.codeBlockBorder = yellowCodeBorder;
        t.codeBlockText = textColor;
        t.inlineCodeBg = yellowInlineBg;
        t.inlineCodeText = textColor;
        t.accentColor = textColor;
        t.selectionBg = blendColor(t.buttonPrimary, QColor(225, 225, 225), 0.68);
        t.linkColor = textColor;
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
    m_theme = detectThemeColors();
    setStyleSheet(buildWidgetStylesheet());
    QPalette chatPal = m_chatDisplay->palette();
    chatPal.setColor(QPalette::Base, m_theme.panelBg);
    chatPal.setColor(QPalette::Window, m_theme.panelBg);
    m_chatDisplay->setPalette(chatPal);
    m_chatDisplay->viewport()->setPalette(chatPal);

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

    if (m_streamingDisplay != nullptr)
    {
        QPalette streamPal = m_streamingDisplay->palette();
        streamPal.setColor(QPalette::Base, blendColor(m_theme.panelBg, m_theme.inputBg, 0.38));
        streamPal.setColor(QPalette::Text, m_theme.textPrimary);
        m_streamingDisplay->setPalette(streamPal);
    }

    rebuildChatDisplay();
    m_updatingTheme = false;
}

QString AiDAChatPanel::buildWidgetStylesheet() const
{
    const ThemeColors& t = m_theme;

    QString css;
    css.reserve(6000);

    css += QStringLiteral(
        "QWidget#aidaChatPanel, QWidget#aidaChatPanel * {"
        "  font-family: 'Inter', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;"
        "  font-size: 10pt;"
        "}");

    css += QStringLiteral("QWidget#aidaChatPanel { background-color: %1; }")
        .arg(colorToRgb(t.panelBg));

    css += QStringLiteral("QWidget#headerBar { background-color: %1; border-bottom: 1px solid %2; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.headerBorder));

    css += QStringLiteral(
        "QLabel#headerLabel { color: %1; font-size: 11pt; font-weight: 650; padding: 0px; background: transparent; }")
        .arg(colorToRgb(t.textPrimary));

    css += QStringLiteral(
        "QLabel#contextLabel { color: %1; font-size: 9pt; padding: 0px; background: transparent; }")
        .arg(colorToRgb(t.textSecondary));

    css += QStringLiteral(
        "QPushButton#historyBtn, QPushButton#newChatBtn {"
        "  background-color: transparent; color: %1; border: 1px solid %2; border-radius: 10px;"
        "  padding: 5px 12px; font-size: 9pt; min-height: 24px; }")
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
        "QTextBrowser#chatDisplay { background-color: %1; border: none; color: %2;"
        "  selection-background-color: %3; padding: 10px 14px 12px 14px; }")
        .arg(colorToRgb(t.panelBg), colorToRgb(t.textPrimary), colorToRgb(t.selectionBg));

    css += QStringLiteral("QWidget#typingWidget { background-color: transparent; }");
    css += QStringLiteral(
        "QLabel#typingLabel { color: %1; font-size: 9pt; font-weight: 500; padding: 0px; background: transparent; }")
        .arg(colorToRgb(t.textSecondary));

    css += QStringLiteral(
        "QWidget#thinkingContainer {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-left: 3px solid %3;"
        "  border-radius: 2px 8px 8px 2px;"
        "  margin: 6px 8px 8px 8px;"
        "  padding: 0px;"
        "}")
        .arg(colorToRgb(blendColor(t.panelBg, t.messageBgSystem, 0.55)),
             colorToRgb(t.messageBorder),
             colorToRgb(t.accentColor));
    css += QStringLiteral(
        "QWidget#thinkingHeader {"
        "  background-color: transparent;"
        "  border-radius: 6px;"
        "}");
    css += QStringLiteral(
        "QPushButton#thinkingToggleBtn {"
        "  background-color: transparent; color: %1; border: none;"
        "  font-size: 9pt; font-weight: 700; padding: 0px; min-width: 20px; max-width: 20px;"
        "}")
        .arg(colorToRgb(t.textMuted));
    css += QStringLiteral(
        "QPushButton#thinkingToggleBtn:hover { color: %1; }")
        .arg(colorToRgb(t.textPrimary));
    css += QStringLiteral(
        "QWidget#thinkingDetails { background-color: transparent; }");
    css += QStringLiteral(
        "QTextEdit#streamingDisplay {"
        "  color: %1; font-size: 9pt; padding: 8px 10px;"
        "  background-color: %2;"
        "  border: 1px solid %3; border-radius: 6px;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace;"
        "  selection-background-color: %4;"
        "}")
        .arg(colorToRgb(t.textSecondary),
             colorToRgb(blendColor(t.panelBg, t.inputBg, 0.38)),
             colorToRgb(t.messageBorder),
             colorToRgb(t.selectionBg));
    css += QStringLiteral(
          "QLabel#currentToolLabel { color: %1; font-size: 9pt; font-weight: 500; padding: 2px 0px; }")
        .arg(colorToRgb(t.accentColor));

    css += QStringLiteral(
        "QLabel#thinkingElapsedLabel {"
        "  color: %1; font-size: 8.5pt; font-weight: 500;"
        "  padding: 2px 8px; background: transparent;"
        "}")
        .arg(colorToRgb(t.textMuted));

    css += QStringLiteral(
        "QWidget#inputContainer { background-color: %1; border-top: 1px solid %2; }")
        .arg(colorToRgb(t.panelBg), colorToRgb(t.headerBorder));

    css += QStringLiteral(
        "QTextEdit#chatInput { background-color: %1; border: 1px solid %2; border-radius: 14px;"
        "  color: %3; font-size: 10pt; padding: 6px 12px; selection-background-color: %4; }")
        .arg(colorToRgb(t.inputBg), colorToRgb(t.inputBorder), colorToRgb(t.textPrimary), colorToRgb(t.selectionBg));
    css += QStringLiteral(
        "QTextEdit#chatInput:focus { border: 1px solid %1; }")
        .arg(colorToRgb(t.inputBorderFocus));

    css += QStringLiteral(
        "QPushButton#sendBtn { background-color: %1; color: %3; border: 1px solid %2; border-radius: 10px;"
        "  padding: 6px 20px; font-size: 10pt; font-weight: 650; min-height: 32px; min-width: 88px; }")
        .arg(colorToRgb(t.buttonPrimary), colorToRgb(t.buttonPrimary.darker(112)), colorToRgb(t.textPrimary));
    css += QStringLiteral("QPushButton#sendBtn:hover { background-color: %1; }")
        .arg(colorToRgb(t.buttonPrimaryHover));
    css += QStringLiteral("QPushButton#sendBtn:pressed { background-color: %1; }")
        .arg(colorToRgb(t.buttonPrimaryPressed));
    css += QStringLiteral(
        "QPushButton#sendBtn:disabled { background-color: %1; color: %2; border-color: %3; }")
        .arg(colorToRgb(t.inputBorder), colorToRgb(t.textSecondary), colorToRgb(t.inputBorder));

    css += QStringLiteral(
        "QPushButton#cancelBtn { background-color: %1; color: %2; border: 1px solid %3; border-radius: 10px;"
        "  padding: 6px 20px; font-size: 10pt; font-weight: 650; min-height: 32px; min-width: 88px; }")
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
        "QPushButton#clearBtn, QPushButton#tagBtn { background-color: transparent; color: %1;"
        "  border: 1px solid %2; border-radius: 10px; padding: 6px 16px; font-size: 9pt; min-height: 32px; }")
        .arg(colorToRgb(t.textSecondary), colorToRgb(t.buttonSecondaryBorder));
    css += QStringLiteral(
        "QPushButton#clearBtn:hover, QPushButton#tagBtn:hover {"
        "  background-color: %1; color: %2; border-color: %3; }")
        .arg(colorToRgb(t.buttonSecondaryHover), colorToRgb(t.textPrimary), colorToRgb(t.inputBorder));

    css += QStringLiteral("QWidget#historyPanel { background-color: %1; border-right: 1px solid %2; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.headerBorder));

    css += QStringLiteral(
        "QListWidget#historyList { background-color: %1; color: %2; border: none; font-size: 9pt; outline: none; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.textPrimary));
    css += QStringLiteral(
        "QListWidget#historyList::item { padding: 11px 14px; border-bottom: 1px solid %1; }")
        .arg(colorToRgb(t.messageBorder));
    css += QStringLiteral(
        "QListWidget#historyList::item:selected { background-color: %1; color: %2; }")
        .arg(colorToRgb(t.historyItemSelected), colorToRgb(t.textPrimary));
    css += QStringLiteral(
        "QListWidget#historyList::item:hover { background-color: %1; }")
        .arg(colorToRgb(t.historyItemHover));

    css += QStringLiteral(
        "QLabel#historyTitle { padding: 10px 12px; font-weight: 650; font-size: 9pt;"
        "  color: %1; background-color: %2; border-bottom: 1px solid %3; }")
        .arg(colorToRgb(t.textPrimary), colorToRgb(t.headerBg), colorToRgb(t.headerBorder));

    css += QStringLiteral(
        "FunctionCompleterPopup { background-color: %1; border: 1px solid %2; border-radius: 12px; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.inputBorderFocus));
    css += QStringLiteral(
        "FunctionCompleterPopup QListWidget { background-color: %1; color: %2; border: none;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace; font-size: 9pt; outline: none; }")
        .arg(colorToRgb(t.headerBg), colorToRgb(t.textPrimary));
    css += QStringLiteral("FunctionCompleterPopup QListWidget::item { padding: 8px 12px; }");
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
        "  border-radius: 12px;"
        "  padding: 6px 18px;"
        "  font-size: 9pt;"
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

    QString css;
    css.reserve(6000);

    css += QStringLiteral(
        "body {"
        "  background-color: %1;"
        "  color: %2;"
        "  font-family: 'Inter', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;"
        "  font-size: 10.5pt;"
        "  line-height: 1.58;"
        "  margin: 0;"
        "  padding: 14px 18px 18px 18px;"
        "}")
        .arg(colorToHex(t.panelBg), colorToHex(t.textPrimary));

    css += QStringLiteral(
        "table.msg-row { width: 100%; border-collapse: separate; border-spacing: 0; margin: 0 0 12px 0; }");
    css += QStringLiteral("table.msg-row td { vertical-align: top; padding: 0 8px; }");
    css += QStringLiteral("td.msg-side { width: 16%; }");
    css += QStringLiteral("td.msg-cell-right { text-align: right; }");
    css += QStringLiteral("td.msg-cell-left { text-align: left; }");

    css += QStringLiteral(
        ".bubble-user, .bubble-ai {"
        "  text-align: left;"
        "  border: 1px solid %1;"
        "  border-radius: 16px;"
        "  padding: 14px 18px 12px 18px;"
        "  display: inline-block;"
        "  max-width: 80%;"
        "  min-width: 120px;"
        "  word-wrap: break-word;"
        "}")
        .arg(colorToHex(t.messageBorder));

    css += QStringLiteral(
        ".bubble-user {"
        "  background-color: %1;"
        "  color: %2;"
        "}")
        .arg(colorToHex(t.messageBgUser), colorToHex(t.textPrimary));

    css += QStringLiteral(
        ".bubble-ai {"
        "  background-color: %1;"
        "  color: %2;"
        "}")
        .arg(colorToHex(t.messageBgAi), colorToHex(t.bubbleAiText));

    css += QStringLiteral(
        ".msg-system {"
        "  margin: 10px auto 16px auto;"
        "  max-width: 84%;"
        "  padding: 9px 14px;"
        "  background-color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 10px;"
        "  color: %1;"
        "  font-size: 9.5pt;"
        "  text-align: center;"
        "}")
        .arg(colorToHex(t.textSecondary), colorToHex(t.messageBgSystem), colorToHex(t.messageBorder));

    css += QStringLiteral(".msg-content { line-height: 1.62; margin: 0; }");
    css += QStringLiteral(".msg-actions { text-align: right; padding-top: 10px; margin: 0; }");

    css += QStringLiteral(
        ".msg-sender-label {"
        "  font-size: 8.5pt;"
        "  font-weight: 650;"
        "  color: %1;"
        "  padding: 0 4px 4px 4px;"
        "  margin: 0;"
        "}")
        .arg(colorToHex(t.textMuted));

    css += QStringLiteral(
        ".copy-btn-user, .copy-btn {"
        "  color: %1;"
        "  font-size: 8.5pt;"
        "  font-weight: 600;"
        "  text-decoration: none;"
        "}")
        .arg(colorToHex(t.linkColor));
    css += QStringLiteral(".copy-btn-user { color: %1; }")
        .arg(colorToHex(t.textPrimary));
    css += QStringLiteral(
        ".copy-btn-outline {"
        "  border: 1px solid %1;"
        "  border-radius: 10px;"
        "  padding: 4px 12px;"
        "  margin: 0 2px;"
        "}")
        .arg(colorToHex(t.messageBorder));

    css += QStringLiteral(
        ".tag-ref {"
        "  color: %1;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace;"
        "  background-color: %2;"
        "  padding: 1px 6px;"
        "  border-radius: 4px;"
        "  text-decoration: none;"
        "}")
        .arg(colorToHex(t.accentColor), colorToHex(t.inlineCodeBg));

    css += QStringLiteral(
        "pre {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 11px;"
        "  padding: 12px 16px;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace;"
        "  font-size: 9.5pt;"
        "  color: %3;"
        "  margin: 12px 0 8px 0;"
        "  white-space: pre-wrap;"
        "  word-wrap: break-word;"
        "  overflow-wrap: anywhere;"
        "  line-height: 1.45;"
        "}")
        .arg(colorToHex(t.codeBlockBg), colorToHex(t.codeBlockBorder), colorToHex(t.codeBlockText));

    css += QStringLiteral(
        ".bubble-user pre, .bubble-ai pre { max-width: 100%; box-sizing: border-box; }");

    css += QStringLiteral(
        "code {"
        "  background-color: %1;"
        "  color: %2;"
        "  padding: 2px 6px;"
        "  border-radius: 5px;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace;"
        "  font-size: 9.5pt;"
        "}")
        .arg(colorToHex(t.inlineCodeBg), colorToHex(t.inlineCodeText));

    css += QStringLiteral(
        ".nav-link {"
        "  color: %1;"
        "  font-family: 'Cascadia Mono', 'Consolas', 'Courier New', monospace;"
        "  font-size: 9.5pt;"
        "  background-color: %2;"
        "  padding: 2px 6px;"
        "  border-radius: 5px;"
        "  text-decoration: none;"
        "  border-bottom: 1px dashed %1;"
        "}")
        .arg(colorToHex(t.linkColor), colorToHex(t.inlineCodeBg));
    css += QStringLiteral(
        ".nav-link:hover { text-decoration: underline; background-color: %1; }")
        .arg(colorToHex(t.selectionBg));

    css += QStringLiteral(
        ".md-heading { font-weight: 700; color: %1; display: block; margin: 2px 0 3px 0; }")
        .arg(colorToHex(t.accentColor));
    css += QStringLiteral(".md-h1 { font-size: 13pt; }");
    css += QStringLiteral(".md-h2 { font-size: 12pt; }");
    css += QStringLiteral(".md-h3 { font-size: 11pt; }");

    return css;
}

void AiDAChatPanel::setupStyle()
{
    m_theme = detectThemeColors();
    setStyleSheet(buildWidgetStylesheet());
    const QFont chatFont = createChatUiFont();
    setFont(chatFont);
    const auto widgets = findChildren<QWidget*>();
    for (QWidget* widget : widgets)
        widget->setFont(chatFont);
    QPalette chatPal = m_chatDisplay->palette();
    chatPal.setColor(QPalette::Base, m_theme.panelBg);
    chatPal.setColor(QPalette::Window, m_theme.panelBg);
    m_chatDisplay->setPalette(chatPal);
    m_chatDisplay->viewport()->setPalette(chatPal);
    m_chatDisplay->document()->setDefaultFont(chatFont);

    QPalette inputPal = m_inputField->palette();
    inputPal.setColor(QPalette::Base, m_theme.inputBg);
    inputPal.setColor(QPalette::Text, m_theme.textPrimary);
#if QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)
    inputPal.setColor(
        QPalette::PlaceholderText,
        blendColor(m_theme.textSecondary, m_theme.inputBg, 0.48));
#endif
    m_inputField->setPalette(inputPal);

    QPalette streamPal = m_streamingDisplay->palette();
    streamPal.setColor(QPalette::Base, blendColor(m_theme.panelBg, m_theme.inputBg, 0.38));
    streamPal.setColor(QPalette::Text, m_theme.textPrimary);
    m_streamingDisplay->setPalette(streamPal);
}

bool AiDAChatPanel::event(QEvent* ev)
{
    if (ev->type() == QEvent::PaletteChange || ev->type() == QEvent::StyleChange)
    {
        updateThemeColors();
    }
    return QWidget::event(ev);
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

    if (m_completerActive)
    {
        m_completer->dismiss();
        m_completerActive = false;
    }

    QString text = m_inputField->toPlainText().trimmed();
    if (text.isEmpty()) return;

    if (text == QStringLiteral("/clear"))
    {
        clearHistory();
        m_inputField->clear();
        return;
    }
    if (text == QStringLiteral("/help"))
    {
        m_history.emplace_back("System",
            "Commands:\n"
            "  /clear \u2014 Clear conversation\n"
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

    setThinkingState(true);

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
    setThinkingState(false);

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
        m_history.emplace_back("AiDA", response);
    }
    rebuildChatDisplay();
    saveCurrentConversation();
    saveToDisk();
}

void AiDAChatPanel::setThinkingState(bool thinking)
{
    m_isWaiting = thinking;
    m_sendBtn->setVisible(!thinking);
    m_cancelBtn->setVisible(thinking);

    if (thinking)
    {
        m_thinkingContainer->setVisible(true);
        m_thinkingToggleBtn->setVisible(true);
        m_userScrolledStreaming = false;
        m_typingDotCount = 0;
        m_typingLabel->setText(QStringLiteral("Thinking"));
        m_thinkingStopwatch.start();
        m_thinkingElapsedLabel->setText(QStringLiteral("0s"));
        m_thinkingElapsedLabel->setVisible(true);
        m_thinkingElapsedTimer->start();
        m_currentToolLabel->clear();
        m_currentToolLabel->setVisible(false);
        m_typingTimer->start(500);
        m_typingPulse->start();
        clearThinkingStatus();
        setThinkingExpanded(false);
    }
    else
    {
        m_typingTimer->stop();
        m_typingPulse->stop();
        m_typingOpacity->setOpacity(1.0);
        m_typewriterTimer->stop();
        m_thinkingElapsedTimer->stop();

        if (!m_typewriterQueue.isEmpty())
        {
            QTextCursor cursor = m_streamingDisplay->textCursor();
            cursor.movePosition(QTextCursor::End);
            cursor.insertText(m_typewriterQueue);
            if (!m_userScrolledStreaming)
            {
                m_streamingDisplay->setTextCursor(cursor);
                m_streamingDisplay->ensureCursorVisible();
            }
            m_typewriterQueue.clear();
        }

        bool hasContent = !m_streamingDisplay->toPlainText().trimmed().isEmpty();
        {
            qint64 elapsed = m_thinkingStopwatch.elapsed() / 1000;
            if (elapsed > 0)
                m_typingLabel->setText(QStringLiteral("Thought for ") + formatElapsedTime(elapsed));
            else
                m_typingLabel->setText(QStringLiteral("Thought"));
        }

        if (hasContent)
        {
            m_typingWidget->setVisible(true);
            m_thinkingToggleBtn->setVisible(true);
            m_thinkingElapsedLabel->setVisible(false);
            setThinkingExpanded(false);
            m_thinkingContainer->setVisible(true);
        }
        else
        {
            m_typingWidget->setVisible(false);
            m_thinkingToggleBtn->setVisible(false);
            m_thinkingExpanded = false;
            m_thinkingDetails->setVisible(false);
            m_currentToolLabel->clear();
            m_currentToolLabel->setVisible(false);
            m_thinkingContainer->setVisible(false);
        }
    }
}

static QString stripCodeFences(const QString& text);

void AiDAChatPanel::updateThinkingStatus(const QString& reasoning, const QStringList& pendingTools, const QString& currentTool)
{
    if (!m_isWaiting)
        return;

    if (!reasoning.isEmpty())
    {
        m_thinkingToggleBtn->setVisible(true);
        if (!m_streamBuffer.isEmpty()
            && !m_streamBuffer.endsWith(QStringLiteral("\n")))
        {
            QString sep = QStringLiteral("\n");
            m_typewriterQueue += sep;
            m_streamBuffer += sep;
        }
        QString cleanedReasoning = stripCodeFences(reasoning);
        m_typewriterQueue += cleanedReasoning;
        m_streamBuffer += cleanedReasoning;

        if (!m_typewriterTimer->isActive())
            m_typewriterTimer->start();

        if (!m_thinkingExpanded)
            setThinkingExpanded(true);
    }

    if (!currentTool.isEmpty())
    {
        m_currentToolLabel->setText(QString(QChar(0x2699)) + QStringLiteral(" Executing: ") + currentTool);
        m_currentToolLabel->setVisible(true);
        m_typingLabel->setText(QStringLiteral("Running ") + currentTool);
    }
    else if (!pendingTools.isEmpty())
    {
        QString toolsText = QStringLiteral("Pending: ") + pendingTools.join(QStringLiteral(", "));
        if (toolsText.length() > 60)
            toolsText = toolsText.left(60) + QStringLiteral("...");
        m_currentToolLabel->setText(toolsText);
        m_currentToolLabel->setVisible(true);
    }
    else
    {
        m_currentToolLabel->clear();
        m_currentToolLabel->setVisible(false);
        m_typingLabel->setText(QStringLiteral("Thinking"));
    }
}

void AiDAChatPanel::addToolResult(const QString& toolName, bool success, const QString& message)
{
    if (!m_isWaiting)
        return;

    if (!m_typewriterQueue.isEmpty())
    {
        QTextCursor flush = m_streamingDisplay->textCursor();
        flush.movePosition(QTextCursor::End);
        flush.insertText(m_typewriterQueue);
        m_typewriterQueue.clear();
    }

    QString icon = success ? QString(QChar(0x2713)) : QString(QChar(0x2717));
    QColor statusColor = success ? QColor(100, 190, 120) : QColor(210, 90, 90);
    QString displayMsg = message;
    if (displayMsg.length() > 100)
        displayMsg = displayMsg.left(100) + QStringLiteral("...");

    QTextCursor cursor = m_streamingDisplay->textCursor();
    cursor.movePosition(QTextCursor::End);

    if (!m_streamingDisplay->document()->isEmpty())
        cursor.insertText(QStringLiteral("\n"));

    QTextCharFormat iconFmt;
    iconFmt.setForeground(statusColor);
    iconFmt.setFontWeight(QFont::DemiBold);
    cursor.insertText(icon + QStringLiteral(" "), iconFmt);

    QTextCharFormat nameFmt;
    nameFmt.setForeground(statusColor);
    nameFmt.setFontWeight(QFont::Medium);
    cursor.insertText(toolName, nameFmt);

    if (!displayMsg.isEmpty())
    {
        QTextCharFormat msgFmt;
        msgFmt.setForeground(m_theme.textMuted);
        cursor.insertText(QStringLiteral("  ") + displayMsg, msgFmt);
    }

    if (!m_userScrolledStreaming)
    {
        m_streamingDisplay->setTextCursor(cursor);
        m_streamingDisplay->ensureCursorVisible();
    }
}

void AiDAChatPanel::setThinkingExpanded(bool expanded)
{
    m_thinkingExpanded = expanded;
    m_thinkingDetails->setVisible(expanded);
    m_thinkingToggleBtn->setText(expanded ? QString(QChar(0x25BC)) : QString(QChar(0x25B6)));
}

void AiDAChatPanel::clearThinkingStatus()
{
    m_streamingDisplay->clear();
    m_streamBuffer.clear();
    m_typewriterQueue.clear();
    m_currentToolLabel->clear();
    m_currentToolLabel->setVisible(false);
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

void AiDAChatPanel::appendStreamChunk(const QString& chunk)
{
    if (!m_isWaiting)
        return;

    QString cleaned = stripCodeFences(chunk);
    m_streamBuffer += cleaned;
    m_typewriterQueue += cleaned;
    m_thinkingToggleBtn->setVisible(true);

    if (!m_typewriterTimer->isActive())
        m_typewriterTimer->start();

    if (!m_thinkingExpanded)
        setThinkingExpanded(true);
}

void AiDAChatPanel::resetStreamBuffer()
{
    m_streamBuffer.clear();
    m_streamingDisplay->clear();
}

void AiDAChatPanel::cancelRequest()
{
    if (!m_isWaiting || !m_plugin || !m_plugin->ai_client)
        return;

    m_plugin->ai_client->cancel_current_request();
    setThinkingState(false);
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
    m_thinkingContainer->setVisible(false);
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

void AiDAChatPanel::rebuildChatDisplay()
{
    QString html;
    html.reserve(16384);

    html += QStringLiteral("<!DOCTYPE html><html><head><style>");
    html += buildDocumentCss();
    html += QStringLiteral("</style></head><body>\n");

    if (m_history.empty())
    {
        html += QStringLiteral(
            "<div class='msg-system'>"
            "<span class='md-heading md-h3'>Welcome to AiDA</span><br>"
            "Ask questions about your binary, tag functions with "
            "<span class='tag-ref'>@function_name</span>, "
            "and get AI-powered analysis.<br>"
            "Type <code>/help</code> for commands."
            "</div>\n");
    }

    for (int i = 0; i < static_cast<int>(m_history.size()); ++i)
    {
        const std::string& role    = m_history[i].first;
        const std::string& content = m_history[i].second;
        QString msg = QString::fromStdString(content);

        if (role == "User")
            html += formatUserMessageHtml(msg, i);
        else if (role == "AiDA")
            html += formatAiMessageHtml(msg, i);
        else
            html += formatSystemMessageHtml(msg);
    }

    html += QStringLiteral("\n</body></html>");

    m_chatDisplay->setHtml(html);
    scrollToBottom();
}

void AiDAChatPanel::scrollToBottom()
{
    if (m_userScrolledChat)
        return;
    QScrollBar* sb = m_chatDisplay->verticalScrollBar();
    sb->setValue(sb->maximum());
}

QString AiDAChatPanel::formatUserMessageHtml(const QString& msg, int index) const
{
    QString escaped = escapeHtml(msg);
    escaped.replace(QStringLiteral("\n"), QStringLiteral("<br>"));

    QString bubbleStyle = QStringLiteral(
        "text-align:left;"
        "border:1px solid %1;"
        "border-radius:16px;"
        "padding:14px 18px 12px 18px;"
        "display:inline-block;"
        "max-width:80%;"
        "min-width:120px;"
        "word-wrap:break-word;"
        "background-color:%2;"
        "color:%3;")
        .arg(colorToHex(m_theme.messageBorder),
             colorToHex(m_theme.messageBgUser),
             colorToHex(m_theme.textPrimary));

    escaped.replace(
        QRegularExpression(QStringLiteral("@(\\w+)")),
        QStringLiteral("<span class='tag-ref'>@\\1</span>"));

    return QStringLiteral(
        "<table class='msg-row' width='100%' cellspacing='0' cellpadding='0'><tr>"
        "<td class='msg-side'></td>"
        "<td class='msg-cell-right'>"
        "<div class='msg-sender-label' style='text-align:right;'>You</div>"
        "<div class='bubble-user' style='%3'>"
        "<div class='msg-content'>%2</div>"
        "<div class='msg-actions'>"
        "<span class='copy-btn-outline'><a href='undo:%1' class='copy-btn-user'>&#x21A9; Undo</a></span>"
        "&nbsp;&nbsp;"
        "<span class='copy-btn-outline'><a href='copy:%1' class='copy-btn-user'>Copy</a></span>"
        "</div>"
        "</div></td>"
        "</tr></table>\n")
        .arg(index)
        .arg(escaped)
        .arg(bubbleStyle);
}

QString AiDAChatPanel::formatAiMessageHtml(const QString& msg, int index) const
{
    QString formatted = markdownToHtml(msg);

    QString bubbleStyle = QStringLiteral(
        "text-align:left;"
        "border:1px solid %1;"
        "border-radius:16px;"
        "padding:14px 18px 12px 18px;"
        "display:inline-block;"
        "max-width:80%;"
        "min-width:120px;"
        "word-wrap:break-word;"
        "background-color:%2;"
        "color:%3;")
        .arg(colorToHex(m_theme.messageBorder),
             colorToHex(m_theme.messageBgAi),
             colorToHex(m_theme.bubbleAiText));

    return QStringLiteral(
        "<table class='msg-row' width='100%' cellspacing='0' cellpadding='0'><tr>"
        "<td class='msg-cell-left'>"
        "<div class='msg-sender-label'>AiDA</div>"
        "<div class='bubble-ai' style='%3'>"
        "<div class='msg-content'>%2</div>"
        "<div class='msg-actions'>"
        "<span class='copy-btn-outline'><a href='undo:%1' class='copy-btn'>&#x21A9; Undo</a></span>"
        "&nbsp;&nbsp;"
        "<span class='copy-btn-outline'><a href='copy:%1' class='copy-btn'>Copy</a></span>"
        "</div>"
        "</div></td><td class='msg-side'></td>"
        "</tr></table>\n")
        .arg(index)
        .arg(formatted)
        .arg(bubbleStyle);
}

QString AiDAChatPanel::formatSystemMessageHtml(const QString& msg) const
{
    QString escaped = escapeHtml(msg);
    escaped.replace(QStringLiteral("\n"), QStringLiteral("<br>"));

    return QStringLiteral(
        "<div class='msg-system'>%1</div>\n")
        .arg(escaped);
}

static QString linkifyCodeContent(const QString& codeContent);

QString AiDAChatPanel::markdownToHtml(const QString& md) const
{
    QString result;
    result.reserve(md.size() * 2);

    QStringList lines = md.split(QChar('\n'));
    bool inCodeBlock = false;
    QString codeAccum;
    bool lastLineWasBlank = false;

    for (int i = 0; i < lines.size(); ++i)
    {
        const QString& line = lines[i];
        QString trimmed = line.trimmed();

        if (trimmed.startsWith(QStringLiteral("```")))
        {
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

        if (trimmed.isEmpty())
        {
            if (!lastLineWasBlank)
                result += QStringLiteral("<br>\n");
            lastLineWasBlank = true;
            continue;
        }
        lastLineWasBlank = false;

        if (QRegularExpression(QStringLiteral("^-{3,}$|^\\*{3,}$|^_{3,}$")).match(trimmed).hasMatch())
        {
            result += QStringLiteral("<hr style='border:none;border-top:1px solid;opacity:0.22;margin:14px 0;'>\n");
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
                        .arg(linkUrl, colorToHex(m_theme.linkColor), linkText);
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
            result += QStringLiteral("<span class='md-heading %1'>%2</span><br>\n")
                .arg(hClass, processed);
        }
        else if (isBlockquote)
        {
            result += QStringLiteral(
                "<div style='border-left:3px solid %1;padding:2px 0 2px 12px;"
                "margin:4px 0;color:%2;'>%3</div>\n")
                .arg(colorToHex(m_theme.accentColor),
                     colorToHex(m_theme.textSecondary),
                     processed);
        }
        else if (isBulletItem)
        {
            result += QStringLiteral(
                "<div style='padding-left:18px;text-indent:-14px;margin:2px 0;'>"
                "<span style='color:%1;'>\u2022</span>&nbsp;%2</div>\n")
                .arg(colorToHex(m_theme.accentColor), processed);
        }
        else if (isNumberedItem)
        {
            result += QStringLiteral(
                "<div style='padding-left:18px;text-indent:-14px;margin:2px 0;'>"
                "<span style='color:%1;font-weight:600;'>%2.</span>&nbsp;%3</div>\n")
                .arg(colorToHex(m_theme.accentColor), listNumber, processed);
        }
        else
        {
            result += processed + QStringLiteral("<br>\n");
        }
    }

    if (inCodeBlock && !codeAccum.isEmpty())
    {
        result += QStringLiteral("<pre>")
               +  escapeHtml(codeAccum)
               +  QStringLiteral("</pre>");
    }

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
    m_thinkingContainer->setVisible(false);
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
