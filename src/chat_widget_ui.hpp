#pragma once

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

#include <ida.hpp>
#include <kernwin.hpp>

#include <string>
#include <vector>
#include <utility>
#include <deque>
#include <functional>

class aida_plugin_t;

class ChatTextBrowser : public QTextBrowser
{
public:
    explicit ChatTextBrowser(QWidget* parent = nullptr) : QTextBrowser(parent)
    {
        setOpenLinks(false);
        setOpenExternalLinks(false);
    }

    std::function<void(const QUrl&)> onAnchorClicked;
    std::function<void(const QUrl&)> onAnchorDoubleClicked;

protected:
    void doSetSource(const QUrl&, QTextDocument::ResourceType) override { /* no-op */ }

    void mouseReleaseEvent(QMouseEvent* e) override
    {
        QString anchor = anchorAt(e->pos());
        if (!anchor.isEmpty() && onAnchorClicked)
        {
            onAnchorClicked(QUrl(anchor));
            e->accept();
            return;
        }
        QTextBrowser::mouseReleaseEvent(e);
    }

    void mouseDoubleClickEvent(QMouseEvent* e) override
    {
        QString anchor = anchorAt(e->pos());
        if (!anchor.isEmpty() && onAnchorDoubleClicked)
        {
            onAnchorDoubleClicked(QUrl(anchor));
            e->accept();
            return;
        }
        QTextBrowser::mouseDoubleClickEvent(e);
    }
};

class FunctionCompleterPopup : public QFrame
{
public:
    explicit FunctionCompleterPopup(QWidget* parent = nullptr);
    void refreshFunctionList();
    void showForPrefix(const QString& prefix, const QPoint& globalPos);
    QString currentSelection() const;
    void moveSelection(int delta);
    bool isActive() const;
    void dismiss();
    void setCompletionCallback(std::function<void(const QString&)> cb);

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    QListWidget* m_list;
    std::function<void(const QString&)> m_completionCallback;

    struct FuncEntry
    {
        QString name;
        ea_t    ea;
    };

    std::vector<FuncEntry> m_allFunctions;

    void applyFilter(const QString& prefix);
};

struct ThemeColors
{
    QColor panelBg;
    QColor headerBg;
    QColor headerBorder;
    QColor textPrimary;
    QColor textSecondary;
    QColor textMuted;
    QColor inputBg;
    QColor inputBorder;
    QColor inputBorderFocus;
    QColor buttonPrimary;
    QColor buttonPrimaryHover;
    QColor buttonPrimaryPressed;
    QColor buttonSecondaryBg;
    QColor buttonSecondaryBorder;
    QColor buttonSecondaryHover;
    QColor messageBgUser;
    QColor messageBgAi;
    QColor messageBgSystem;
    QColor messageBorder;
    QColor bubbleAiText;
    QColor codeBlockBg;
    QColor codeBlockBorder;
    QColor codeBlockText;
    QColor inlineCodeBg;
    QColor inlineCodeText;
    QColor accentColor;
    QColor selectionBg;
    QColor linkColor;
    QColor historyItemHover;
    QColor historyItemSelected;
};

class AiDAChatPanel : public QWidget
{
public:
    explicit AiDAChatPanel(QWidget* parent,
                           aida_plugin_t* plugin,
                           ea_t context_ea,
                           const QString& context_func_name);
    ~AiDAChatPanel() override;

    void setContextFunction(ea_t ea, const QString& func_name);
    void onAiResponse(const std::string& response);
    void clearHistory();

    void updateThinkingStatus(const QString& reasoning, const QStringList& pendingTools, const QString& currentTool);
    void addToolResult(const QString& toolName, bool success, const QString& message);
    void setThinkingExpanded(bool expanded);
    void clearThinkingStatus();
    void appendStreamChunk(const QString& chunk);
    void resetStreamBuffer();

    void setHistory(const std::vector<std::pair<std::string, std::string>>& history);
    std::vector<std::pair<std::string, std::string>> getHistory() const;

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;
    bool event(QEvent* event) override;

private:
    void setupUI();
    void setupStyle();
    void updateContextLabel();
    void updateThemeColors();
    ThemeColors detectThemeColors() const;
    QString buildWidgetStylesheet() const;
    QString buildDocumentCss() const;

    void sendMessage();
    void cancelRequest();
    void setThinkingState(bool thinking);
    void rebuildChatDisplay();
    void scrollToBottom();
    void copyMessageToClipboard(int index);

    void toggleHistoryPanel();
    void loadConversation(int index);
    void saveCurrentConversation();
    void startNewConversation();
    void deleteConversation(int index);
    void rebuildHistoryList();

    QString formatUserMessageHtml(const QString& msg, int index) const;
    QString formatAiMessageHtml(const QString& msg, int index) const;
    QString formatSystemMessageHtml(const QString& msg) const;
    QString markdownToHtml(const QString& md) const;
    QString escapeHtml(const QString& text) const;

    struct TagInfo
    {
        QString tag_name;
        ea_t    resolved_ea   = BADADDR;
        QString resolved_code;
        bool    resolved      = false;
    };
    std::vector<TagInfo> parseTags(const QString& message) const;
    QString buildTagContext(const std::vector<TagInfo>& tags) const;

    void handleAtTrigger();
    void insertCompletion(const QString& funcName);
    int  findAtPosition() const;

    static qstring getHistoryFilePath();
    void saveToDisk() const;
    void loadFromDisk();

    aida_plugin_t* m_plugin;
    ea_t           m_contextEa;
    QString        m_contextFuncName;
    std::vector<std::pair<std::string, std::string>> m_history;
    bool           m_isWaiting;
    bool           m_updatingTheme;
    ThemeColors    m_theme;

    std::vector<TagInfo> m_conversationTags;

    struct SavedConversation
    {
        QString title;
        QString timestamp;
        std::vector<std::pair<std::string, std::string>> messages;
    };
    std::vector<SavedConversation> m_savedConversations;
    int m_activeConversationIndex;

    QWidget*                 m_headerBar;
    QLabel*                  m_headerLabel;
    QLabel*                  m_contextLabel;
    QPushButton*             m_historyBtn;
    QPushButton*             m_newChatBtn;
    ChatTextBrowser*         m_chatDisplay;
    QTextEdit*               m_inputField;
    QPushButton*             m_sendBtn;
    QPushButton*             m_cancelBtn;
    QPushButton*             m_clearBtn;
    QPushButton*             m_tagBtn;
    QWidget*                 m_typingWidget;
    QLabel*                  m_typingLabel;
    QTimer*                  m_typingTimer;
    int                      m_typingDotCount;
    QGraphicsOpacityEffect*  m_typingOpacity;
    QPropertyAnimation*      m_typingPulse;

    QWidget*                 m_thinkingContainer;
    QPushButton*             m_thinkingToggleBtn;
    QWidget*                 m_thinkingDetails;
    QTextEdit*               m_streamingDisplay;
    QLabel*                  m_currentToolLabel;
    bool                     m_thinkingExpanded;
    QString                  m_streamBuffer;

    QWidget*                 m_historyPanel;
    QListWidget*             m_historyList;
    bool                     m_historyVisible;

    FunctionCompleterPopup*  m_completer;
    bool                     m_completerActive;

    QTimer*                  m_typewriterTimer;
    QString                  m_typewriterQueue;
};