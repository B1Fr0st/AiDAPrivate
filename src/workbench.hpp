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

#include <nlohmann/json.hpp>

#include "graphrag.hpp"

#include <vector>

class aida_plugin_t;
class AiDAChatPanel;

class AiDAWorkbenchPanel : public QWidget
{
public:
    explicit AiDAWorkbenchPanel(
        QWidget* parent,
        aida_plugin_t* plugin,
        ea_t context_ea,
        const QString& context_func_name);
    ~AiDAWorkbenchPanel() override = default;

    AiDAChatPanel* query_panel() const;
    void set_context_function(ea_t ea, const QString& func_name);

protected:
    bool event(QEvent* event) override;

private:
    void build_ui();
    void apply_theme();
    void refresh_header_badge_layout();
    void queue_visual_refresh();
    void refresh_all_tabs();
    void refresh_header();

    void build_explain_tab();
    void build_actions_tab();
    void build_graph_tab();
    void build_rag_tab();
    void build_settings_tab();

    bool has_function_context() const;
    ea_t current_function_ea() const;
    QString current_function_display_name() const;
    std::string current_model_name() const;
    std::string analysis_type_key(const char* suffix) const;

    void set_busy_button(QPushButton* button, bool busy, const QString& busy_text, const QString& idle_text);
    void render_text_browser(QTextBrowser* browser, const std::string& text, const QString& title = QString()) const;
    void handle_browser_link(const QUrl& url);

    void save_analysis_entry(const std::string& type, const std::string& result);
    std::string load_analysis_entry(const std::string& type) const;

    void refresh_explain_tab();
    void refresh_explain_side_panel();
    void run_explain_function();
    void run_explain_line();

    void append_actions_log(const QString& title, const std::string& body, bool overwrite = false);
    void refresh_actions_tab();
    void run_copy_context();
    void run_rename_all();
    void run_generate_comments();
    void run_generate_struct();
    void run_generate_hook();
    void run_fix_analysis();

    void refresh_graph_tab();
    void refresh_graph_search_results(const nlohmann::json& results);
    void refresh_graph_visualization(ea_t focus_ea = BADADDR, const std::vector<ea_t>& explicit_addresses = {});
    void rebuild_graph_scene(const std::vector<ea_t>& addresses = {}, ea_t focus_ea = BADADDR);
    void show_graph_node_details(ea_t address);
    std::vector<graphrag::edge_type_t> selected_graph_edge_types() const;
    void index_current_function();
    void reindex_binary();
    void run_graph_security_overview();
    void run_graph_communities();
    void run_graph_network_flow();
    void run_graph_search();

    void refresh_rag_tab();
    void run_rag_search();

    void refresh_settings_tab();

private:
    aida_plugin_t* m_plugin;
    ea_t           m_contextEa;
    QString        m_contextFuncName;
    QString        m_lineExplainText;
    std::string    m_binaryHash;
    bool           m_applyingTheme;
    bool           m_visualRefreshQueued;
    QString        m_appliedStyleSheet;

    QLabel*        m_headerContextLabel;
    QLabel*        m_headerProviderLabel;
    QLabel*        m_headerGraphLabel;
    QTabWidget*    m_tabs;

    AiDAChatPanel* m_queryPanel;

    QLabel*        m_explainContextLabel;
    QTextBrowser*  m_explainBrowser;
    QTextBrowser*  m_explainDetailsBrowser;
    QPushButton*   m_explainFunctionBtn;
    QPushButton*   m_explainLineBtn;
    QPushButton*   m_explainCopyBtn;
    QPushButton*   m_explainClearBtn;

    QLabel*        m_actionsContextLabel;
    QTextBrowser*  m_actionsLogBrowser;
    QPushButton*   m_actionRenameBtn;
    QPushButton*   m_actionCommentsBtn;
    QPushButton*   m_actionStructBtn;
    QPushButton*   m_actionHookBtn;
    QPushButton*   m_actionFixBtn;
    QPushButton*   m_actionCopyBtn;

    QLabel*        m_graphContextLabel;
    QLabel*        m_graphStatusLabel;
    QLabel*        m_graphStatsLabel;
    QGraphicsView* m_graphView;
    QGraphicsScene* m_graphScene;
    QTextBrowser*  m_graphOverviewBrowser;
    QSpinBox*      m_graphHopsSpin;
    QCheckBox*     m_graphCallsCheck;
    QCheckBox*     m_graphVulnCheck;
    QCheckBox*     m_graphNetworkCheck;
    QLabel*        m_graphZoomLabel;
    QLineEdit*     m_graphSearchEdit;
    QSpinBox*      m_graphLimitSpin;
    QTableWidget*  m_graphResultsTable;
    QPushButton*   m_graphIndexBtn;
    QPushButton*   m_graphReindexBtn;
    QPushButton*   m_graphSecurityBtn;
    QPushButton*   m_graphCommunitiesBtn;
    QPushButton*   m_graphNetworkBtn;
    ea_t           m_graphSelectedEa;

    QLabel*        m_ragContextLabel;
    QTextBrowser*  m_ragContextBrowser;
    QLineEdit*     m_ragQueryEdit;
    QTableWidget*  m_ragResultsTable;
    QPushButton*   m_ragRefreshBtn;
    QPushButton*   m_ragSearchBtn;

    QTextBrowser*  m_settingsBrowser;
    QPushButton*   m_settingsOpenBtn;
    QPushButton*   m_settingsRefreshBtn;
    QPushButton*   m_settingsToggleMcpBtn;
    QPushButton*   m_settingsPromptMgrBtn;
};