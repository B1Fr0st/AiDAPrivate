#pragma once


#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <deque>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <functional>
#include <algorithm>
#include <chrono>

#include <nlohmann/json.hpp>
#include <ida.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <hexrays.hpp>
#include <name.hpp>
#include <segment.hpp>

namespace graphrag
{


enum class node_type_t
{
    FUNCTION,
    MODULE,
    COMMUNITY,
    BINARY
};

inline const char* node_type_str(node_type_t t)
{
    switch (t)
    {
    case node_type_t::FUNCTION:  return "FUNCTION";
    case node_type_t::MODULE:    return "MODULE";
    case node_type_t::COMMUNITY: return "COMMUNITY";
    case node_type_t::BINARY:    return "BINARY";
    }
    return "UNKNOWN";
}

inline node_type_t node_type_from_str(const std::string& s)
{
    if (s == "MODULE")    return node_type_t::MODULE;
    if (s == "COMMUNITY") return node_type_t::COMMUNITY;
    if (s == "BINARY")    return node_type_t::BINARY;
    return node_type_t::FUNCTION;
}

enum class edge_type_t
{

    CONTAINS,
    CALLS,
    FLOWS_TO,
    REFERENCES,
    INHERITS,

    SIMILAR_PURPOSE,
    DEPENDS_ON,
    IMPLEMENTS,
    RELATED_TO,

    VULNERABLE_VIA,
    TAINT_FLOWS_TO,
    CALLS_VULNERABLE,
    NETWORK_SEND,
    NETWORK_RECV,

    BELONGS_TO_COMMUNITY,
    SIBLING
};

inline const char* edge_type_str(edge_type_t t)
{
    switch (t)
    {
    case edge_type_t::CONTAINS:              return "CONTAINS";
    case edge_type_t::CALLS:                 return "CALLS";
    case edge_type_t::FLOWS_TO:              return "FLOWS_TO";
    case edge_type_t::REFERENCES:            return "REFERENCES";
    case edge_type_t::INHERITS:              return "INHERITS";
    case edge_type_t::SIMILAR_PURPOSE:       return "SIMILAR_PURPOSE";
    case edge_type_t::DEPENDS_ON:            return "DEPENDS_ON";
    case edge_type_t::IMPLEMENTS:            return "IMPLEMENTS";
    case edge_type_t::RELATED_TO:            return "RELATED_TO";
    case edge_type_t::VULNERABLE_VIA:        return "VULNERABLE_VIA";
    case edge_type_t::TAINT_FLOWS_TO:        return "TAINT_FLOWS_TO";
    case edge_type_t::CALLS_VULNERABLE:      return "CALLS_VULNERABLE";
    case edge_type_t::NETWORK_SEND:          return "NETWORK_SEND";
    case edge_type_t::NETWORK_RECV:          return "NETWORK_RECV";
    case edge_type_t::BELONGS_TO_COMMUNITY:  return "BELONGS_TO_COMMUNITY";
    case edge_type_t::SIBLING:               return "SIBLING";
    }
    return "UNKNOWN";
}

inline edge_type_t edge_type_from_str(const std::string& s)
{
    static const std::unordered_map<std::string, edge_type_t> map = {
        {"CONTAINS", edge_type_t::CONTAINS}, {"CALLS", edge_type_t::CALLS},
        {"FLOWS_TO", edge_type_t::FLOWS_TO}, {"REFERENCES", edge_type_t::REFERENCES},
        {"INHERITS", edge_type_t::INHERITS}, {"SIMILAR_PURPOSE", edge_type_t::SIMILAR_PURPOSE},
        {"DEPENDS_ON", edge_type_t::DEPENDS_ON}, {"IMPLEMENTS", edge_type_t::IMPLEMENTS},
        {"RELATED_TO", edge_type_t::RELATED_TO}, {"VULNERABLE_VIA", edge_type_t::VULNERABLE_VIA},
        {"TAINT_FLOWS_TO", edge_type_t::TAINT_FLOWS_TO}, {"CALLS_VULNERABLE", edge_type_t::CALLS_VULNERABLE},
        {"NETWORK_SEND", edge_type_t::NETWORK_SEND}, {"NETWORK_RECV", edge_type_t::NETWORK_RECV},
        {"BELONGS_TO_COMMUNITY", edge_type_t::BELONGS_TO_COMMUNITY}, {"SIBLING", edge_type_t::SIBLING}
    };
    auto it = map.find(s);
    return it != map.end() ? it->second : edge_type_t::CALLS;
}


struct graph_node_t
{
    int          id = 0;
    std::string  binary_hash;
    node_type_t  node_type = node_type_t::FUNCTION;
    ea_t         address = BADADDR;
    std::string  name;
    std::string  raw_code;
    std::string  llm_summary;
    double       confidence = 0.0;


    std::vector<std::string> security_flags;
    std::vector<std::string> network_apis;
    std::vector<std::string> file_io_apis;
    std::vector<std::string> crypto_apis;
    std::vector<std::string> process_apis;
    std::vector<std::string> ip_addresses;
    std::vector<std::string> urls;
    std::vector<std::string> file_paths;
    std::vector<std::string> domains;
    std::vector<std::string> registry_keys;
    std::string  risk_level;
    std::string  activity_profile;


    int          analysis_depth = 0;
    uint64_t     created_at = 0;
    uint64_t     updated_at = 0;
    bool         is_stale = true;
    bool         user_edited = false;
    int          community_id = -1;
};

inline void to_json(nlohmann::json& j, const graph_node_t& n)
{
    j = {
        {"id", n.id}, {"binary_hash", n.binary_hash},
        {"node_type", node_type_str(n.node_type)},
        {"address", n.address}, {"name", n.name},
        {"raw_code", n.raw_code}, {"llm_summary", n.llm_summary},
        {"confidence", n.confidence},
        {"security_flags", n.security_flags}, {"network_apis", n.network_apis},
        {"file_io_apis", n.file_io_apis}, {"crypto_apis", n.crypto_apis},
        {"process_apis", n.process_apis},
        {"ip_addresses", n.ip_addresses}, {"urls", n.urls},
        {"file_paths", n.file_paths}, {"domains", n.domains},
        {"registry_keys", n.registry_keys},
        {"risk_level", n.risk_level}, {"activity_profile", n.activity_profile},
        {"analysis_depth", n.analysis_depth},
        {"created_at", n.created_at}, {"updated_at", n.updated_at},
        {"is_stale", n.is_stale}, {"user_edited", n.user_edited},
        {"community_id", n.community_id}
    };
}

inline void from_json(const nlohmann::json& j, graph_node_t& n)
{
    n.id = j.value("id", 0);
    n.binary_hash = j.value("binary_hash", "");
    n.node_type = node_type_from_str(j.value("node_type", "FUNCTION"));
    n.address = j.value("address", ea_t(BADADDR));
    n.name = j.value("name", "");
    n.raw_code = j.value("raw_code", "");
    n.llm_summary = j.value("llm_summary", "");
    n.confidence = j.value("confidence", 0.0);
    n.security_flags = j.value("security_flags", std::vector<std::string>{});
    n.network_apis = j.value("network_apis", std::vector<std::string>{});
    n.file_io_apis = j.value("file_io_apis", std::vector<std::string>{});
    n.crypto_apis = j.value("crypto_apis", std::vector<std::string>{});
    n.process_apis = j.value("process_apis", std::vector<std::string>{});
    n.ip_addresses = j.value("ip_addresses", std::vector<std::string>{});
    n.urls = j.value("urls", std::vector<std::string>{});
    n.file_paths = j.value("file_paths", std::vector<std::string>{});
    n.domains = j.value("domains", std::vector<std::string>{});
    n.registry_keys = j.value("registry_keys", std::vector<std::string>{});
    n.risk_level = j.value("risk_level", "");
    n.activity_profile = j.value("activity_profile", "");
    n.analysis_depth = j.value("analysis_depth", 0);
    n.created_at = j.value("created_at", uint64_t(0));
    n.updated_at = j.value("updated_at", uint64_t(0));
    n.is_stale = j.value("is_stale", true);
    n.user_edited = j.value("user_edited", false);
    n.community_id = j.value("community_id", -1);
}

struct graph_edge_t
{
    int         id = 0;
    std::string binary_hash;
    int         source_id = 0;
    int         target_id = 0;
    edge_type_t edge_type = edge_type_t::CALLS;
    double      weight = 1.0;
};

inline void to_json(nlohmann::json& j, const graph_edge_t& e)
{
    j = {{"id", e.id}, {"binary_hash", e.binary_hash},
         {"source_id", e.source_id}, {"target_id", e.target_id},
         {"edge_type", edge_type_str(e.edge_type)}, {"weight", e.weight}};
}

inline void from_json(const nlohmann::json& j, graph_edge_t& e)
{
    e.id = j.value("id", 0);
    e.binary_hash = j.value("binary_hash", "");
    e.source_id = j.value("source_id", 0);
    e.target_id = j.value("target_id", 0);
    e.edge_type = edge_type_from_str(j.value("edge_type", "CALLS"));
    e.weight = j.value("weight", 1.0);
}

struct community_t
{
    int         id = 0;
    std::string binary_hash;
    std::string label;
    std::string purpose;
    std::vector<int> member_ids;
};

inline void to_json(nlohmann::json& j, const community_t& c)
{
    j = {{"id", c.id}, {"binary_hash", c.binary_hash},
         {"label", c.label}, {"purpose", c.purpose},
         {"member_ids", c.member_ids}};
}

inline void from_json(const nlohmann::json& j, community_t& c)
{
    c.id = j.value("id", 0);
    c.binary_hash = j.value("binary_hash", "");
    c.label = j.value("label", "");
    c.purpose = j.value("purpose", "");
    c.member_ids = j.value("member_ids", std::vector<int>{});
}

struct taint_path_t
{
    int         source_id = 0;
    int         sink_id = 0;
    std::vector<int> path;
    std::string source_name;
    std::string sink_name;
    std::vector<std::string> path_names;
    std::vector<std::string> source_apis;
    std::vector<std::string> sink_apis;
    std::string vulnerability_type;
};


class SecurityFeatureExtractor
{
public:
    struct features_t
    {
        std::set<std::string> network_apis;
        std::set<std::string> file_io_apis;
        std::set<std::string> crypto_apis;
        std::set<std::string> process_apis;
        std::map<std::string, std::string> dangerous_functions;
        std::set<std::string> ip_addresses;
        std::set<std::string> urls;
        std::set<std::string> file_paths;
        std::set<std::string> domains;
        std::set<std::string> registry_keys;

        std::vector<std::string> generate_security_flags() const;
        std::string get_activity_profile() const;
        std::string get_risk_level() const;
        bool is_empty() const;
    };

    features_t extract_from_code(const std::string& func_name, const std::string& code) const;
};


class GraphStore
{
public:
    static GraphStore& instance()
    {
        static GraphStore s_inst;
        return s_inst;
    }


    graph_node_t* upsert_node(graph_node_t node);
    graph_node_t* get_node(int id);
    graph_node_t* get_node_by_address(const std::string& binary_hash, node_type_t type, ea_t addr);
    std::vector<graph_node_t*> get_nodes_by_type(const std::string& binary_hash, node_type_t type);
    std::vector<graph_node_t*> get_all_nodes(const std::string& binary_hash);


    graph_edge_t* add_edge(graph_edge_t edge);
    bool has_edge(int source_id, int target_id, edge_type_t type) const;
    std::vector<graph_edge_t*> get_edges_from(int source_id);
    std::vector<graph_edge_t*> get_edges_to(int target_id);
    std::vector<graph_edge_t*> get_edges_for_node(int node_id);
    std::vector<graph_edge_t*> get_edges_by_types(const std::string& binary_hash, const std::vector<edge_type_t>& types);
    std::vector<graph_node_t*> get_callers(const std::string& binary_hash, int node_id);
    std::vector<graph_node_t*> get_callees(const std::string& binary_hash, int node_id);


    void add_community(community_t comm);
    std::vector<community_t> get_communities(const std::string& binary_hash) const;
    bool communities_exist(const std::string& binary_hash) const;
    int delete_communities(const std::string& binary_hash);


    std::vector<graph_node_t*> search_nodes(const std::string& binary_hash, const std::string& query, int limit = 10);


    struct graph_stats_t
    {
        int nodes = 0;
        int edges = 0;
        int stale = 0;
        int communities = 0;
    };
    graph_stats_t get_stats(const std::string& binary_hash) const;


    void delete_graph(const std::string& binary_hash);
    bool save_to_file(const std::string& path);
    bool load_from_file(const std::string& path);
    std::string get_graph_path(const std::string& binary_hash) const;

private:
    GraphStore() = default;
    GraphStore(const GraphStore&) = delete;
    GraphStore& operator=(const GraphStore&) = delete;

    mutable std::mutex m_mtx;
    int m_next_node_id = 1;
    int m_next_edge_id = 1;

    std::unordered_map<int, graph_node_t> m_nodes;
    std::unordered_map<int, graph_edge_t> m_edges;
    std::vector<community_t> m_communities;


    struct addr_key_t
    {
        std::string binary_hash;
        node_type_t type;
        ea_t addr;
        bool operator==(const addr_key_t& o) const
        {
            return binary_hash == o.binary_hash && type == o.type && addr == o.addr;
        }
    };
    struct addr_key_hash
    {
        size_t operator()(const addr_key_t& k) const
        {
            size_t h = std::hash<std::string>{}(k.binary_hash);
            h ^= std::hash<int>{}(static_cast<int>(k.type)) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<ea_t>{}(k.addr) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };
    std::unordered_map<addr_key_t, int, addr_key_hash> m_addr_index;


    std::unordered_map<int, std::vector<int>> m_edges_from;
    std::unordered_map<int, std::vector<int>> m_edges_to;
};


class StructureExtractor
{
public:
    struct extraction_result_t
    {
        int functions_extracted = 0;
        int edges_created = 0;
    };

    using progress_fn = std::function<void(int current, int total, const std::string& msg)>;

    explicit StructureExtractor(GraphStore& store);

    graph_node_t* extract_function(ea_t func_ea, const std::string& binary_hash);
    extraction_result_t extract_all(const std::string& binary_hash, progress_fn on_progress = nullptr);
    void cancel() { m_cancelled = true; }

private:
    GraphStore& m_store;
    SecurityFeatureExtractor m_security;
    std::atomic<bool> m_cancelled{false};

    std::string get_raw_code(ea_t func_ea);
    int extract_call_edges(ea_t func_ea, const std::string& binary_hash, graph_node_t& node);
};


class TaintAnalyzer
{
public:
    static constexpr int MAX_PATH_LENGTH = 10;

    explicit TaintAnalyzer(GraphStore& store);

    std::vector<taint_path_t> find_taint_paths(const std::string& binary_hash,
                                                int max_paths = 100,
                                                bool create_edges = true);
    void cancel() { m_cancelled = true; }


    static const std::set<std::string>& taint_sources();
    static const std::set<std::string>& taint_sinks();

private:
    GraphStore& m_store;
    std::atomic<bool> m_cancelled{false};

    std::vector<graph_node_t*> find_source_nodes(const std::string& binary_hash);
    std::vector<graph_node_t*> find_sink_nodes(const std::string& binary_hash);
    std::vector<std::pair<std::vector<int>, graph_node_t*>> dfs_paths(
        int source_id, const std::unordered_map<int, graph_node_t*>& sinks,
        const std::string& binary_hash, int remaining);
};


class CommunityDetector
{
public:
    using progress_fn = std::function<void(int iteration, int max_iterations)>;

    explicit CommunityDetector(GraphStore& store);

    int detect(const std::string& binary_hash,
               int min_size = 2,
               int max_iterations = 100,
               bool force = false,
               progress_fn on_progress = nullptr);
    void cancel() { m_cancelled = true; }

private:
    GraphStore& m_store;
    std::atomic<bool> m_cancelled{false};

    std::string infer_community_purpose(const std::vector<graph_node_t*>& members);
};


class NetworkFlowAnalyzer
{
public:
    static constexpr int MAX_PATH_LENGTH = 10;

    struct flow_path_t
    {
        int source_id = 0;
        int target_id = 0;
        std::vector<int> path;
        std::string source_name;
        std::string target_name;
        std::string api_name;
        int hop_count = 0;
    };

    struct result_t
    {
        int send_edges_created = 0;
        int recv_edges_created = 0;
        int send_edges_existing = 0;
        int recv_edges_existing = 0;
        std::vector<std::string> send_functions;
        std::vector<std::string> recv_functions;
        std::vector<flow_path_t> send_paths;
        std::vector<flow_path_t> recv_paths;
    };

    using progress_fn = std::function<void(int current, int total, const std::string& msg)>;

    explicit NetworkFlowAnalyzer(GraphStore& store);

    result_t analyze(const std::string& binary_hash, progress_fn on_progress = nullptr);
    void cancel() { m_cancelled = true; }

    static const std::set<std::string>& send_apis();
    static const std::set<std::string>& recv_apis();
    static const std::set<std::string>& entry_point_names();

private:
    GraphStore& m_store;
    std::atomic<bool> m_cancelled{false};

    std::vector<graph_node_t*> find_send_nodes(const std::string& binary_hash);
    std::vector<graph_node_t*> find_recv_nodes(const std::string& binary_hash);
    std::vector<flow_path_t> bfs_find_paths(int source_id, const std::unordered_set<int>& targets,
                                             const std::string& binary_hash);
};


class QueryEngine
{
public:
    explicit QueryEngine(GraphStore& store);

    nlohmann::json get_semantic_analysis(const std::string& binary_hash, ea_t address);
    nlohmann::json search_semantic(const std::string& binary_hash, const std::string& query, int limit = 10);
    nlohmann::json get_similar_functions(const std::string& binary_hash, ea_t address, int limit = 5);
    nlohmann::json get_call_context(const std::string& binary_hash, ea_t address, int depth = 2);
    nlohmann::json get_taint_paths(const std::string& binary_hash, ea_t address);
    nlohmann::json get_community_info(const std::string& binary_hash, ea_t address);
    nlohmann::json get_security_analysis(const std::string& binary_hash, int limit = 50);
    nlohmann::json get_activity_analysis(const std::string& binary_hash, const std::string& activity_filter = "");
    nlohmann::json get_all_communities(const std::string& binary_hash);

private:
    GraphStore& m_store;

    std::string node_display_name(const graph_node_t* n) const;
};


bool ensure_function_indexed(const std::string& binary_hash, ea_t func_ea);
bool ensure_full_binary_index(const std::string& binary_hash,
                              StructureExtractor::progress_fn on_progress = nullptr,
                              bool* reindexed = nullptr);


void initialize(const std::string& binary_hash);
void save_graph(const std::string& binary_hash);
void load_graph(const std::string& binary_hash);

}
