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

namespace httplib { class Client; }
class settings_t;

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
    std::string  module_id;
    bool         legacy_binary_hash_alias = false;
    std::string  identity_source;
    node_type_t  node_type = node_type_t::FUNCTION;
    ea_t         address = BADADDR;
    uint64_t     rva = 0;
    bool         has_rva = false;
    std::string  address_key;
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
        {"module_id", n.module_id},
        {"legacy_binary_hash_alias", n.legacy_binary_hash_alias},
        {"identity_source", n.identity_source},
        {"node_type", node_type_str(n.node_type)},
        {"address", n.address}, {"rva", n.rva}, {"has_rva", n.has_rva},
        {"address_key", n.address_key}, {"name", n.name},
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
    n.module_id = j.value("module_id", n.binary_hash);
    n.legacy_binary_hash_alias = j.value("legacy_binary_hash_alias", false);
    n.identity_source = j.value("identity_source", "");
    if (n.module_id.empty() && !n.binary_hash.empty())
    {
        n.module_id = n.binary_hash;
        n.legacy_binary_hash_alias = true;
    }
    if (n.binary_hash.empty() || n.binary_hash != n.module_id)
        n.binary_hash = n.module_id;
    n.node_type = node_type_from_str(j.value("node_type", "FUNCTION"));
    n.address = j.value("address", ea_t(BADADDR));
    n.rva = j.value("rva", uint64_t(0));
    n.has_rva = j.value("has_rva", false);
    n.address_key = j.value("address_key", "");
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
    std::string module_id;
    bool        legacy_binary_hash_alias = false;
    int         source_id = 0;
    int         target_id = 0;
    edge_type_t edge_type = edge_type_t::CALLS;
    double      weight = 1.0;
};

inline void to_json(nlohmann::json& j, const graph_edge_t& e)
{
    j = {{"id", e.id}, {"binary_hash", e.binary_hash}, {"module_id", e.module_id},
         {"legacy_binary_hash_alias", e.legacy_binary_hash_alias},
         {"source_id", e.source_id}, {"target_id", e.target_id},
         {"edge_type", edge_type_str(e.edge_type)}, {"weight", e.weight}};
}

inline void from_json(const nlohmann::json& j, graph_edge_t& e)
{
    e.id = j.value("id", 0);
    e.binary_hash = j.value("binary_hash", "");
    e.module_id = j.value("module_id", e.binary_hash);
    e.legacy_binary_hash_alias = j.value("legacy_binary_hash_alias", false);
    if (e.module_id.empty() && !e.binary_hash.empty())
    {
        e.module_id = e.binary_hash;
        e.legacy_binary_hash_alias = true;
    }
    if (e.binary_hash.empty() || e.binary_hash != e.module_id)
        e.binary_hash = e.module_id;
    e.source_id = j.value("source_id", 0);
    e.target_id = j.value("target_id", 0);
    e.edge_type = edge_type_from_str(j.value("edge_type", "CALLS"));
    e.weight = j.value("weight", 1.0);
}

struct community_t
{
    int         id = 0;
    std::string binary_hash;
    std::string module_id;
    bool        legacy_binary_hash_alias = false;
    std::string label;
    std::string purpose;
    std::vector<int> member_ids;
};

inline void to_json(nlohmann::json& j, const community_t& c)
{
    j = {{"id", c.id}, {"binary_hash", c.binary_hash}, {"module_id", c.module_id},
         {"legacy_binary_hash_alias", c.legacy_binary_hash_alias},
         {"label", c.label}, {"purpose", c.purpose},
         {"member_ids", c.member_ids}};
}

inline void from_json(const nlohmann::json& j, community_t& c)
{
    c.id = j.value("id", 0);
    c.binary_hash = j.value("binary_hash", "");
    c.module_id = j.value("module_id", c.binary_hash);
    c.legacy_binary_hash_alias = j.value("legacy_binary_hash_alias", false);
    if (c.module_id.empty() && !c.binary_hash.empty())
    {
        c.module_id = c.binary_hash;
        c.legacy_binary_hash_alias = true;
    }
    if (c.binary_hash.empty() || c.binary_hash != c.module_id)
        c.binary_hash = c.module_id;
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


class VectorStore
{
public:
    struct search_result_t
    {
        int   node_id = 0;
        float score   = 0.0f;
    };

    void   add(int node_id, std::vector<float> embedding);
    void   remove(int node_id);
    bool   has(int node_id) const;
    size_t size() const;
    int    dimensions() const { return m_dimensions; }
    void   clear();

    std::vector<search_result_t> search(const std::vector<float>& query, int top_k) const;

    bool save_to_file(const std::string& path) const;
    bool load_from_file(const std::string& path);
    std::string get_embeddings_path(const std::string& binary_hash) const;

private:
    mutable std::mutex m_mtx;
    int m_dimensions = 0;
    std::unordered_map<int, std::vector<float>> m_embeddings;

    static float dot_product(const float* a, const float* b, int n);
    static void  l2_normalize(std::vector<float>& v);
};


class LocalVectorizer
{
public:
    static constexpr int DIMENSIONS = 768;

    void build(const std::vector<std::pair<int, std::string>>& documents);
    std::vector<float> vectorize(const std::string& text) const;
    bool is_built() const { return m_built; }

    bool save_to_file(const std::string& path) const;
    bool load_from_file(const std::string& path);
    std::string get_vectorizer_path(const std::string& binary_hash) const;

private:
    std::vector<float> m_idf;
    int  m_doc_count = 0;
    bool m_built     = false;

    static std::vector<std::string> tokenize(const std::string& text);
    static uint32_t hash_token(const std::string& token);
};


class EmbeddingClient
{
public:
    EmbeddingClient();

    bool is_available() const;
    int  dimensions() const { return m_dimensions; }

    std::vector<float>               embed_single(const std::string& text);
    std::vector<std::vector<float>>  embed_batch(const std::vector<std::string>& texts);

private:
    std::string m_api_host;
    std::string m_api_key;
    std::string m_model_name;
    int         m_dimensions  = 1536;
    int         m_batch_size  = 32;

    std::shared_ptr<httplib::Client> m_client;
    std::mutex m_client_mtx;

    void configure();
    std::shared_ptr<httplib::Client> get_client();
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
    bool save_to_file(const std::string& path, const std::string& binary_hash);
    bool load_from_file(const std::string& path);
    std::string get_graph_path(const std::string& binary_hash) const;

    // ---- Slice H2: incremental persistence -----------------------------------
    // Returns the count of dirty nodes flushed (no-op if path is empty / not dirty).
    int save_incremental(const std::string& binary_hash, const std::string& path);
    int dirty_count(const std::string& binary_hash) const;

    // ---- Slice H3: in-memory inverted indices --------------------------------
    // Maintained incrementally inside upsert_node. rebuild_inverted_indices
    // is a recovery path (e.g. after load_from_file).
    void rebuild_inverted_indices(const std::string& binary_hash);
    // JSON predicate spec: { "binary_hash": "..", "all_flags": [..],
    // "any_flags": [..], "all_apis": [..], "any_apis": [..],
    // "risk_levels": [..] }. AND across distinct keys, semantics-per-key.
    std::vector<graph_node_t*> filter_nodes(const std::string& binary_hash,
                                            const nlohmann::json& criteria);

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

    // H2: per-binary dirty node tracking.
    std::unordered_map<std::string, std::unordered_set<int>> m_dirty_nodes;
    // H3: inverted indices over node fields.
    //   m_flag_index: security_flag -> [node_id]
    //   m_api_index : api_name -> [node_id] (union of network/file/crypto/process apis)
    // The vectors are kept sorted+unique; modifications use erase-remove
    // to keep filter_nodes() O(matching) instead of O(all_nodes).
    std::unordered_map<std::string, std::vector<int>> m_flag_index;
    std::unordered_map<std::string, std::vector<int>> m_api_index;

    // Internal helpers (must be called with m_mtx held).
    void index_remove_node_locked(int node_id);
    void index_add_node_locked(const graph_node_t& node);
    static void vec_insert_unique(std::vector<int>& v, int id);
    static void vec_remove(std::vector<int>& v, int id);

public:
    struct addr_key_t
    {
        std::string module_id;
        node_type_t type;
        uint64_t canonical_addr = 0;
        bool has_rva = false;
        bool operator==(const addr_key_t& o) const
        {
            return module_id == o.module_id && type == o.type && canonical_addr == o.canonical_addr && has_rva == o.has_rva;
        }
    };
    struct addr_key_hash
    {
        size_t operator()(const addr_key_t& k) const
        {
            size_t h = std::hash<std::string>{}(k.module_id);
            h ^= std::hash<int>{}(static_cast<int>(k.type)) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint64_t>{}(k.canonical_addr) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<bool>{}(k.has_rva) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };
private:
    std::unordered_map<addr_key_t, int, addr_key_hash> m_addr_index;


    std::unordered_map<int, std::vector<int>> m_edges_from;
    std::unordered_map<int, std::vector<int>> m_edges_to;
    // H15: per-binary edge id list. Lets delete_graph rebuild edge indices in
    // O(surviving_edges) by only touching the surviving binaries' lists,
    // instead of O(all_edges).
    std::unordered_map<std::string, std::vector<int>> m_edges_by_binary;
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


struct query_cursor_t;

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

    // ---- Slice H5: cursor-aware overloads -----------------------------------
    // When `in_cursor` filters out a node by since_ms or seen_id, that node
    // is dropped from the response. On return, `out_cursor` carries the new
    // baseline (since_ms = max(updated_at), seen_node_ids merged with the
    // emitted set) and `out_has_more` reflects whether the limit/page truncated
    // a still-larger result set.
    nlohmann::json get_security_analysis(const std::string& binary_hash, int limit,
                                         const query_cursor_t& in_cursor,
                                         query_cursor_t& out_cursor, bool& out_has_more);
    nlohmann::json get_activity_analysis(const std::string& binary_hash,
                                         const std::string& activity_filter,
                                         const query_cursor_t& in_cursor,
                                         query_cursor_t& out_cursor, bool& out_has_more);
    nlohmann::json search_semantic(const std::string& binary_hash, const std::string& query,
                                   int limit,
                                   const query_cursor_t& in_cursor,
                                   query_cursor_t& out_cursor, bool& out_has_more);

private:
    GraphStore& m_store;

    std::string node_display_name(const graph_node_t* n) const;
};


bool ensure_function_indexed(const std::string& binary_hash, ea_t func_ea);
bool ensure_full_binary_index(const std::string& binary_hash,
                              StructureExtractor::progress_fn on_progress = nullptr,
                              bool* reindexed = nullptr);


VectorStore&     get_vector_store();
LocalVectorizer& get_local_vectorizer();

std::string build_embedding_text(const graph_node_t& node);

void index_embeddings(const std::string& binary_hash,
                      StructureExtractor::progress_fn on_progress = nullptr);

void save_vectors(const std::string& binary_hash);
void load_vectors(const std::string& binary_hash);


void initialize(const std::string& binary_hash);
void save_graph(const std::string& binary_hash);
void load_graph(const std::string& binary_hash);

// ---- Slice H4: aggregate externally-reachable entry enumeration ------------
struct external_entry_t
{
    ea_t        ea = BADADDR;
    std::string name;
    std::string category;   // e.g. "pe_export", "rpc_ndr", "com_idispatch",
                            //      "driver_dispatch", "winrt_factory",
                            //      "service_handler", "wsk_callback"
    std::string source;     // free-form provenance for the operator
};

std::vector<external_entry_t> extract_externally_reachable_entries();

nlohmann::json build_binary_capability_index(const std::vector<std::string>& filter_apis = {},
                                             size_t max_callsites_per_api = 64);

nlohmann::json extract_dispatch_tables(bool include_handler_code = false,
                                       size_t max_handler_code_len = 6000);

// ---- Slice H5: incremental cursor for delta queries ------------------------
struct query_cursor_t
{
    uint64_t           since_ms = 0;
    std::vector<int>   seen_node_ids;
};

// Encode/decode cursor as base64-encoded JSON. Returns empty string for an
// empty/default cursor.
std::string encode_cursor(const query_cursor_t& c);
bool        decode_cursor(const std::string& encoded, query_cursor_t& out);

}
