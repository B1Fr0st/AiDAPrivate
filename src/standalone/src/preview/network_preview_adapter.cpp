#include "network_preview_adapter.hpp"
#include "preview_fixture_controls.hpp"

#include "../core/network/network_view.hpp"
#include "../core/network/mitm_proxy.hpp"
#include "../core/network/burp/collaborator.hpp"
#include "../core/network/burp/comparer.hpp"
#include "../core/network/burp/jwt_lab.hpp"
#include "../core/network/burp/match_replace.hpp"
#include "../core/network/burp/sequencer.hpp"
#include "../core/network/burp/session_handler.hpp"
#include "../core/runtime/standalone_driver.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <regex>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida::preview::network {
namespace {
network_view::state_t* s_current_state = nullptr;
fixture_state_t s_pending_fixture = fixture_state_t::normal;
std::size_t s_pending_cardinality = 0;
bool s_pending_fixture_valid = false;
}

static void apply_fixture(network_view::state_t& state, fixture_state_t fixture,
    std::size_t cardinality);

namespace {

std::string s_receipt;

void copy_text(char* destination, size_t capacity, const char* value) {
    if (!destination || capacity == 0) return;
    std::snprintf(destination, capacity, "%s", value ? value : "");
}

}
}

namespace driver_bridge {

bool using_kernel_driver() { return true; }
bool refresh_heartbeat() { return true; }
uint32_t attached_pid() { return 6420; }

std::vector<net_connection_info_t> enumerate_connections(uint32_t filter_pid, uint32_t filter_protocol) {
    std::vector<net_connection_info_t> entries;
    auto append = [&](uint32_t pid, uint32_t protocol, uint32_t state, uint32_t local_port, uint32_t remote_port,
                      const uint8_t* local, const uint8_t* remote, const char* process) {
        if (filter_pid != 0 && pid != filter_pid) return;
        if (filter_protocol != 0 && protocol != filter_protocol) return;
        net_connection_info_t entry;
        entry.pid = pid;
        entry.protocol = protocol;
        entry.state = state;
        entry.local_port = local_port;
        entry.remote_port = remote_port;
        entry.address_family = 2;
        std::copy(local, local + 4, entry.local_addr);
        std::copy(remote, remote + 4, entry.remote_addr);
        std::snprintf(entry.process_path, sizeof(entry.process_path), "%s", process);
        entries.push_back(entry);
    };
    const uint8_t ide_local[4] = {10, 24, 7, 18};
    const uint8_t portal_remote[4] = {172, 67, 19, 44};
    const uint8_t loopback[4] = {127, 0, 0, 1};
    const uint8_t zero[4] = {};
    const uint8_t browser_remote[4] = {104, 18, 32, 47};
    append(6420, 6, 4, 51542, 443, ide_local, portal_remote, "C:\\AiDA\\AiDAStandalone.exe");
    append(9148, 6, 1, 8443, 0, loopback, zero, "C:\\AiDA\\AiDAProxy.exe");
    append(12064, 6, 4, 51618, 443, ide_local, browser_remote, "C:\\AiDA\\camoufox.exe");
    return entries;
}

bool start_capture(uint32_t, uint32_t, uint32_t, const uint8_t*, uint32_t) {
    aida::preview::network::record_receipt("Packet capture", "started");
    return true;
}

bool stop_capture() {
    aida::preview::network::record_receipt("Packet capture", "stopped");
    return true;
}

std::vector<captured_packet_t> get_captured_packets(uint32_t) { return {}; }

std::vector<dns_entry_t> get_dns_queries(uint32_t filter_pid) {
    std::vector<dns_entry_t> entries;
    dns_entry_t entry;
    entry.timestamp = aida::preview::network::monotonic_ms();
    entry.pid = filter_pid == 0 ? 12064 : filter_pid;
    entry.query_type = 1;
    entry.domain = "portal.aidapro.net";
    entry.resolved_addr[0] = 172;
    entry.resolved_addr[1] = 67;
    entry.resolved_addr[2] = 19;
    entry.resolved_addr[3] = 44;
    entry.ttl = 300;
    entries.push_back(std::move(entry));
    return entries;
}

bool add_filter_rule(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, const uint8_t*, const uint8_t*, uint32_t* out_rule_id) {
    static uint32_t next_rule = 200;
    if (out_rule_id) *out_rule_id = next_rule++;
    aida::preview::network::record_receipt("Network filter", "rule added");
    return true;
}

bool remove_filter_rule(uint32_t rule_id) {
    aida::preview::network::record_receipt("Network filter removed", std::to_string(rule_id));
    return true;
}

bool clear_filter_rules() {
    aida::preview::network::record_receipt("Network filters", "cleared");
    return true;
}

bool bw_monitor_op(uint32_t operation, uint32_t, bw_stats_t* out_stats) {
    if (out_stats) out_stats->active = operation == 0;
    aida::preview::network::record_receipt("Bandwidth monitor", operation == 0 ? "started" : "stopped");
    return true;
}

std::vector<bw_process_info_t> get_bw_per_process(uint32_t filter_pid) {
    std::vector<bw_process_info_t> entries;
    if (filter_pid == 0 || filter_pid == 12064)
        entries.push_back({12064, 3824910, 18742341, 18422, 29510, aida::preview::network::monotonic_ms()});
    if (filter_pid == 0 || filter_pid == 6420)
        entries.push_back({6420, 1245982, 5421870, 4211, 8094, aida::preview::network::monotonic_ms()});
    return entries;
}

}

namespace standalone_license {
bool is_valid() { return true; }
}

namespace protocol_parser {

detection_result detect_protocol(const uint8_t* data, size_t len,
                                 uint16_t source_port, uint16_t destination_port,
                                 uint32_t ip_protocol) {
    detection_result result;
    if (!data || len == 0) {
        result.label = ip_protocol == 17 ? "UDP" : "TCP";
        result.summary = "No payload";
        return result;
    }
    const std::string text(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data) + len);
    if (source_port == 53 || destination_port == 53) {
        result.protocol = detected_protocol_t::dns;
        result.label = "DNS";
        result.summary = "DNS query response";
    } else if (text.rfind("HTTP/", 0) == 0) {
        result.protocol = detected_protocol_t::http_response;
        result.label = "HTTP";
        result.summary = text.substr(0, text.find("\r\n"));
    } else if (text.rfind("GET ", 0) == 0 || text.rfind("POST ", 0) == 0 || text.rfind("PUT ", 0) == 0) {
        result.protocol = detected_protocol_t::http_request;
        result.label = "HTTP";
        result.summary = text.substr(0, text.find("\r\n"));
    } else if (data[0] == 0x16 && len >= 3) {
        result.protocol = detected_protocol_t::tls;
        result.label = "TLS";
        result.summary = "TLS handshake record";
    } else if (source_port == 443 || destination_port == 443) {
        result.protocol = detected_protocol_t::tls;
        result.label = "TLS";
        result.summary = "Encrypted application data";
    } else {
        result.label = ip_protocol == 17 ? "UDP" : "TCP";
        result.summary = std::to_string(len) + " payload bytes";
    }
    return result;
}

}

namespace aida::burp::collaborator {
namespace {

collaborator_config_t s_collaborator_config;
bool s_collaborator_running = true;
uint64_t s_collaborator_started = aida::preview::network::monotonic_ms() - 420000;
uint64_t s_collaborator_next_token = 4;
std::vector<token_info_t> s_collaborator_tokens = {
    { "aida-r3v-01", "aida-r3v-01.collab.aidapro.net", aida::preview::network::monotonic_ms() - 390000, aida::preview::network::monotonic_ms() - 12000, 2 },
    { "aida-r3v-02", "aida-r3v-02.collab.aidapro.net", aida::preview::network::monotonic_ms() - 240000, aida::preview::network::monotonic_ms() - 89000, 1 },
    { "aida-r3v-03", "aida-r3v-03.collab.aidapro.net", aida::preview::network::monotonic_ms() - 120000, 0, 0 }
};
std::vector<interaction_t> s_collaborator_interactions = {
    { 301, aida::preview::network::monotonic_ms() - 12000, "dns", "10.24.7.44", 5353, "aida-r3v-01", "A aida-r3v-01.collab.aidapro.net", {{"query_type", "A"}, {"resolver", "10.24.7.1"}}, "aida-r3v-01" },
    { 302, aida::preview::network::monotonic_ms() - 11300, "http", "10.24.7.44", 51822, "aida-r3v-01", "GET /probe HTTP/1.1\r\nHost: aida-r3v-01.collab.aidapro.net\r\n\r\n", {{"method", "GET"}, {"path", "/probe"}}, "aida-r3v-01" },
    { 303, aida::preview::network::monotonic_ms() - 89000, "smtp", "172.16.4.18", 49210, "aida-r3v-02", "MAIL FROM:<scanner@target.local>", {{"mail_from", "scanner@target.local"}}, "aida-r3v-02" }
};

}

bool start(const collaborator_config_t& config) {
    s_collaborator_config = config;
    s_collaborator_running = true;
    s_collaborator_started = aida::preview::network::monotonic_ms();
    aida::preview::network::record_receipt("Collaborator", "started on " + config.bind_ip);
    return true;
}

void stop() {
    s_collaborator_running = false;
    aida::preview::network::record_receipt("Collaborator", "stopped");
}

bool is_running() { return s_collaborator_running; }

status_t status() {
    status_t result;
    result.running = s_collaborator_running;
    result.http_alive = s_collaborator_running && s_collaborator_config.enable_http;
    result.dns_alive = s_collaborator_running && s_collaborator_config.enable_dns;
    result.smtp_alive = s_collaborator_running && s_collaborator_config.enable_smtp;
    result.bind_ip = s_collaborator_config.bind_ip.empty() ? "0.0.0.0" : s_collaborator_config.bind_ip;
    result.http_port = s_collaborator_config.http_port;
    result.dns_port = s_collaborator_config.dns_port;
    result.smtp_port = s_collaborator_config.smtp_port;
    result.public_host = s_collaborator_config.public_host.empty() ? "collab.aidapro.net" : s_collaborator_config.public_host;
    result.public_ip = s_collaborator_config.public_ip.empty() ? "127.0.0.1" : s_collaborator_config.public_ip;
    result.interaction_count = s_collaborator_interactions.size();
    result.token_count = s_collaborator_tokens.size();
    result.started_ms = s_collaborator_started;
    result.durable_state_path = "/aida-preview/state/collaborator.json";
    return result;
}

collaborator_config_t current_config() {
    if (s_collaborator_config.public_host.empty()) s_collaborator_config.public_host = "collab.aidapro.net";
    if (s_collaborator_config.public_ip.empty()) s_collaborator_config.public_ip = "127.0.0.1";
    return s_collaborator_config;
}

std::string generate_token() {
    const auto token_sequence = s_collaborator_next_token++;
    const std::string token = "aida-r3v-" + (token_sequence < 10 ? std::string("0") : std::string()) + std::to_string(token_sequence);
    s_collaborator_tokens.push_back({ token, token + ".collab.aidapro.net", aida::preview::network::monotonic_ms(), 0, 0 });
    aida::preview::network::record_receipt("Collaborator token", token);
    return token;
}

std::vector<token_info_t> list_tokens() { return s_collaborator_tokens; }

bool forget_token(const std::string& token) {
    const auto old_size = s_collaborator_tokens.size();
    s_collaborator_tokens.erase(std::remove_if(s_collaborator_tokens.begin(), s_collaborator_tokens.end(),
        [&](const auto& item) { return item.token == token; }), s_collaborator_tokens.end());
    return old_size != s_collaborator_tokens.size();
}

std::vector<interaction_t> snapshot_all(size_t max_entries) {
    const size_t count = max_entries == 0 ? s_collaborator_interactions.size() : std::min(max_entries, s_collaborator_interactions.size());
    return std::vector<interaction_t>(s_collaborator_interactions.end() - static_cast<ptrdiff_t>(count), s_collaborator_interactions.end());
}

bool get_interaction(uint64_t id, interaction_t& out) {
    for (const auto& interaction : s_collaborator_interactions) if (interaction.id == id) { out = interaction; return true; }
    return false;
}

void clear() {
    s_collaborator_interactions.clear();
    aida::preview::network::record_receipt("Collaborator interactions", "cleared");
}

std::string last_error() { return {}; }

}

namespace aida::burp::sequencer {
namespace {

uint64_t s_sequencer_next_id = 4;
uint64_t s_sequencer_next_instance_revision = 4;
uint64_t s_sequencer_generation = 1;
std::mutex s_sequencer_mutex;
std::string s_sequencer_error;
std::unordered_map<uint64_t, collection_config_t> s_sequencer_configs;
std::unordered_map<uint64_t, std::vector<std::string>> s_sequencer_samples;
std::vector<collection_status_t> s_sequencer_collections = {
    { 1, "https://portal.aidapro.net/login", "Session token", 200, 200, false, false, {}, aida::preview::network::monotonic_ms() - 300000, aida::preview::network::monotonic_ms() - 220000 },
    { 2, "https://sandbox.aidapro.net/api/csrf", "CSRF token", 146, 200, true, false, {}, aida::preview::network::monotonic_ms() - 97000, aida::preview::network::monotonic_ms() - 300 },
    { 3, "https://portal.aidapro.net/api/nonce", "API nonce", 82, 100, false, true, "Target returned 429 after 82 samples", aida::preview::network::monotonic_ms() - 180000, aida::preview::network::monotonic_ms() - 151000 }
};

std::vector<std::string> generated_samples(uint64_t id, size_t count);

void ensure_sequencer_identity() {
    for (size_t index = 0; index < s_sequencer_collections.size(); ++index) {
        auto& collection = s_sequencer_collections[index];
        if (collection.instance_revision == 0) collection.instance_revision = index + 1;
        if (s_sequencer_configs.find(collection.id) == s_sequencer_configs.end()) {
            collection_config_t config;
            config.url = collection.url;
            config.name = collection.name;
            config.target_count = collection.target;
            config.extract_regex = "([A-Za-z0-9_]+)";
            s_sequencer_configs.emplace(collection.id, std::move(config));
        }
        if (s_sequencer_samples.find(collection.id) == s_sequencer_samples.end()) {
            auto retained = generated_samples(collection.id, collection.collected);
            size_t retained_bytes = 0;
            for (const auto& sample : retained) retained_bytes += sample.size();
            collection.retained_sample_bytes = retained_bytes;
            s_sequencer_samples.emplace(collection.id, std::move(retained));
        }
    }
}

size_t retained_bytes_locked() {
    size_t bytes = 0;
    for (const auto& entry : s_sequencer_samples)
        for (const auto& sample : entry.second) bytes += sample.size();
    return bytes;
}

std::vector<std::string> generated_samples(uint64_t id, size_t count) {
    std::vector<std::string> values;
    values.reserve(count);
    for (size_t i = 0; i < count; ++i)
        values.push_back("tkn_" + std::to_string(id) + "_" + std::to_string(918273645ULL + i * 7919ULL));
    return values;
}

}

uint64_t start_collection(const collection_config_t& config) {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    ensure_sequencer_identity();
    if (config.target_count == 0 || config.target_count > max_target_samples ||
        config.concurrency == 0 || config.concurrency > max_collection_concurrency ||
        config.raw_request.size() > max_raw_request_bytes || config.extract_regex.empty() ||
        config.extract_regex.size() > max_extract_regex_bytes ||
        (config.url.empty() && config.host.empty())) {
        s_sequencer_error = "collection configuration exceeds the bounded Sequencer contract";
        return 0;
    }
    if (s_sequencer_collections.size() >= max_collection_count) {
        s_sequencer_error = "collection capacity 128 reached; delete a collection";
        return 0;
    }
    const uint64_t id = s_sequencer_next_id;
    const size_t retained_count = (std::min)(config.target_count, static_cast<size_t>(200));
    auto retained = generated_samples(id, retained_count);
    size_t retained_bytes = 0;
    for (const auto& sample : retained) retained_bytes += sample.size();
    if (retained_bytes_locked() > max_total_sample_bytes - retained_bytes) {
        s_sequencer_error = "retained sample capacity reached; delete a collection";
        return 0;
    }
    collection_status_t status;
    status.id = id;
    status.url = config.url;
    status.name = config.name;
    status.collected = retained_count;
    status.target = config.target_count;
    status.running = retained_count < config.target_count;
    status.started_ms = aida::preview::network::monotonic_ms();
    status.last_sample_ms = status.started_ms;
    status.retained_sample_bytes = retained_bytes;
    status.instance_revision = s_sequencer_next_instance_revision++;
    s_sequencer_collections.push_back(status);
    s_sequencer_configs[id] = config;
    s_sequencer_samples[id] = std::move(retained);
    ++s_sequencer_next_id;
    ++s_sequencer_generation;
    s_sequencer_error.clear();
    aida::preview::network::record_receipt("Sequencer collection", config.name.empty() ? config.url : config.name);
    return id;
}

bool stop_collection(uint64_t id) {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    ensure_sequencer_identity();
    for (auto& collection : s_sequencer_collections) if (collection.id == id) {
        collection.running = false;
        ++s_sequencer_generation;
        return true;
    }
    return false;
}

collection_status_t status(uint64_t id) {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    ensure_sequencer_identity();
    for (const auto& collection : s_sequencer_collections) if (collection.id == id) return collection;
    return {};
}

std::vector<std::string> samples(uint64_t id, size_t max_count) {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    ensure_sequencer_identity();
    const auto stored = s_sequencer_samples.find(id);
    size_t available = 0;
    for (const auto& collection : s_sequencer_collections)
        if (collection.id == id) available = collection.collected;
    const size_t take = max_count == 0 ? available : (std::min)(max_count, available);
    if (stored == s_sequencer_samples.end()) return generated_samples(id, take);
    const size_t stored_take = (std::min)(take, stored->second.size());
    return std::vector<std::string>(stored->second.end() - static_cast<ptrdiff_t>(stored_take),
        stored->second.end());
}

analysis_result_t analyze(uint64_t id) {
    analysis_result_t result;
    result.collection_id = id;
    result.samples_count = status(id).collected;
    result.token_length_mode = 24;
    result.min_token_length = 24;
    result.max_token_length = 24;
    result.alphabet_size = 62;
    result.total_bits = 143;
    result.shannon_entropy_bits = 5.91;
    result.min_entropy_bits_per_symbol = 5.42;
    result.chi_square = 51.3;
    result.chi_square_p_value = 0.71;
    result.monobit_p_value = 0.64;
    result.poker_p_value = 0.58;
    result.runs_p_value = 0.76;
    result.long_run_p_value = 0.88;
    result.maurer_universal = 6.14;
    result.autocorrelation = 0.012;
    result.serial_correlation = -0.008;
    result.compression_ratio = 0.98;
    result.passes_fips_140_2 = true;
    result.fips_assessment = "All FIPS 140-2 statistical checks passed";
    result.nist_sp800_90b_assessment = "No material bias detected in the preview sample";
    result.confidence_score = 0.93;
    result.confidence_label = "High";
    result.valid = id != 0;
    result.verdict = "Strong unpredictability";
    result.notes = "Deterministic preview dataset representing a high-quality token source";
    aida::preview::network::record_receipt("Sequencer analysis", std::to_string(id));
    return result;
}

analysis_result_t analyze(uint64_t id, const analysis_config_t&) { return analyze(id); }
std::vector<collection_status_t> list_collections() { return snapshot_collections().collections; }

uint64_t registry_generation() {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    return s_sequencer_generation;
}

registry_snapshot_t snapshot_collections() {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    ensure_sequencer_identity();
    registry_snapshot_t snapshot;
    snapshot.generation = s_sequencer_generation;
    snapshot.collections = s_sequencer_collections;
    snapshot.capacity.collection_count = snapshot.collections.size();
    snapshot.capacity.retained_sample_bytes = retained_bytes_locked();
    std::sort(snapshot.collections.begin(), snapshot.collections.end(),
        [](const auto& left, const auto& right) { return left.id < right.id; });
    return snapshot;
}

bool delete_collection(uint64_t id) {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    ensure_sequencer_identity();
    const auto old_size = s_sequencer_collections.size();
    s_sequencer_collections.erase(std::remove_if(s_sequencer_collections.begin(), s_sequencer_collections.end(),
        [id](const auto& collection) { return collection.id == id; }), s_sequencer_collections.end());
    const bool removed = old_size != s_sequencer_collections.size();
    if (removed) {
        s_sequencer_configs.erase(id);
        s_sequencer_samples.erase(id);
        ++s_sequencer_generation;
    }
    return removed;
}

bool delete_collection_exact(uint64_t id, uint64_t started_ms, uint64_t instance_revision) {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    ensure_sequencer_identity();
    const auto found = std::find_if(s_sequencer_collections.begin(), s_sequencer_collections.end(),
        [&](const auto& collection) {
            return collection.id == id && collection.started_ms == started_ms &&
                collection.instance_revision == instance_revision;
        });
    if (found == s_sequencer_collections.end()) {
        s_sequencer_error = "collection changed after delete review";
        return false;
    }
    s_sequencer_collections.erase(found);
    s_sequencer_configs.erase(id);
    s_sequencer_samples.erase(id);
    ++s_sequencer_generation;
    return true;
}

nlohmann::json export_json() {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    ensure_sequencer_identity();
    nlohmann::json root;
    root["version"] = 1;
    root["limits"] = {
        {"collections", max_collection_count},
        {"samples_per_collection", max_target_samples},
        {"sample_bytes", max_sample_bytes},
        {"collection_sample_bytes", max_collection_sample_bytes},
        {"total_sample_bytes", max_total_sample_bytes}
    };
    nlohmann::json rows = nlohmann::json::array();
    auto collections = s_sequencer_collections;
    std::sort(collections.begin(), collections.end(),
        [](const auto& left, const auto& right) { return left.id < right.id; });
    for (const auto& collection : collections) {
        const auto config = s_sequencer_configs.find(collection.id);
        const auto retained = s_sequencer_samples.find(collection.id);
        if (config == s_sequencer_configs.end() || retained == s_sequencer_samples.end()) continue;
        nlohmann::json samples_json = nlohmann::json::array();
        for (const auto& sample : retained->second)
            samples_json.push_back(std::vector<uint8_t>(sample.begin(), sample.end()));
        rows.push_back({
            {"id", collection.id}, {"name", collection.name}, {"url", config->second.url},
            {"raw_request", config->second.raw_request}, {"use_tls", config->second.use_tls},
            {"host", config->second.host}, {"port", config->second.port},
            {"extract_regex", config->second.extract_regex},
            {"capture_group", config->second.capture_group},
            {"target_count", config->second.target_count},
            {"concurrency", config->second.concurrency}, {"throttle_ms", config->second.throttle_ms},
            {"started_ms", collection.started_ms}, {"last_sample_ms", collection.last_sample_ms},
            {"running", collection.running}, {"error", collection.error},
            {"error_message", collection.error_message}, {"samples", std::move(samples_json)}
        });
    }
    root["collections"] = std::move(rows);
    return root;
}

bool import_json(const nlohmann::json& document, bool replace_existing) {
    struct staged_t {
        collection_status_t status;
        collection_config_t config;
        std::vector<std::string> samples;
    };
    if (!document.is_object() || document.value("version", 0) != 1 ||
        !document.contains("collections") || !document["collections"].is_array() ||
        document["collections"].size() > max_collection_count) {
        std::lock_guard<std::mutex> lock(s_sequencer_mutex);
        s_sequencer_error = "sequencer_import_invalid_schema_or_collection_capacity";
        return false;
    }
    std::vector<staged_t> staged;
    std::unordered_set<uint64_t> imported_ids;
    size_t staged_bytes = 0;
    try {
        staged.reserve(document["collections"].size());
        for (const auto& row : document["collections"]) {
            if (!row.is_object() || !row.contains("id") || !row["id"].is_number_unsigned() ||
                !row.contains("samples") || !row["samples"].is_array())
                throw std::invalid_argument("sequencer_import_invalid_collection");
            staged_t item;
            item.status.id = row["id"].get<uint64_t>();
            if (item.status.id == 0 || item.status.id == UINT64_MAX ||
                !imported_ids.insert(item.status.id).second)
                throw std::invalid_argument("sequencer_import_duplicate_or_zero_collection_id");
            item.status.name = row.value("name", std::string());
            item.status.url = row.value("url", std::string());
            item.config.name = item.status.name;
            item.config.url = item.status.url;
            item.config.use_tls = row.value("use_tls", true);
            item.config.host = row.value("host", std::string());
            item.config.port = row.value("port", static_cast<uint16_t>(443));
            item.config.extract_regex = row.value("extract_regex", std::string());
            item.config.capture_group = row.value("capture_group", 1);
            item.config.target_count = row.value("target_count", static_cast<size_t>(0));
            item.config.concurrency = row.value("concurrency", static_cast<size_t>(0));
            item.config.throttle_ms = row.value("throttle_ms", static_cast<size_t>(0));
            if (!row.contains("raw_request") || !row["raw_request"].is_array())
                throw std::invalid_argument("sequencer_import_raw_request_not_byte_array");
            const auto request = row["raw_request"].get<std::vector<uint8_t>>();
            item.config.raw_request.assign(request.begin(), request.end());
            if (item.config.target_count == 0 || item.config.target_count > max_target_samples ||
                item.config.concurrency == 0 || item.config.concurrency > max_collection_concurrency ||
                item.config.raw_request.size() > max_raw_request_bytes ||
                item.config.extract_regex.empty() || item.config.extract_regex.size() > max_extract_regex_bytes ||
                (item.config.url.empty() && item.config.host.empty()) ||
                row["samples"].size() > item.config.target_count)
                throw std::invalid_argument("sequencer_import_collection_exceeds_runtime_contract");
            size_t collection_bytes = 0;
            item.samples.reserve(row["samples"].size());
            for (const auto& encoded : row["samples"]) {
                if (!encoded.is_array()) throw std::invalid_argument("sequencer_import_sample_not_byte_array");
                const auto bytes = encoded.get<std::vector<uint8_t>>();
                if (bytes.empty() || bytes.size() > max_sample_bytes ||
                    collection_bytes > max_collection_sample_bytes - bytes.size() ||
                    staged_bytes > max_total_sample_bytes - bytes.size())
                    throw std::invalid_argument("sequencer_import_sample_capacity_exceeded");
                item.samples.emplace_back(bytes.begin(), bytes.end());
                collection_bytes += bytes.size();
                staged_bytes += bytes.size();
            }
            item.status.collected = item.samples.size();
            item.status.target = item.config.target_count;
            item.status.started_ms = row.value("started_ms", static_cast<uint64_t>(0));
            item.status.last_sample_ms = row.value("last_sample_ms", static_cast<uint64_t>(0));
            item.status.error = row.value("error", false);
            item.status.error_message = row.value("error_message", std::string());
            if (row.value("running", false)) {
                item.status.error = true;
                item.status.error_message = "restored_collection_was_running_and_requires_explicit_restart";
            }
            item.status.running = false;
            item.status.retained_sample_bytes = collection_bytes;
            staged.push_back(std::move(item));
        }
    } catch (const std::exception& exception) {
        std::lock_guard<std::mutex> lock(s_sequencer_mutex);
        s_sequencer_error = exception.what();
        return false;
    }

    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    ensure_sequencer_identity();
    try {
        auto next_collections = replace_existing
            ? std::vector<collection_status_t>() : s_sequencer_collections;
        auto next_configs = replace_existing
            ? std::unordered_map<uint64_t, collection_config_t>() : s_sequencer_configs;
        auto next_samples = replace_existing
            ? std::unordered_map<uint64_t, std::vector<std::string>>() : s_sequencer_samples;
        const size_t existing_bytes = replace_existing ? 0 : retained_bytes_locked();
        if (next_collections.size() > max_collection_count - staged.size() ||
            existing_bytes > max_total_sample_bytes - staged_bytes) {
            s_sequencer_error = "sequencer_import_collection_or_sample_capacity_exceeded";
            return false;
        }
        uint64_t next_id = replace_existing ? 1 : s_sequencer_next_id;
        uint64_t next_instance_revision = s_sequencer_next_instance_revision;
        for (auto& item : staged) {
            if (next_configs.find(item.status.id) != next_configs.end()) {
                s_sequencer_error = "sequencer_import_collection_identity_conflict";
                return false;
            }
            item.status.instance_revision = next_instance_revision++;
            next_id = (std::max)(next_id, item.status.id + 1);
            next_collections.push_back(item.status);
            next_configs.emplace(item.status.id, std::move(item.config));
            next_samples.emplace(item.status.id, std::move(item.samples));
        }
        s_sequencer_collections.swap(next_collections);
        s_sequencer_configs.swap(next_configs);
        s_sequencer_samples.swap(next_samples);
        s_sequencer_next_id = next_id;
        s_sequencer_next_instance_revision = next_instance_revision;
    } catch (const std::exception& exception) {
        s_sequencer_error = std::string("sequencer_import_commit_failed: ") + exception.what();
        return false;
    }
    ++s_sequencer_generation;
    s_sequencer_error.clear();
    return true;
}

std::string last_error() {
    std::lock_guard<std::mutex> lock(s_sequencer_mutex);
    return s_sequencer_error;
}

}

namespace aida::burp::comparer {
namespace {

uint64_t s_comparer_next_id = 3;
std::vector<slot_t> s_comparer_slots = {
    { 1, "Original response", std::vector<uint8_t>({'H','T','T','P','/','1','.','1',' ','2','0','0',' ','O','K','\n','R','o','l','e',':',' ','u','s','e','r','\n','F','e','a','t','u','r','e',':',' ','r','e','a','d'}), "proxy #2041", aida::preview::network::monotonic_ms() - 60000 },
    { 2, "Modified response", std::vector<uint8_t>({'H','T','T','P','/','1','.','1',' ','2','0','0',' ','O','K','\n','R','o','l','e',':',' ','a','d','m','i','n','\n','F','e','a','t','u','r','e',':',' ','w','r','i','t','e'}), "repeater #3001", aida::preview::network::monotonic_ms() - 45000 }
};

}

uint64_t add_slot(const slot_t& source) {
    slot_t slot = source;
    slot.id = s_comparer_next_id++;
    slot.created_ms = aida::preview::network::monotonic_ms();
    s_comparer_slots.push_back(slot);
    return slot.id;
}

uint64_t add_slot_from_bytes(const std::string& label, const std::vector<uint8_t>& data, const std::string& source_hint) {
    return add_slot({ 0, label.empty() ? "Untitled" : label, data, source_hint, 0 });
}

bool add_slot_from_file(const std::string& label, const std::string& path) {
    if (path.empty()) return false;
    const std::string fixture = "MZ preview PE payload\n.text  RVA 00001000\n.rdata RVA 00009000\n";
    add_slot_from_bytes(label.empty() ? "Preview file" : label, std::vector<uint8_t>(fixture.begin(), fixture.end()), path);
    aida::preview::network::record_receipt("Comparer file slot", path);
    return true;
}

std::vector<slot_t> list_slots() { return s_comparer_slots; }

bool get_slot(uint64_t id, slot_t& out) {
    for (const auto& slot : s_comparer_slots) if (slot.id == id) { out = slot; return true; }
    return false;
}

void clear_slots() { s_comparer_slots.clear(); }

bool remove_slot(uint64_t id) {
    const auto old_size = s_comparer_slots.size();
    s_comparer_slots.erase(std::remove_if(s_comparer_slots.begin(), s_comparer_slots.end(),
        [id](const auto& slot) { return slot.id == id; }), s_comparer_slots.end());
    return old_size != s_comparer_slots.size();
}

std::vector<diff_block_t> compute_diff_with_stats(uint64_t slot_a, uint64_t slot_b, diff_mode_t, diff_stats_t& stats) {
    slot_t a;
    slot_t b;
    if (!get_slot(slot_a, a) || !get_slot(slot_b, b)) return {};
    stats = {};
    stats.a_size = a.data.size();
    stats.b_size = b.data.size();
    size_t prefix = 0;
    while (prefix < a.data.size() && prefix < b.data.size() && a.data[prefix] == b.data[prefix]) ++prefix;
    size_t suffix = 0;
    while (suffix + prefix < a.data.size() && suffix + prefix < b.data.size() &&
           a.data[a.data.size() - 1 - suffix] == b.data[b.data.size() - 1 - suffix]) ++suffix;
    std::vector<diff_block_t> blocks;
    if (prefix > 0) { blocks.push_back({diff_block_t::kind_t::equal, 0, prefix, 0, prefix}); ++stats.equal_runs; stats.bytes_equal += prefix; }
    const size_t a_end = a.data.size() - suffix;
    const size_t b_end = b.data.size() - suffix;
    if (a_end > prefix || b_end > prefix) {
        blocks.push_back({diff_block_t::kind_t::replace, prefix, a_end, prefix, b_end});
        ++stats.replace_runs;
        stats.bytes_replaced = std::max(a_end - prefix, b_end - prefix);
    }
    if (suffix > 0) { blocks.push_back({diff_block_t::kind_t::equal, a_end, a.data.size(), b_end, b.data.size()}); ++stats.equal_runs; stats.bytes_equal += suffix; }
    stats.window_used = std::max(a.data.size(), b.data.size());
    aida::preview::network::record_receipt("Comparer diff", std::to_string(slot_a) + " vs " + std::to_string(slot_b));
    return blocks;
}

std::vector<diff_block_t> compute_diff(uint64_t slot_a, uint64_t slot_b, diff_mode_t mode) {
    diff_stats_t stats;
    return compute_diff_with_stats(slot_a, slot_b, mode, stats);
}

std::string last_error() { return {}; }

}

namespace aida::burp::session_handler {
namespace {

uint64_t s_session_next_macro = 3;
uint64_t s_session_next_rule = 3;
std::vector<macro_t> s_session_macros = {
    { 1, "Refresh analyst session", { { "Fetch CSRF", "https", "portal.aidapro.net", 443,
        std::vector<uint8_t>({'G','E','T',' ','/','l','o','g','i','n',' ','H','T','T','P','/','1','.','1','\r','\n','\r','\n'}), 15000,
        { { "csrf", "body", "name=\\\"csrf\\\" value=\\\"([^\\\"]+)", 1 } } } },
      {{"csrf", "preview-csrf-7f32"}}, aida::preview::network::monotonic_ms() - 80000, true },
    { 2, "Acquire API token", { { "Token endpoint", "https", "portal.aidapro.net", 443,
        std::vector<uint8_t>({'P','O','S','T',' ','/','a','p','i','/','t','o','k','e','n',' ','H','T','T','P','/','1','.','1','\r','\n','\r','\n'}), 15000,
        { { "access_token", "json", "access_token", 1 } } } },
      {{"access_token", "preview-token-redacted"}}, aida::preview::network::monotonic_ms() - 42000, true }
};
std::vector<session_rule_t> s_session_rules = {
    { 1, "Refresh on unauthorized", sh_match_t::response_status, {}, 401, 1, true, true, true, true },
    { 2, "Refresh protected API", sh_match_t::url_regex, "/api/v2/.*", 0, 2, false, true, false, true }
};

}

bool initialize() { return true; }
void shutdown() {}
uint64_t add_macro(macro_t macro) { macro.id = s_session_next_macro++; s_session_macros.push_back(macro); return macro.id; }
bool remove_macro(uint64_t id) { const auto n=s_session_macros.size(); s_session_macros.erase(std::remove_if(s_session_macros.begin(),s_session_macros.end(),[id](const auto& v){return v.id==id;}),s_session_macros.end()); return n!=s_session_macros.size(); }
bool update_macro(const macro_t& source) { for(auto& macro:s_session_macros) if(macro.id==source.id){macro=source;return true;} return false; }
std::vector<macro_t> list_macros() { return s_session_macros; }
bool get_macro(uint64_t id, macro_t& out) { for(const auto& macro:s_session_macros) if(macro.id==id){out=macro;return true;} return false; }

bool run_macro(uint64_t id, std::map<std::string, std::string>& values) {
    for (auto& macro : s_session_macros) if (macro.id == id) {
        values = macro.last_extracted_values;
        if (values.empty()) values["session"] = "preview-session-refreshed";
        macro.last_extracted_values = values;
        macro.last_run_ms = aida::preview::network::monotonic_ms();
        macro.ok_last_run = true;
        aida::preview::network::record_receipt("Session macro", macro.name);
        return true;
    }
    return false;
}

uint64_t add_rule(session_rule_t rule) { rule.id=s_session_next_rule++; s_session_rules.push_back(rule); return rule.id; }
bool remove_rule(uint64_t id) { const auto n=s_session_rules.size(); s_session_rules.erase(std::remove_if(s_session_rules.begin(),s_session_rules.end(),[id](const auto& v){return v.id==id;}),s_session_rules.end()); return n!=s_session_rules.size(); }
bool update_rule(const session_rule_t& source) { for(auto& rule:s_session_rules) if(rule.id==source.id){rule=source;return true;} return false; }
std::vector<session_rule_t> list_rules() { return s_session_rules; }

bool apply_rules(std::vector<uint8_t>& raw_request, const std::string& url, int last_status) {
    std::string request(raw_request.begin(), raw_request.end());
    bool changed = false;
    for (const auto& rule : s_session_rules) {
        if (!rule.active) continue;
        bool matched = false;
        try {
            if (rule.match == sh_match_t::response_status) matched = last_status == rule.match_status;
            else if (rule.match == sh_match_t::url_regex) matched = std::regex_search(url, std::regex(rule.match_pattern));
            else matched = std::regex_search(request, std::regex(rule.match_pattern));
        } catch (...) {
            continue;
        }
        if (!matched) continue;
        std::map<std::string, std::string> values;
        if (!run_macro(rule.macro_id, values)) continue;
        for (const auto& [name, value] : values) {
            const std::string marker = "${" + name + "}";
            size_t position = 0;
            while ((position = request.find(marker, position)) != std::string::npos) {
                request.replace(position, marker.size(), value);
                position += value.size();
                changed = true;
            }
        }
    }
    if (changed) raw_request.assign(request.begin(), request.end());
    return true;
}

const char* match_label(sh_match_t match) {
    switch (match) {
    case sh_match_t::url_regex: return "URL regex";
    case sh_match_t::response_status: return "Response status";
    case sh_match_t::response_regex: return "Response regex";
    }
    return "URL regex";
}

bool parse_match(const std::string& value, sh_match_t& output) {
    for (int i = 0; i <= static_cast<int>(sh_match_t::response_regex); ++i) {
        const auto match = static_cast<sh_match_t>(i);
        if (value == match_label(match)) { output = match; return true; }
    }
    return false;
}

std::string storage_path_macros() { return "/aida-preview/state/session-macros.json"; }
std::string storage_path_rules() { return "/aida-preview/state/session-rules.json"; }
bool save_to_disk() { aida::preview::network::record_receipt("Session handling", "saved to preview state"); return true; }
bool load_from_disk() { return initialize(); }

nlohmann::json export_json() {
    nlohmann::json document;
    document["macros"] = nlohmann::json::array();
    document["rules"] = nlohmann::json::array();
    for (const auto& macro : s_session_macros) document["macros"].push_back({{"id",macro.id},{"name",macro.name},{"steps",macro.steps.size()},{"last_run_ms",macro.last_run_ms},{"ok",macro.ok_last_run}});
    for (const auto& rule : s_session_rules) document["rules"].push_back({{"id",rule.id},{"name",rule.name},{"match",match_label(rule.match)},{"pattern",rule.match_pattern},{"status",rule.match_status},{"macro_id",rule.macro_id},{"active",rule.active}});
    return document;
}

bool import_json(const nlohmann::json& document, bool replace_existing) {
    if (!document.is_object()) return false;
    if (replace_existing) { s_session_macros.clear(); s_session_rules.clear(); }
    if (document.contains("macros") && document["macros"].is_array()) {
        for (const auto& item : document["macros"]) { macro_t macro; macro.name=item.value("name","Imported macro"); add_macro(std::move(macro)); }
    }
    if (document.contains("rules") && document["rules"].is_array()) {
        for (const auto& item : document["rules"]) { session_rule_t rule; rule.name=item.value("name","Imported rule"); rule.match_pattern=item.value("pattern",""); rule.match_status=item.value("status",0); rule.macro_id=item.value("macro_id",0ULL); rule.active=item.value("active",true); parse_match(item.value("match","URL regex"),rule.match); add_rule(std::move(rule)); }
    }
    return true;
}

std::string last_error() { return {}; }

}

namespace aida::burp::jwt_lab {
namespace {

std::vector<crack_status_t> s_jwt_cracks;
uint64_t s_jwt_next_crack = 1;
std::string s_jwt_error;

std::string join_token(const nlohmann::json& header, const nlohmann::json& payload, const std::string& signature) {
    return base64url_encode(header.dump()) + "." + base64url_encode(payload.dump()) + "." + signature;
}

}

bool initialize() { s_jwt_error.clear(); return true; }
void shutdown() { s_jwt_cracks.clear(); }

std::string base64url_encode(const uint8_t* data, size_t len) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result;
    result.reserve((len * 4 + 2) / 3);
    uint32_t buffer = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            result.push_back(alphabet[(buffer >> bits) & 0x3f]);
        }
    }
    if (bits > 0) result.push_back(alphabet[(buffer << (6 - bits)) & 0x3f]);
    return result;
}

std::string base64url_encode(const std::string& data) {
    return base64url_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

bool base64url_decode(const std::string& input, std::vector<uint8_t>& output) {
    output.clear();
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : input) {
        int value = -1;
        if (c >= 'A' && c <= 'Z') value = c - 'A';
        else if (c >= 'a' && c <= 'z') value = c - 'a' + 26;
        else if (c >= '0' && c <= '9') value = c - '0' + 52;
        else if (c == '-' || c == '+') value = 62;
        else if (c == '_' || c == '/') value = 63;
        else if (c == '=') break;
        else return false;
        buffer = (buffer << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
        }
    }
    return true;
}

jwt_parsed_t decode(const std::string& token) {
    jwt_parsed_t parsed;
    parsed.raw = token;
    const size_t first = token.find('.');
    const size_t second = first == std::string::npos ? std::string::npos : token.find('.', first + 1);
    if (first == std::string::npos || second == std::string::npos) {
        s_jwt_error = "Token must contain three segments";
        return parsed;
    }
    parsed.header_b64 = token.substr(0, first);
    parsed.payload_b64 = token.substr(first + 1, second - first - 1);
    parsed.signature_b64 = token.substr(second + 1);
    std::vector<uint8_t> header_bytes;
    std::vector<uint8_t> payload_bytes;
    if (!base64url_decode(parsed.header_b64, header_bytes) || !base64url_decode(parsed.payload_b64, payload_bytes)) {
        s_jwt_error = "Invalid base64url segment";
        return parsed;
    }
    try {
        parsed.header = nlohmann::json::parse(std::string(header_bytes.begin(), header_bytes.end()));
        parsed.payload = nlohmann::json::parse(std::string(payload_bytes.begin(), payload_bytes.end()));
        parsed.alg = parsed.header.value("alg", "unknown");
        parsed.kid = parsed.header.value("kid", "");
        parsed.valid_structure = parsed.header.is_object() && parsed.payload.is_object();
        s_jwt_error.clear();
    } catch (const std::exception& exception) {
        s_jwt_error = exception.what();
    }
    return parsed;
}

std::string forge(const jwt_forge_input_t& input) {
    nlohmann::json header = input.header.is_object() ? input.header : nlohmann::json::object();
    header["alg"] = input.alg.empty() ? "HS256" : input.alg;
    const std::string signature = input.alg == "none" ? std::string() : base64url_encode("preview-signature-" + input.alg);
    s_jwt_error.clear();
    aida::preview::network::record_receipt("JWT forged", header.value("alg", "unknown"));
    return join_token(header, input.payload.is_object() ? input.payload : nlohmann::json::object(), signature);
}

bool verify_hmac(const std::string& token, const std::string& secret) { return decode(token).valid_structure && !secret.empty(); }
bool verify_rsa(const std::string& token, const std::string& public_key) { return decode(token).valid_structure && public_key.find("PUBLIC KEY") != std::string::npos; }
bool verify_ecdsa(const std::string& token, const std::string& public_key) { return verify_rsa(token, public_key); }

uint64_t start_crack(const crack_config_t& config) {
    crack_status_t status;
    status.id = s_jwt_next_crack++;
    status.attempts = std::min<size_t>(config.max_attempts, 18432);
    status.running = false;
    status.secret_found = config.custom_words.empty() ? "preview-secret" : config.custom_words.front();
    s_jwt_cracks.push_back(status);
    return status.id;
}

crack_status_t crack_status(uint64_t id) { for (const auto& status : s_jwt_cracks) if (status.id == id) return status; return {}; }
void crack_stop(uint64_t id) { for (auto& status : s_jwt_cracks) if (status.id == id) status.running = false; }
std::vector<crack_status_t> list_cracks() { return s_jwt_cracks; }

std::vector<std::string> attack_alg_none(const std::string& token) {
    auto parsed = decode(token);
    if (!parsed.valid_structure) return {};
    parsed.header["alg"] = "none";
    return { join_token(parsed.header, parsed.payload, ""), join_token(parsed.header, parsed.payload, "AA") };
}

std::vector<std::string> attack_alg_confusion(const std::string& token, const std::string&) {
    auto parsed = decode(token);
    if (!parsed.valid_structure) return {};
    parsed.header["alg"] = "HS256";
    return { join_token(parsed.header, parsed.payload, base64url_encode("rsa-as-hmac")) };
}

std::vector<std::string> attack_kid_traversal(const std::string& token) {
    auto parsed = decode(token);
    if (!parsed.valid_structure) return {};
    parsed.header["kid"] = "../../../../dev/null";
    return { join_token(parsed.header, parsed.payload, base64url_encode("kid-traversal")) };
}

std::vector<std::string> attack_jku_injection(const std::string& token, const std::string& url) {
    auto parsed = decode(token);
    if (!parsed.valid_structure) return {};
    parsed.header["jku"] = url.empty() ? "https://collab.aidapro.net/jwks.json" : url;
    return { join_token(parsed.header, parsed.payload, base64url_encode("jku-injection")) };
}

std::vector<std::string> attack_signature_strip(const std::string& token) {
    auto parsed = decode(token);
    if (!parsed.valid_structure) return {};
    return { join_token(parsed.header, parsed.payload, ""), join_token(parsed.header, parsed.payload, "AA") };
}

std::string last_error() { return s_jwt_error; }

}

namespace aida::burp::match_replace {
namespace {

uint64_t s_match_next_id = 4;
std::string s_match_error;
std::vector<rule_t> s_match_rules;

bool applies_to(const rule_t& rule, match_kind_t target, const std::string& host, const std::string& scheme) {
    return rule.active && (rule.target == match_kind_t::all || rule.target == target) &&
           (rule.host_filter.empty() || host.find(rule.host_filter) != std::string::npos) &&
           (rule.scheme_filter.empty() || rule.scheme_filter == scheme);
}

}

bool initialize() {
    if (s_match_rules.empty()) {
        s_match_rules = {
            {1, "Remove telemetry headers", match_kind_t::request_headers, "^X-AiDA-Telemetry:.*$", "", true, true, true, "", "https", 18},
            {2, "Route sandbox API", match_kind_t::request_url, "portal\\.aidapro\\.net/api", "sandbox.aidapro.net/api", true, false, true, "portal.aidapro.net", "https", 7},
            {3, "Reveal feature flags", match_kind_t::response_body, "\"enabled\":false", "\"enabled\":true", false, false, false, "sandbox.aidapro.net", "https", 0}
        };
    }
    s_match_error.clear();
    return true;
}

void shutdown() {}
uint64_t add(rule_t rule) { rule.id = s_match_next_id++; s_match_rules.push_back(rule); return rule.id; }
bool update(const rule_t& source) { for (auto& rule : s_match_rules) if (rule.id == source.id) { rule = source; return true; } return false; }
bool remove(uint64_t id) { const auto size=s_match_rules.size(); s_match_rules.erase(std::remove_if(s_match_rules.begin(),s_match_rules.end(),[id](const auto& rule){return rule.id==id;}),s_match_rules.end()); return size!=s_match_rules.size(); }
std::vector<rule_t> list() { return s_match_rules; }
void clear() { s_match_rules.clear(); }

bool move(uint64_t id, int delta) {
    const auto it = std::find_if(s_match_rules.begin(), s_match_rules.end(), [id](const auto& rule){ return rule.id == id; });
    if (it == s_match_rules.end() || delta == 0) return false;
    const ptrdiff_t current = std::distance(s_match_rules.begin(), it);
    const ptrdiff_t target = std::clamp<ptrdiff_t>(current + (delta < 0 ? -1 : 1), 0, static_cast<ptrdiff_t>(s_match_rules.size() - 1));
    if (current == target) return false;
    std::iter_swap(s_match_rules.begin() + current, s_match_rules.begin() + target);
    return true;
}

bool test_rule(const rule_t& rule, const std::string& sample, std::string& output) {
    try {
        if (rule.regex) {
            auto flags = std::regex_constants::ECMAScript;
            if (rule.case_insensitive) flags |= std::regex_constants::icase;
            output = std::regex_replace(sample, std::regex(rule.match_regex, flags), rule.replacement);
        } else {
            output = sample;
            size_t position = 0;
            while (!rule.match_regex.empty() && (position = output.find(rule.match_regex, position)) != std::string::npos) {
                output.replace(position, rule.match_regex.size(), rule.replacement);
                position += rule.replacement.size();
            }
        }
        s_match_error.clear();
        return true;
    } catch (const std::exception& exception) {
        s_match_error = exception.what();
        return false;
    }
}

bool apply_text(std::string& text, match_kind_t target, const std::string& host, const std::string& scheme, size_t* rules_applied) {
    size_t applied = 0;
    for (auto& rule : s_match_rules) {
        if (!applies_to(rule, target, host, scheme)) continue;
        std::string output;
        if (!test_rule(rule, text, output)) return false;
        if (output != text) { text = std::move(output); ++rule.hit_count; ++applied; }
    }
    if (rules_applied) *rules_applied = applied;
    return true;
}

bool apply_request(std::vector<uint8_t>& raw, const std::string& host, const std::string& scheme) { std::string text(raw.begin(),raw.end()); const bool ok=apply_text(text,match_kind_t::all,host,scheme); raw.assign(text.begin(),text.end()); return ok; }
bool apply_response(std::vector<uint8_t>& raw, const std::string& host, const std::string& scheme) { std::string text(raw.begin(),raw.end()); const bool ok=apply_text(text,match_kind_t::all,host,scheme); raw.assign(text.begin(),text.end()); return ok; }
bool save_to_disk() { aida::preview::network::record_receipt("Match and Replace", "saved to preview state"); return true; }
bool load_from_disk() { return initialize(); }
std::string storage_path() { return "/aida-preview/state/match-replace.json"; }
nlohmann::json export_json() { nlohmann::json result=nlohmann::json::array(); for(const auto& rule:s_match_rules) result.push_back({{"id",rule.id},{"label",rule.label},{"target",target_label(rule.target)},{"match",rule.match_regex},{"replacement",rule.replacement},{"active",rule.active}}); return result; }
bool import_json(const nlohmann::json& document, bool replace_existing) { if(!document.is_array()) return false; if(replace_existing) s_match_rules.clear(); for(const auto& item:document){ rule_t rule; rule.label=item.value("label",""); rule.match_regex=item.value("match",""); rule.replacement=item.value("replacement",""); rule.active=item.value("active",true); match_kind_t target; if(parse_target(item.value("target","all"),target)) rule.target=target; add(rule); } return true; }

const char* target_label(match_kind_t kind) {
    switch (kind) {
    case match_kind_t::request_url: return "request_url";
    case match_kind_t::request_headers: return "request_headers";
    case match_kind_t::request_body: return "request_body";
    case match_kind_t::response_headers: return "response_headers";
    case match_kind_t::response_body: return "response_body";
    case match_kind_t::all: return "all";
    }
    return "all";
}

bool parse_target(const std::string& value, match_kind_t& output) { for(int i=0;i<=static_cast<int>(match_kind_t::all);++i){const auto kind=static_cast<match_kind_t>(i); if(value==target_label(kind)){output=kind;return true;}} return false; }
std::string last_error() { return s_match_error; }

}

namespace mitm_proxy {
namespace {

void seed_proxy_history() {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    if (!g_state.history.empty()) return;
    auto append = [](uint64_t id, const char* host, const char* method, const char* uri,
                     int status, const char* reason, uint64_t latency, const char* body) {
        auto exchange = std::make_shared<http_exchange>();
        exchange->id = id;
        exchange->timestamp = aida::preview::network::monotonic_ms() - (2050 - id) * 410;
        exchange->client_addr = "127.0.0.1";
        exchange->client_port = static_cast<uint16_t>(51000 + id % 1000);
        exchange->target_host = host;
        exchange->target_port = 443;
        exchange->is_tls = true;
        exchange->tls_sni = host;
        exchange->tls_version_str = "TLS 1.3";
        exchange->alpn_protocol = "h2";
        exchange->request.method = method;
        exchange->request.uri = uri;
        exchange->request.version = "HTTP/1.1";
        exchange->request.valid = true;
        exchange->request.headers.push_back({"Host", host});
        exchange->request.headers.push_back({"User-Agent", "Camoufox/135"});
        exchange->response.status_code = status;
        exchange->response.reason = reason;
        exchange->response.version = "HTTP/1.1";
        exchange->response.valid = true;
        exchange->response.headers.push_back({"Content-Type", "application/json"});
        exchange->response.body.assign(body, body + std::strlen(body));
        const std::string request = std::string(method) + " " + uri + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Camoufox/135\r\n\r\n";
        const std::string response = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\nContent-Type: application/json\r\n\r\n" + body;
        exchange->raw_request.assign(request.begin(), request.end());
        exchange->raw_response.assign(response.begin(), response.end());
        exchange->request_size = exchange->raw_request.size();
        exchange->response_size = exchange->raw_response.size();
        exchange->request_time = exchange->timestamp;
        exchange->response_time = exchange->timestamp + latency;
        exchange->latency_ms = latency;
        exchange->state = http_exchange::state_t::complete;
        g_state.history.push_back(std::move(exchange));
    };
    append(2041, "portal.aidapro.net", "GET", "/api/v2/session", 200, "OK", 84, "{\"session\":\"authenticated\"}");
    append(2042, "sandbox.aidapro.net", "POST", "/v1/analyze", 202, "Accepted", 131, "{\"job_id\":\"scan-7f32\"}");
    append(2043, "portal.aidapro.net", "GET", "/api/v2/symbols?module=suspect.dll", 200, "OK", 62, "{\"count\":1842}");
    append(2044, "telemetry.aidapro.net", "POST", "/v1/events", 204, "No Content", 43, "{}");
    g_state.total_requests.store(4, std::memory_order_release);
    g_state.total_bytes_in.store(2841, std::memory_order_release);
    g_state.total_bytes_out.store(1392, std::memory_order_release);
}

http_exchange* find_mutable(uint64_t id) {
    for (auto& exchange : g_state.history) {
        if (exchange && exchange->id == id) return exchange.get();
    }
    return nullptr;
}

}

bool start(const proxy_config& config) {
    g_state.config = config;
    g_state.running.store(true, std::memory_order_release);
    g_state.proxy_alive.store(true, std::memory_order_release);
    seed_proxy_history();
    aida::preview::network::record_receipt("MITM proxy", "started at " + config.bind_addr + ":" + std::to_string(config.bind_port));
    return true;
}

void stop() {
    g_state.running.store(false, std::memory_order_release);
    g_state.proxy_alive.store(false, std::memory_order_release);
    aida::preview::network::record_receipt("MITM proxy", "stopped");
}

bool is_running() { return g_state.running.load(std::memory_order_acquire); }
proxy_config get_config() { return g_state.config; }
bool set_config(const proxy_config& config) { g_state.config = config; return true; }

std::vector<http_exchange> get_history(size_t max_count) {
    seed_proxy_history();
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    const size_t count = max_count == 0 ? g_state.history.size() : std::min(max_count, g_state.history.size());
    std::vector<http_exchange> result;
    result.reserve(count);
    const size_t begin = g_state.history.size() - count;
    for (size_t i = begin; i < g_state.history.size(); ++i) if (g_state.history[i]) result.push_back(*g_state.history[i]);
    return result;
}

void clear_history() {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    g_state.history.clear();
    g_state.total_requests.store(0, std::memory_order_release);
    aida::preview::network::record_receipt("Proxy history", "cleared");
}

bool clear_history_if_exact(const std::vector<uint64_t>& reviewed_ids) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    if (g_state.history.size() != reviewed_ids.size()) return false;
    for (size_t index = 0; index < g_state.history.size(); ++index) {
        if (!g_state.history[index] || g_state.history[index]->id != reviewed_ids[index]) return false;
    }
    g_state.history.clear();
    g_state.total_requests.store(0, std::memory_order_release);
    aida::preview::network::record_receipt("Proxy history", "exact reviewed history cleared");
    return true;
}

size_t history_count() {
    seed_proxy_history();
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    return g_state.history.size();
}

std::vector<tls_observation_t> get_tls_observations(size_t) {
    return {
        { aida::preview::network::monotonic_ms(), tls_observation_kind_t::http_tls, "127.0.0.1", 51618,
          "portal.aidapro.net", 443, "portal.aidapro.net", "h2", "Intercepted with the AiDA preview CA" }
    };
}

const char* to_string(tls_observation_kind_t kind) {
    switch (kind) {
    case tls_observation_kind_t::http_tls: return "http_tls";
    case tls_observation_kind_t::client_handshake_failed: return "client_handshake_failed";
    case tls_observation_kind_t::upstream_handshake_failed: return "upstream_handshake_failed";
    case tls_observation_kind_t::upstream_pin_mismatch: return "upstream_pin_mismatch";
    case tls_observation_kind_t::sni_authority_mismatch: return "sni_authority_mismatch";
    case tls_observation_kind_t::non_http_tls: return "non_http_tls";
    case tls_observation_kind_t::tunnel_passthrough: return "tunnel_passthrough";
    }
    return "unknown";
}

void set_intercept_enabled(bool enabled) {
    g_state.config.intercept_enabled = enabled;
    aida::preview::network::record_receipt("Proxy interception", enabled ? "enabled" : "disabled");
}

bool is_intercept_enabled() { return g_state.config.intercept_enabled; }
void set_ws_frame_callback(ws_frame_callback_t callback) { g_state.ws_observer_cb = std::move(callback); }

std::vector<http_exchange> get_held_exchanges() {
    auto result = get_history(2);
    for (auto& exchange : result) exchange.state = http_exchange::state_t::pending;
    return g_state.config.intercept_enabled ? result : std::vector<http_exchange>();
}

void forward_exchange(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    if (auto* exchange = find_mutable(id)) exchange->state = http_exchange::state_t::complete;
    aida::preview::network::record_receipt("Intercept forwarded", std::to_string(id));
}

void forward_modified(uint64_t id, const std::vector<uint8_t>& modified_request) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    if (auto* exchange = find_mutable(id)) {
        exchange->raw_request = modified_request;
        exchange->request_size = modified_request.size();
        exchange->state = http_exchange::state_t::complete;
    }
    aida::preview::network::record_receipt("Intercept modified and forwarded", std::to_string(id));
}

void drop_exchange(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    if (auto* exchange = find_mutable(id)) exchange->state = http_exchange::state_t::dropped;
    aida::preview::network::record_receipt("Intercept dropped", std::to_string(id));
}

void forward_all() {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (auto& exchange : g_state.history) if (exchange) exchange->state = http_exchange::state_t::complete;
    aida::preview::network::record_receipt("Intercept queue", "all forwarded");
}

void drop_all() {
    std::lock_guard<std::mutex> lock(g_state.history_mutex);
    for (auto& exchange : g_state.history) if (exchange) exchange->state = http_exchange::state_t::dropped;
    aida::preview::network::record_receipt("Intercept queue", "all dropped");
}

repeat_result repeat_request(const std::string& host, uint16_t port, bool use_tls, const std::vector<uint8_t>& raw_request) {
    repeat_result result;
    result.success = !host.empty() && !raw_request.empty();
    result.exchange.id = 3001;
    result.exchange.timestamp = aida::preview::network::monotonic_ms();
    result.exchange.target_host = host;
    result.exchange.target_port = port;
    result.exchange.is_tls = use_tls;
    result.exchange.raw_request = raw_request;
    result.exchange.request_size = raw_request.size();
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"preview\":true,\"receipt\":\"replayed\"}";
    result.exchange.raw_response.assign(response.begin(), response.end());
    result.exchange.response.status_code = 200;
    result.exchange.response.reason = "OK";
    result.exchange.response_size = result.exchange.raw_response.size();
    result.exchange.latency_ms = 67;
    result.exchange.state = http_exchange::state_t::complete;
    if (!result.success) result.error = "Host and request are required";
    aida::preview::network::record_receipt("Repeater request", host + ":" + std::to_string(port));
    return result;
}

proxy_stats get_stats() {
    seed_proxy_history();
    proxy_stats stats;
    stats.running = is_running();
    stats.total_requests = g_state.total_requests.load(std::memory_order_acquire);
    stats.total_bytes_in = g_state.total_bytes_in.load(std::memory_order_acquire);
    stats.total_bytes_out = g_state.total_bytes_out.load(std::memory_order_acquire);
    stats.active_connections = stats.running ? 3 : 0;
    stats.history_size = history_count();
    stats.held_count = get_held_exchanges().size();
    return stats;
}

}

namespace aida::preview::network {
namespace {

network_view::packet_entry_t packet(uint64_t timestamp,
                                    uint32_t pid,
                                    uint8_t direction,
                                    uint16_t source_port,
                                    uint16_t destination_port,
                                    const char* protocol,
                                    const char* summary,
                                    const char* payload) {
    network_view::packet_entry_t entry;
    entry.timestamp = timestamp;
    entry.pid = pid;
    entry.protocol = 6;
    entry.direction = direction;
    entry.src_port = source_port;
    entry.dst_port = destination_port;
    entry.src_addr[0] = 10;
    entry.src_addr[1] = 24;
    entry.src_addr[2] = 7;
    entry.src_addr[3] = 18;
    entry.dst_addr[0] = 172;
    entry.dst_addr[1] = 67;
    entry.dst_addr[2] = 19;
    entry.dst_addr[3] = 44;
    entry.protocol_label = protocol;
    entry.summary = summary;
    if (payload) entry.payload.assign(payload, payload + std::strlen(payload));
    entry.payload_size = static_cast<uint32_t>(entry.payload.size());
    return entry;
}

network_view::dns_entry_t dns(uint64_t timestamp,
                              uint32_t pid,
                              uint16_t query_type,
                              const char* domain,
                              const char* address,
                              uint32_t ttl) {
    network_view::dns_entry_t entry;
    entry.timestamp = timestamp;
    entry.pid = pid;
    entry.query_type = query_type;
    entry.domain = domain;
    entry.resolved_addr = address;
    entry.response_code = 0;
    entry.ttl = ttl;
    return entry;
}

}

uint64_t monotonic_ms() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

void record_receipt(std::string action, std::string detail) {
    s_receipt = std::move(action);
    if (!detail.empty()) {
        s_receipt += " ";
        s_receipt += detail;
    }
}

const std::string& receipt() {
    return s_receipt;
}

void initialize(network_view::state_t& state) {
    s_current_state = &state;
    state.active = true;
    state.active_tab = network_view::sub_tab_t::connections;
    state.prev_tab = state.active_tab;
    state.last_render_tick_ms.store(monotonic_ms(), std::memory_order_release);

    state.connections.clear();
    state.connections.push_back({ 6420, 6, 4, 51542, 443, 2, {10, 24, 7, 18}, {172, 67, 19, 44}, "AiDAStandalone.exe" });
    state.connections.push_back({ 9148, 6, 1, 8443, 0, 2, {127, 0, 0, 1}, {}, "AiDAProxy.exe" });
    state.connections.push_back({ 12064, 17, 4, 5353, 5353, 2, {10, 24, 7, 18}, {224, 0, 0, 251}, "camoufox.exe" });
    state.connections.push_back({ 12064, 6, 4, 51618, 443, 2, {10, 24, 7, 18}, {104, 18, 32, 47}, "camoufox.exe" });
    state.conn_selected = 0;
    state.conn_filter_pid = 0;
    state.conn_filter_protocol = 0;
    state.conn_auto_refresh = true;
    state.conn_auto_refresh_enabled.store(true, std::memory_order_release);
    state.conn_polling.store(false, std::memory_order_release);
    state.conn_thread_done.store(true, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        state.captured_packets.clear();
        state.captured_packets.push_back(packet(39128412, 12064, 1, 51618, 443, "TLS", "Client Hello  SNI=portal.aidapro.net  ALPN=h2,http/1.1", "\x16\x03\x01\x02\x00"));
        state.captured_packets.push_back(packet(39128567, 12064, 1, 51618, 443, "HTTP", "GET /api/v2/session HTTP/1.1", "GET /api/v2/session HTTP/1.1\r\nHost: portal.aidapro.net\r\nAccept: application/json\r\n\r\n"));
        state.captured_packets.push_back(packet(39128604, 12064, 0, 443, 51618, "HTTP", "200 OK  application/json  842 B", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n{\"session\":\"authenticated\"}"));
        state.captured_packets.push_back(packet(39129220, 6420, 1, 51542, 443, "WebSocket", "TEXT  client -> server  96 B", "{\"type\":\"analysis.progress\",\"phase\":\"symbols\",\"value\":0.72}"));
    }
    state.cap_selected = 1;
    state.cap_running.store(true, std::memory_order_release);
    state.cap_start_pending.store(false, std::memory_order_release);
    state.cap_stop_pending.store(false, std::memory_order_release);
    state.cap_polling.store(false, std::memory_order_release);
    state.cap_thread_alive.store(false, std::memory_order_release);
    state.cap_thread_done.store(true, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(state.dns_mutex);
        state.dns_entries.clear();
        state.dns_entries.push_back(dns(39128102, 12064, 1, "portal.aidapro.net", "172.67.19.44", 300));
        state.dns_entries.push_back(dns(39128188, 12064, 28, "api.aidapro.net", "2606:4700:3034::6815:2b2f", 300));
        state.dns_entries.push_back(dns(39128870, 6420, 1, "collab.aidapro.net", "104.18.32.47", 120));
        state.dns_entries.push_back(dns(39129041, 12064, 1, "cdn.jsdelivr.net", "151.101.1.229", 60));
    }
    state.dns_selected = 0;
    state.dns_polling.store(false, std::memory_order_release);
    state.dns_thread_alive.store(false, std::memory_order_release);
    state.dns_thread_done.store(true, std::memory_order_release);

    state.filters.clear();
    state.filters.push_back({ 101, 0, 2, 6, 12064, 443, "0.0.0.0/0", true });
    state.filters.push_back({ 102, 1, 1, 17, 0, 53, "0.0.0.0/0", true });
    state.filters.push_back({ 103, 0, 2, 6, 6420, 8443, "127.0.0.1", true });
    state.filter_selected = 0;

    {
        std::lock_guard<std::mutex> lock(state.bw_mutex);
        state.bw_entries.clear();
        network_view::bw_entry_t browser;
        browser.pid = 12064;
        browser.process_name = "camoufox.exe";
        browser.bytes_in = 18742341;
        browser.bytes_out = 3824910;
        browser.rate_in = 284112.f;
        browser.rate_out = 42170.f;
        for (int i = 0; i < 64; ++i) browser.rate_history[i] = 90000.f + static_cast<float>((i * 37991) % 260000);
        browser.history_index = 63;
        state.bw_entries.push_back(browser);
        network_view::bw_entry_t ide;
        ide.pid = 6420;
        ide.process_name = "AiDAStandalone.exe";
        ide.bytes_in = 5421870;
        ide.bytes_out = 1245982;
        ide.rate_in = 48210.f;
        ide.rate_out = 18920.f;
        for (int i = 0; i < 64; ++i) ide.rate_history[i] = 22000.f + static_cast<float>((i * 11731) % 56000);
        ide.history_index = 63;
        state.bw_entries.push_back(ide);
    }
    state.bw_monitoring = true;
    state.bw_selected = 0;
    state.bw_polling.store(false, std::memory_order_release);
    state.bw_thread_alive.store(false, std::memory_order_release);
    state.bw_thread_done.store(true, std::memory_order_release);

    copy_text(state.proxy_bind_addr, sizeof(state.proxy_bind_addr), "127.0.0.1");
    state.proxy_port = 8443;
    state.proxy_decode_tls = true;
    state.proxy_selected = 0;
    state.intercept_enabled = true;
    state.intercept_selected = 0;
    mitm_proxy::proxy_config proxy_config;
    proxy_config.bind_addr = state.proxy_bind_addr;
    proxy_config.bind_port = static_cast<uint16_t>(state.proxy_port);
    proxy_config.decode_tls = state.proxy_decode_tls;
    proxy_config.intercept_enabled = state.intercept_enabled;
    mitm_proxy::start(proxy_config);

    state.repeater_entries.clear();
    auto session_request = std::make_shared<network_view::repeater_entry_t>();
    session_request->host = "portal.aidapro.net";
    session_request->port = 443;
    session_request->use_tls = true;
    session_request->raw_request = "GET /api/v2/session HTTP/1.1\r\nHost: portal.aidapro.net\r\nAccept: application/json\r\n\r\n";
    session_request->raw_response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n{\"session\":\"authenticated\"}";
    session_request->status_code = 200;
    session_request->latency_ms = 84;
    state.repeater_entries.push_back(session_request);
    auto scan_request = std::make_shared<network_view::repeater_entry_t>();
    scan_request->host = "sandbox.aidapro.net";
    scan_request->port = 443;
    scan_request->use_tls = true;
    scan_request->raw_request = "POST /v1/analyze HTTP/1.1\r\nHost: sandbox.aidapro.net\r\nContent-Type: application/json\r\n\r\n{\"sample\":\"suspect.dll\"}";
    scan_request->raw_response = "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{\"job_id\":\"scan-7f32\"}";
    scan_request->status_code = 202;
    scan_request->latency_ms = 131;
    state.repeater_entries.push_back(scan_request);
    state.repeater_selected = 0;

    copy_text(state.kl_exe_path, sizeof(state.kl_exe_path), "C:\\ReverseLab\\targets\\suspect.exe");
    copy_text(state.kl_args, sizeof(state.kl_args), "--inspect --safe-mode");
    copy_text(state.kl_watch_path, sizeof(state.kl_watch_path), "C:\\ReverseLab\\captures\\sslkeys.log");
    state.kl_selected = 0;

    copy_text(state.pcap_path, sizeof(state.pcap_path), "C:\\ReverseLab\\captures\\suspect-session.pcapng");
    state.pcap_filter_pid = 12064;
    state.pcap_filter_protocol = 6;
    state.pcap_writing.store(false, std::memory_order_release);
    state.pcap_written_count.store(428, std::memory_order_release);
    state.pcap_last_error.clear();

    state.fuzz_config.host = "sandbox.aidapro.net";
    state.fuzz_config.port = 443;
    state.fuzz_config.use_tls = true;
    state.fuzz_config.base_request = "GET /api/files/FUZZ HTTP/1.1\r\nHost: sandbox.aidapro.net\r\nAccept: application/json\r\n\r\n";
    state.fuzz_config.payload_sets.clear();
    network_view::payload_set_t paths;
    paths.name = "Traversal probes";
    paths.source = "AiDA curated payloads";
    paths.type = 0;
    paths.entries = { "..%2f..%2fwindows%2fwin.ini", "..%252f..%252fboot.ini", "....//....//etc/passwd" };
    state.fuzz_config.payload_sets.push_back(std::move(paths));
    {
        std::lock_guard<std::mutex> lock(state.fuzz_mutex);
        state.fuzz_results.clear();
        state.fuzz_results.push_back({ 1, "..%2f..%2fwindows%2fwin.ini", 403, 312, 48, false, "Access denied", {}, {} });
        state.fuzz_results.push_back({ 2, "..%252f..%252fboot.ini", 200, 941, 73, true, "[boot loader] timeout=30", {}, "timeout=30" });
        state.fuzz_results.push_back({ 3, "....//....//etc/passwd", 404, 129, 41, false, "Not found", {}, {} });
    }
    state.fuzz_selected = 1;
    state.fuzz_running.store(false, std::memory_order_release);
    state.fuzz_progress.store(3, std::memory_order_release);
    state.fuzz_total.store(3, std::memory_order_release);
    state.fuzz_thread_alive.store(false, std::memory_order_release);
    state.fuzz_thread_done.store(true, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(state.ws_mutex);
        state.ws_frames.clear();
        network_view::state_t::ws_frame_entry_t outbound;
        outbound.timestamp = 39129220;
        outbound.exchange_id = 2041;
        outbound.host = "portal.aidapro.net";
        outbound.port = 443;
        outbound.is_outbound = true;
        outbound.is_text = true;
        outbound.opcode = 1;
        const char* outgoing = "{\"type\":\"analysis.progress\",\"phase\":\"symbols\",\"value\":0.72}";
        outbound.payload.assign(outgoing, outgoing + std::strlen(outgoing));
        outbound.preview = outgoing;
        state.ws_frames.push_back(std::move(outbound));
        network_view::state_t::ws_frame_entry_t inbound;
        inbound.timestamp = 39129286;
        inbound.exchange_id = 2041;
        inbound.host = "portal.aidapro.net";
        inbound.port = 443;
        inbound.is_outbound = false;
        inbound.is_text = true;
        inbound.opcode = 1;
        const char* incoming = "{\"type\":\"analysis.symbols\",\"count\":1842,\"status\":\"ready\"}";
        inbound.payload.assign(incoming, incoming + std::strlen(incoming));
        inbound.preview = incoming;
        state.ws_frames.push_back(std::move(inbound));
    }
    state.ws_selected = 0;

    state.scripts.clear();
    state.scripts.push_back({ "Redact authorization headers", "C:\\ReverseLab\\scripts\\redact-auth.js", true, true });
    state.scripts.push_back({ "Tag suspicious responses", "C:\\ReverseLab\\scripts\\tag-findings.js", true, true });
    state.scripts.push_back({ "Rewrite sandbox host", "C:\\ReverseLab\\scripts\\sandbox-route.js", false, true });
    state.script_selected = 0;
    copy_text(state.script_editor_buf, sizeof(state.script_editor_buf),
        "function onRequest(request) {\n  request.headers.remove('Authorization');\n  return request;\n}\n\nfunction onResponse(response) {\n  if (response.status >= 500) response.tags.add('server-error');\n  return response;\n}");
    {
        std::lock_guard<std::mutex> lock(state.script_log_mutex);
        state.script_log.clear();
        state.script_log.push_back("[INFO] Loaded redact-auth.js");
        state.script_log.push_back("[INFO] Loaded tag-findings.js");
        state.script_log.push_back("[OUT ] Request 2041 sanitized in 0.4 ms");
    }

    state.decoder_pipeline.clear();
    state.decoder_pipeline.push_back({ "URL decode", { { "mode", "component" } } });
    state.decoder_pipeline.push_back({ "Base64 decode", {} });
    state.decoder_pipeline.push_back({ "Gunzip", {} });
    copy_text(state.decoder_input, sizeof(state.decoder_input), "H4sIAAAAAAAA/6tWKkktLlGyUipOLS7OzM9T0lEqS8wpTQUA");
    state.decoder_output = "{\"type\":\"analysis.result\",\"score\":92}";
    state.decoder_selected_step = 1;

    state.show_detail = true;
    state.detail_ratio = 0.65f;
    state.content_fade = 1.f;
    std::fill(std::begin(state.tab_anim), std::end(state.tab_anim), 0.f);
    state.tab_anim[static_cast<int>(state.active_tab)] = 1.f;
    record_receipt("Network preview initialized", "36 authoritative routes mounted");
    if (s_pending_fixture_valid)
        apply_fixture(state, s_pending_fixture, s_pending_cardinality);
}

static void apply_fixture(network_view::state_t& state, fixture_state_t fixture,
    std::size_t cardinality) {
    if (fixture == fixture_state_t::empty || fixture == fixture_state_t::disconnected) {
        state.active_tab = network_view::sub_tab_t::capture;
        state.cap_running.store(false, std::memory_order_release);
        state.cap_start_pending.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(state.conn_mutex);
            state.connections.clear();
        }
        {
            std::lock_guard<std::mutex> lock(state.cap_mutex);
            state.captured_packets.clear();
        }
        {
            std::lock_guard<std::mutex> lock(state.dns_mutex);
            state.dns_entries.clear();
        }
        {
            std::lock_guard<std::mutex> lock(state.bw_mutex);
            state.bw_entries.clear();
        }
        state.bw_monitoring = false;
        state.intercept_enabled = false;
        state.repeater_entries.clear();
        mitm_proxy::stop();
        return;
    }
    if (fixture == fixture_state_t::error) {
        state.active_tab = network_view::sub_tab_t::pcap_export;
        state.pcap_writing.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(state.pcap_error_mutex);
            state.pcap_last_error = "Capture export failed because the retained destination is unavailable";
        }
        mitm_proxy::stop();
        return;
    }
    state.active_tab = network_view::sub_tab_t::capture;
    {
        std::lock_guard<std::mutex> lock(state.pcap_error_mutex);
        state.pcap_last_error.clear();
    }
    const std::size_t bounded = (std::min<std::size_t>)(cardinality, state.cap_max_packets);
    {
        std::lock_guard<std::mutex> lock(state.cap_mutex);
        for (std::size_t index = state.captured_packets.size(); index < bounded; ++index) {
            network_view::packet_entry_t row;
            row.timestamp = 39130000ULL + static_cast<std::uint64_t>(index);
            row.pid = index % 5U == 0U ? 12064U : 6420U;
            row.protocol = 6;
            row.direction = static_cast<std::uint8_t>(index % 2U);
            row.src_port = static_cast<std::uint16_t>(50000U + index % 10000U);
            row.dst_port = 443;
            row.protocol_label = index % 7U == 0U ? "WebSocket" : "HTTP";
            row.summary = "Deterministic capture row " + std::to_string(index + 1U);
            state.captured_packets.push_back(std::move(row));
        }
    }
    state.cap_running.store(fixture == fixture_state_t::loading,
        std::memory_order_release);
    state.cap_start_pending.store(fixture == fixture_state_t::cancellation_requested,
        std::memory_order_release);
}

void configure_fixture(fixture_state_t fixture, std::size_t cardinality) {
    s_pending_fixture = fixture;
    s_pending_cardinality = (std::min<std::size_t>)(cardinality, 10000U);
    s_pending_fixture_valid = true;
    if (s_current_state)
        initialize(*s_current_state);
}

void shutdown(network_view::state_t& state) {
    if (s_current_state == &state)
        s_current_state = nullptr;
    state.conn_polling.store(false, std::memory_order_release);
    state.cap_polling.store(false, std::memory_order_release);
    state.cap_running.store(false, std::memory_order_release);
    state.dns_polling.store(false, std::memory_order_release);
    state.bw_polling.store(false, std::memory_order_release);
    state.fuzz_running.store(false, std::memory_order_release);
    state.active = false;
    record_receipt("Network preview stopped", "state retained for inspection");
}

}

namespace aida::preview {
void configure_network_fixture(fixture_state_t fixture, std::size_t cardinality) {
    network::configure_fixture(fixture, cardinality);
}
}
