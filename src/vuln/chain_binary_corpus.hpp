#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>

#include "chain_model.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

enum class corpus_kind_t
{
    binary,
    firmware_region,
    protocol_spec,
    memory_snapshot,
    external_contract,
    recorded_trace
};

enum class corpus_availability_t
{
    loaded,
    peer_loaded,
    missing,
    partial,
    recorded_only
};

enum class corpus_trust_t
{
    ida_extracted,
    recorded_dynamic,
    user_declared,
    imported_contract
};

enum class address_kind_t
{
    image_rva,
    segment_offset,
    import_slot,
    export_forwarder,
    synthetic,
    unknown
};

enum class location_layer_t
{
    raw,
    ctree,
    microcode,
    type,
    xref,
    dynamic,
    declared
};

enum class location_confidence_t
{
    exact,
    symbolic_exact,
    weak_name,
    ambiguous,
    unresolved
};

struct hash_identity_t
{
    std::string md5;
    std::string sha256;
    std::string crc32;
    std::uint64_t input_size = 0;
};

struct live_instance_metadata_t
{
    std::string instance_id;
    std::uint64_t pid = 0;
    int port = 0;
    std::string base_url;
    std::string mcp_url;
    std::uint64_t heartbeat_ms = 0;
    std::uint64_t index_generation = 0;
    nlohmann::json metadata = nlohmann::json::object();
};

struct segment_record_t
{
    std::string name;
    std::string segment_class;
    std::uint64_t start_ea = 0;
    std::uint64_t end_ea = 0;
    std::uint64_t start_rva = 0;
    std::uint64_t size = 0;
    bool read = false;
    bool write = false;
    bool execute = false;
    int type = 0;
};

struct corpus_identity_t
{
    std::string corpus_id;
    std::string canonical_name;
    std::string input_path;
    std::string idb_path;
    hash_identity_t hashes;
    std::uint64_t image_base = 0;
    std::uint64_t min_ea = 0;
    std::uint64_t max_ea = 0;
    std::string processor;
    std::uint32_t bitness = 0;
    int file_type = 0;
    bool is_dll = false;
    bool is_kernel = false;
    bool is_big_endian = false;
    std::string pdb_guid_age;
    std::string pdb_path;
    std::string segment_digest;
    std::string exportset_digest;
    std::string symbol_set_digest;
};

struct corpus_record_t
{
    corpus_kind_t kind = corpus_kind_t::binary;
    corpus_availability_t availability = corpus_availability_t::missing;
    corpus_trust_t trust = corpus_trust_t::user_declared;
    corpus_identity_t identity;
    std::vector<segment_record_t> segments;
    std::vector<live_instance_metadata_t> live_instances;
    nlohmann::json loader_model = nlohmann::json::object();
    nlohmann::json metadata = nlohmann::json::object();
};

struct canonical_address_t
{
    std::string corpus_id;
    std::uint64_t ea = 0;
    std::uint64_t rva = 0;
    std::string segment;
    std::uint64_t segment_start_rva = 0;
    std::uint64_t segment_offset = 0;
    std::string function_id;
    std::string instruction_id;
    address_kind_t kind = address_kind_t::unknown;
    location_layer_t layer = location_layer_t::raw;
    location_confidence_t confidence = location_confidence_t::unresolved;
};

struct normalize_address_result_t
{
    bool ok = false;
    canonical_address_t address;
    validation_error_t error;
};

const char* to_string(corpus_kind_t value);
const char* to_string(corpus_availability_t value);
const char* to_string(corpus_trust_t value);
const char* to_string(address_kind_t value);
const char* to_string(location_layer_t value);
const char* to_string(location_confidence_t value);

std::optional<corpus_kind_t> corpus_kind_from_string(const std::string& value);
std::optional<corpus_availability_t> corpus_availability_from_string(const std::string& value);
std::optional<corpus_trust_t> corpus_trust_from_string(const std::string& value);
std::optional<address_kind_t> address_kind_from_string(const std::string& value);
std::optional<location_layer_t> location_layer_from_string(const std::string& value);
std::optional<location_confidence_t> location_confidence_from_string(const std::string& value);

nlohmann::json to_json(const hash_identity_t& value);
nlohmann::json to_json(const live_instance_metadata_t& value);
nlohmann::json to_json(const segment_record_t& value);
nlohmann::json to_json(const corpus_identity_t& value);
nlohmann::json to_json(const corpus_record_t& value);
nlohmann::json to_json(const canonical_address_t& value);
nlohmann::json to_json(const normalize_address_result_t& value);

bool from_json(const nlohmann::json& value, hash_identity_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, live_instance_metadata_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, segment_record_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, corpus_identity_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, corpus_record_t& out, validation_result_t& errors, const std::string& path);
bool from_json(const nlohmann::json& value, canonical_address_t& out, validation_result_t& errors, const std::string& path);

corpus_record_t make_missing_corpus(const std::string& corpus_id,
                                    const std::string& canonical_name,
                                    const std::string& reason);
corpus_record_t snapshot_current_idb_corpus(const std::string& corpus_id_override = {});
std::string derive_module_id(const corpus_identity_t& identity);
std::string canonical_name_from_path(const std::string& path);
std::optional<const corpus_record_t*> find_corpus(const std::vector<corpus_record_t>& corpus, const std::string& corpus_id);
std::optional<corpus_record_t*> find_corpus(std::vector<corpus_record_t>& corpus, const std::string& corpus_id);
normalize_address_result_t normalize_ea(const corpus_record_t& corpus,
                                        std::uint64_t ea,
                                        location_layer_t layer = location_layer_t::raw);
normalize_address_result_t normalize_rva(const corpus_record_t& corpus,
                                         std::uint64_t rva,
                                         location_layer_t layer = location_layer_t::raw);
bool corpus_blocks_confirmation(const corpus_record_t& corpus);
validation_result_t validate_corpus_records(const std::vector<corpus_record_t>& corpus);

}
}
}
