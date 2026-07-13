#pragma once

#include "decompiler_contracts.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace aida::analysis::type_graph {

constexpr std::uint8_t k_max_confidence = 100;

std::uint32_t provenance_priority(decompiler_fact_provenance_t provenance) noexcept;

struct type_provenance_record_t {
    decompiler_fact_provenance_t source = decompiler_fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::string source_detail;
    source_coordinate_t coordinate;

    bool valid() const noexcept;
};

std::uint32_t effective_score(const type_provenance_record_t& record) noexcept;

bool strictly_higher(const type_provenance_record_t& lhs, const type_provenance_record_t& rhs) noexcept;

bool same_authority(const type_provenance_record_t& lhs, const type_provenance_record_t& rhs) noexcept;

struct provenance_field_key_t {
    std::string canonical_name;
    std::string field_name;

    bool operator==(const provenance_field_key_t& other) const noexcept {
        return canonical_name == other.canonical_name && field_name == other.field_name;
    }
};

struct provenance_field_key_hash_t {
    std::size_t operator()(const provenance_field_key_t& key) const noexcept {
        std::size_t h = std::hash<std::string>{}(key.canonical_name);
        h ^= std::hash<std::string>{}(key.field_name) + 0x9e3779b9u + (h << 6) + (h >> 2);
        return h;
    }
};

class provenance_journal_t {
public:
    void record(const std::string& canonical_name, const std::string& field_name,
                const type_provenance_record_t& record);

    const std::vector<type_provenance_record_t>* records_for(const std::string& canonical_name,
                                                              const std::string& field_name) const;

    bool has_conflict(const std::string& canonical_name, const std::string& field_name) const;

    std::size_t conflict_count() const noexcept { return conflict_count_; }
    std::size_t total_records() const noexcept { return total_records_; }
    std::size_t field_count() const noexcept { return fields_.size(); }

    void clear() noexcept;

    std::vector<std::string> all_canonical_names() const;

    std::vector<type_provenance_record_t> all_records_for(const std::string& canonical_name) const;

private:
    std::unordered_map<provenance_field_key_t, std::vector<type_provenance_record_t>, provenance_field_key_hash_t> fields_;
    std::size_t conflict_count_ = 0;
    std::size_t total_records_ = 0;
};

struct provenance_conflict_t {
    std::string canonical_name;
    std::string field_name;
    type_provenance_record_t winner;
    type_provenance_record_t loser;
    std::string winner_value;
    std::string loser_value;
};

std::string provenance_label(decompiler_fact_provenance_t provenance) noexcept;

std::string format_provenance_record(const type_provenance_record_t& record);

}
