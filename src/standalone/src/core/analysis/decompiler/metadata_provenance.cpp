#include "metadata_provenance.hpp"

#include <algorithm>
#include <sstream>

namespace aida::analysis::type_graph {

std::uint32_t provenance_priority(decompiler_fact_provenance_t provenance) noexcept
{
    switch (provenance) {
    case decompiler_fact_provenance_t::user_overlay:
        return 200;
    case decompiler_fact_provenance_t::semantic_proof:
        return 180;
    case decompiler_fact_provenance_t::bytecode_verifier:
        return 160;
    case decompiler_fact_provenance_t::debug_metadata:
        return 140;
    case decompiler_fact_provenance_t::rtti:
        return 120;
    case decompiler_fact_provenance_t::objc_metadata:
        return 120;
    case decompiler_fact_provenance_t::swift_metadata:
        return 120;
    case decompiler_fact_provenance_t::call_signature:
        return 100;
    case decompiler_fact_provenance_t::provider_semantics:
        return 80;
    case decompiler_fact_provenance_t::loader_metadata:
        return 60;
    case decompiler_fact_provenance_t::unknown:
        return 20;
    }
    return 20;
}

bool type_provenance_record_t::valid() const noexcept
{
    return confidence <= k_max_confidence;
}

std::uint32_t effective_score(const type_provenance_record_t& record) noexcept
{
    return provenance_priority(record.source) * 256u + static_cast<std::uint32_t>(record.confidence);
}

bool strictly_higher(const type_provenance_record_t& lhs, const type_provenance_record_t& rhs) noexcept
{
    return effective_score(lhs) > effective_score(rhs);
}

bool same_authority(const type_provenance_record_t& lhs, const type_provenance_record_t& rhs) noexcept
{
    return effective_score(lhs) == effective_score(rhs);
}

void provenance_journal_t::record(const std::string& canonical_name, const std::string& field_name,
                                  const type_provenance_record_t& record)
{
    provenance_field_key_t key{canonical_name, field_name};
    auto& bucket = fields_[key];
    if (!bucket.empty()) {
        const auto& existing = bucket.front();
        if (!same_authority(existing, record) || existing.source != record.source) {
            if (strictly_higher(existing, record))
                conflict_count_++;
            else if (strictly_higher(record, existing))
                conflict_count_++;
            else if (existing.source != record.source)
                conflict_count_++;
        }
    }
    bucket.push_back(record);
    total_records_++;
}

const std::vector<type_provenance_record_t>* provenance_journal_t::records_for(
    const std::string& canonical_name, const std::string& field_name) const
{
    provenance_field_key_t key{canonical_name, field_name};
    auto it = fields_.find(key);
    if (it == fields_.end())
        return nullptr;
    return &it->second;
}

bool provenance_journal_t::has_conflict(const std::string& canonical_name, const std::string& field_name) const
{
    provenance_field_key_t key{canonical_name, field_name};
    auto it = fields_.find(key);
    if (it == fields_.end() || it->second.size() < 2)
        return false;
    const auto& bucket = it->second;
    for (std::size_t i = 1; i < bucket.size(); ++i) {
        if (bucket[i].source != bucket[0].source || !same_authority(bucket[0], bucket[i]))
            return true;
    }
    return false;
}

void provenance_journal_t::clear() noexcept
{
    fields_.clear();
    conflict_count_ = 0;
    total_records_ = 0;
}

std::vector<std::string> provenance_journal_t::all_canonical_names() const
{
    std::vector<std::string> names;
    names.reserve(fields_.size());
    for (const auto& entry : fields_) {
        if (std::find(names.begin(), names.end(), entry.first.canonical_name) == names.end())
            names.push_back(entry.first.canonical_name);
    }
    std::sort(names.begin(), names.end());
    return names;
}

std::vector<type_provenance_record_t> provenance_journal_t::all_records_for(const std::string& canonical_name) const
{
    std::vector<type_provenance_record_t> result;
    for (const auto& entry : fields_) {
        if (entry.first.canonical_name == canonical_name) {
            for (const auto& record : entry.second)
                result.push_back(record);
        }
    }
    return result;
}

std::string provenance_label(decompiler_fact_provenance_t provenance) noexcept
{
    switch (provenance) {
    case decompiler_fact_provenance_t::loader_metadata:
        return "loader_metadata";
    case decompiler_fact_provenance_t::debug_metadata:
        return "debug_metadata";
    case decompiler_fact_provenance_t::provider_semantics:
        return "provider_semantics";
    case decompiler_fact_provenance_t::bytecode_verifier:
        return "bytecode_verifier";
    case decompiler_fact_provenance_t::rtti:
        return "rtti";
    case decompiler_fact_provenance_t::objc_metadata:
        return "objc_metadata";
    case decompiler_fact_provenance_t::swift_metadata:
        return "swift_metadata";
    case decompiler_fact_provenance_t::call_signature:
        return "call_signature";
    case decompiler_fact_provenance_t::semantic_proof:
        return "semantic_proof";
    case decompiler_fact_provenance_t::user_overlay:
        return "user_overlay";
    case decompiler_fact_provenance_t::unknown:
        return "unknown";
    }
    return "unknown";
}

std::string format_provenance_record(const type_provenance_record_t& record)
{
    std::ostringstream ss;
    ss << provenance_label(record.source) << "(confidence=" << static_cast<int>(record.confidence);
    if (!record.source_detail.empty())
        ss << ", detail=" << record.source_detail;
    ss << ")";
    return ss.str();
}

}
