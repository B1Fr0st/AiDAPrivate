#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner_view {

bool   initialize();
void   shutdown();

void   render(float pos_x, float pos_y, float width, float height,
              float alpha, float accent_r, float accent_g, float accent_b);

bool   open_new_audit_with(const std::string& url,
                           const std::string& raw_request);
bool   resolve_retained_artifact(std::uint64_t issue_id, std::uint64_t seen_ms,
                                 std::uint64_t evidence_index, bool response,
                                 std::vector<std::uint8_t>& bytes, std::string& reason);
bool   resolve_retained_endpoint(std::uint64_t issue_id, std::uint64_t seen_ms,
                                 std::string& host, std::uint16_t& port, bool& use_tls,
                                 std::string& reason);

}
}
}
