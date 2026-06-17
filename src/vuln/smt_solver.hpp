#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida
{
namespace vuln
{
namespace smt
{

enum class result_t
{
    sat,
    unsat,
    unknown
};

inline const char* result_str(result_t r)
{
    switch (r)
    {
    case result_t::sat:     return "sat";
    case result_t::unsat:   return "unsat";
    case result_t::unknown: return "unknown";
    }
    return "unknown";
}

struct model_entry_t
{
    std::string name;
    std::string sort;
    uint64_t    bv_value = 0;
    int         bv_width = 0;
    std::string text_value;
    bool        is_bitvector = false;
};

struct solve_result_t
{
    result_t                       result = result_t::unknown;
    std::vector<model_entry_t>     model;
    std::string                    reason;
    uint64_t                       solve_ms = 0;
    std::string                    smtlib_dump;
};

class SmtContext
{
public:
    SmtContext();
    ~SmtContext();

    SmtContext(const SmtContext&) = delete;
    SmtContext& operator=(const SmtContext&) = delete;

    bool             is_available() const;
    const char*      last_error() const;

    bool             declare_bv(const std::string& name, int bit_width);
    bool             declare_bool(const std::string& name);

    bool             assert_smtlib2(const std::string& formula);
    bool             assert_bv_eq_const(const std::string& var, uint64_t value, int width);
    bool             assert_bv_ult(const std::string& var, uint64_t value, int width);
    bool             assert_bv_ugt(const std::string& var, uint64_t value, int width);
    bool             assert_bv_slt(const std::string& var, int64_t value, int width);
    bool             assert_bv_sgt(const std::string& var, int64_t value, int width);

    void             push();
    void             pop();
    void             reset();

    solve_result_t   check();
    solve_result_t   check_with_timeout(uint32_t timeout_ms);

    std::optional<uint64_t> max_value_bv(const std::string& var, int width);
    std::optional<uint64_t> min_value_bv(const std::string& var, int width);
    std::optional<uint64_t> max_value_bv(const std::string& var, int width, uint32_t timeout_ms);
    std::optional<uint64_t> min_value_bv(const std::string& var, int width, uint32_t timeout_ms);

    std::string      to_smtlib2() const;

    static bool      smtlib2_quick_check(const std::string& formula, result_t& out_result, uint32_t timeout_ms = 5000);

private:
    struct impl_t;
    std::unique_ptr<impl_t> m_impl;
};

class SmtContextPool
{
public:
    explicit SmtContextPool(uint32_t default_timeout_ms = 5000);

    std::unique_ptr<SmtContext> create_context() const;
    uint32_t default_timeout_ms() const;

private:
    uint32_t m_default_timeout_ms;
};

nlohmann::json to_json(const solve_result_t& r);
nlohmann::json to_json(const model_entry_t& e);

bool ensure_z3_runtime();

}
}
}
