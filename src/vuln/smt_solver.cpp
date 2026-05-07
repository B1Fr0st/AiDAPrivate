#include "../aida_pro.hpp"

#include "smt_solver.hpp"
#include "embedded_libz3.hpp"

#include <z3++.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <utility>

namespace aida
{
namespace vuln
{
namespace smt
{

bool ensure_z3_runtime()
{
#if defined(_WIN32)
    return aida::vuln::embedded_libz3::ensure_loaded();
#else
    return true;
#endif
}

namespace
{

struct decl_record_t
{
    z3::expr expr_value;
    int      width;
};

constexpr const char* k_unavailable = "z3 runtime unavailable";

std::string z3_message(const z3::exception& e)
{
    const char* m = e.msg();
    if (m == nullptr)
        return std::string("z3 exception");
    return std::string(m);
}

std::string sort_to_string(const z3::sort& s)
{
    try
    {
        return s.to_string();
    }
    catch (const z3::exception&)
    {
        return std::string("<sort?>");
    }
    catch (...)
    {
        return std::string("<sort?>");
    }
}

std::string symbol_to_string(const z3::symbol& sym)
{
    try
    {
        if (sym.kind() == Z3_STRING_SYMBOL)
            return sym.str();
        char buf[32];
        ::qsnprintf(buf, sizeof(buf), "k!%d", sym.to_int());
        return std::string(buf);
    }
    catch (const z3::exception&)
    {
        return std::string("?");
    }
    catch (...)
    {
        return std::string("?");
    }
}

std::string expr_to_string(const z3::expr& e)
{
    try
    {
        return e.to_string();
    }
    catch (const z3::exception&)
    {
        return std::string();
    }
    catch (...)
    {
        return std::string();
    }
}

void populate_model_entries(z3::context& ctx,
                            const z3::model& m,
                            std::vector<model_entry_t>& out)
{
    unsigned const n_consts = m.num_consts();
    out.reserve(static_cast<size_t>(n_consts));
    for (unsigned i = 0; i < n_consts; ++i)
    {
        try
        {
            z3::func_decl fd = m.get_const_decl(i);
            z3::expr v = m.get_const_interp(fd);
            model_entry_t entry;
            entry.name = symbol_to_string(fd.name());
            z3::sort s = v.get_sort();
            entry.sort = sort_to_string(s);
            entry.text_value = expr_to_string(v);
            if (s.is_bv())
            {
                entry.is_bitvector = true;
                entry.bv_width = static_cast<int>(s.bv_size());
                uint64_t val = 0;
                if (Z3_get_numeral_uint64(ctx, v, &val))
                    entry.bv_value = val;
                else
                    entry.bv_value = 0;
            }
            else
            {
                entry.is_bitvector = false;
                entry.bv_width = 0;
                entry.bv_value = 0;
            }
            out.push_back(std::move(entry));
        }
        catch (const z3::exception&)
        {
            continue;
        }
        catch (...)
        {
            continue;
        }
    }
}

std::string solver_to_smtlib2(z3::solver& solver)
{
    try
    {
        return solver.to_smt2();
    }
    catch (const z3::exception&)
    {
        return std::string();
    }
    catch (...)
    {
        return std::string();
    }
}

}

struct SmtContext::impl_t
{
    z3::context                                     ctx;
    std::unique_ptr<z3::solver>                     solver;
    std::unordered_map<std::string, decl_record_t>  declared_vars;
    std::string                                     last_err;
    bool                                            available = false;
    mutable std::mutex                              mtx;

    impl_t() = default;

    bool ensure_var(const std::string& name, int width, z3::expr& out_expr)
    {
        auto it = declared_vars.find(name);
        if (it != declared_vars.end())
        {
            if (it->second.width != width)
            {
                last_err = "bv re-declared with different width";
                return false;
            }
            out_expr = it->second.expr_value;
            return true;
        }
        try
        {
            z3::expr e = ctx.bv_const(name.c_str(), static_cast<unsigned>(width));
            auto ins = declared_vars.emplace(name, decl_record_t{e, width});
            out_expr = ins.first->second.expr_value;
            return true;
        }
        catch (const z3::exception& ex)
        {
            last_err = z3_message(ex);
            return false;
        }
        catch (...)
        {
            last_err = "unknown z3 error in declare";
            return false;
        }
    }
};

SmtContext::SmtContext()
    : m_impl(std::make_unique<impl_t>())
{
    if (!ensure_z3_runtime())
    {
        m_impl->last_err = "libz3.dll not loadable";
        m_impl->available = false;
        return;
    }
    try
    {
        m_impl->ctx.set_enable_exceptions(true);
        m_impl->solver = std::make_unique<z3::solver>(m_impl->ctx);
        z3::params p(m_impl->ctx);
        p.set("model", true);
        p.set("unsat_core", false);
        m_impl->solver->set(p);
        m_impl->available = true;
    }
    catch (const z3::exception& e)
    {
        m_impl->last_err = z3_message(e);
        m_impl->available = false;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 init error";
        m_impl->available = false;
    }
}

SmtContext::~SmtContext() = default;

bool SmtContext::is_available() const
{
    return m_impl && m_impl->available;
}

const char* SmtContext::last_error() const
{
    if (!m_impl)
        return "";
    return m_impl->last_err.c_str();
}

bool SmtContext::declare_bv(const std::string& name, int bit_width)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return false;
    }
    if (bit_width <= 0 || bit_width > 8192)
    {
        m_impl->last_err = "invalid bit width";
        return false;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    auto it = m_impl->declared_vars.find(name);
    if (it != m_impl->declared_vars.end())
    {
        if (it->second.width != bit_width)
        {
            m_impl->last_err = "bv re-declared with different width";
            return false;
        }
        return true;
    }
    try
    {
        z3::expr e = m_impl->ctx.bv_const(name.c_str(), static_cast<unsigned>(bit_width));
        m_impl->declared_vars.emplace(name, decl_record_t{e, bit_width});
        return true;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in declare_bv";
        return false;
    }
}

bool SmtContext::declare_bool(const std::string& name)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return false;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    auto it = m_impl->declared_vars.find(name);
    if (it != m_impl->declared_vars.end())
    {
        if (it->second.width != 0)
        {
            m_impl->last_err = "bool re-declared with bv width";
            return false;
        }
        return true;
    }
    try
    {
        z3::expr e = m_impl->ctx.bool_const(name.c_str());
        m_impl->declared_vars.emplace(name, decl_record_t{e, 0});
        return true;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in declare_bool";
        return false;
    }
}

bool SmtContext::assert_smtlib2(const std::string& formula)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return false;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    try
    {
        z3::sort_vector sort_vec(m_impl->ctx);
        z3::func_decl_vector decl_vec(m_impl->ctx);
        for (const auto& kv : m_impl->declared_vars)
        {
            try
            {
                decl_vec.push_back(kv.second.expr_value.decl());
            }
            catch (const z3::exception&)
            {
                continue;
            }
        }
        z3::expr_vector exprs = m_impl->ctx.parse_string(formula.c_str(), sort_vec, decl_vec);
        for (unsigned i = 0; i < exprs.size(); ++i)
            m_impl->solver->add(exprs[i]);
        return true;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in assert_smtlib2";
        return false;
    }
}

bool SmtContext::assert_bv_eq_const(const std::string& var, uint64_t value, int width)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return false;
    }
    if (width <= 0 || width > 8192)
    {
        m_impl->last_err = "invalid bit width";
        return false;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    z3::expr lhs(m_impl->ctx);
    if (!m_impl->ensure_var(var, width, lhs))
        return false;
    try
    {
        z3::expr rhs = m_impl->ctx.bv_val(static_cast<uint64_t>(value), static_cast<unsigned>(width));
        m_impl->solver->add(lhs == rhs);
        return true;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in assert_bv_eq_const";
        return false;
    }
}

bool SmtContext::assert_bv_ult(const std::string& var, uint64_t value, int width)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return false;
    }
    if (width <= 0 || width > 8192)
    {
        m_impl->last_err = "invalid bit width";
        return false;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    z3::expr lhs(m_impl->ctx);
    if (!m_impl->ensure_var(var, width, lhs))
        return false;
    try
    {
        z3::expr rhs = m_impl->ctx.bv_val(static_cast<uint64_t>(value), static_cast<unsigned>(width));
        m_impl->solver->add(z3::ult(lhs, rhs));
        return true;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in assert_bv_ult";
        return false;
    }
}

bool SmtContext::assert_bv_ugt(const std::string& var, uint64_t value, int width)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return false;
    }
    if (width <= 0 || width > 8192)
    {
        m_impl->last_err = "invalid bit width";
        return false;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    z3::expr lhs(m_impl->ctx);
    if (!m_impl->ensure_var(var, width, lhs))
        return false;
    try
    {
        z3::expr rhs = m_impl->ctx.bv_val(static_cast<uint64_t>(value), static_cast<unsigned>(width));
        m_impl->solver->add(z3::ugt(lhs, rhs));
        return true;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in assert_bv_ugt";
        return false;
    }
}

bool SmtContext::assert_bv_slt(const std::string& var, int64_t value, int width)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return false;
    }
    if (width <= 0 || width > 8192)
    {
        m_impl->last_err = "invalid bit width";
        return false;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    z3::expr lhs(m_impl->ctx);
    if (!m_impl->ensure_var(var, width, lhs))
        return false;
    try
    {
        z3::expr rhs = m_impl->ctx.bv_val(static_cast<int64_t>(value), static_cast<unsigned>(width));
        m_impl->solver->add(lhs < rhs);
        return true;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in assert_bv_slt";
        return false;
    }
}

bool SmtContext::assert_bv_sgt(const std::string& var, int64_t value, int width)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return false;
    }
    if (width <= 0 || width > 8192)
    {
        m_impl->last_err = "invalid bit width";
        return false;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    z3::expr lhs(m_impl->ctx);
    if (!m_impl->ensure_var(var, width, lhs))
        return false;
    try
    {
        z3::expr rhs = m_impl->ctx.bv_val(static_cast<int64_t>(value), static_cast<unsigned>(width));
        m_impl->solver->add(lhs > rhs);
        return true;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return false;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in assert_bv_sgt";
        return false;
    }
}

void SmtContext::push()
{
    if (!is_available())
        return;
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    try
    {
        m_impl->solver->push();
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in push";
    }
}

void SmtContext::pop()
{
    if (!is_available())
        return;
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    try
    {
        m_impl->solver->pop(1);
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in pop";
    }
}

void SmtContext::reset()
{
    if (!is_available())
        return;
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    try
    {
        m_impl->solver->reset();
        m_impl->declared_vars.clear();
        m_impl->last_err.clear();
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in reset";
    }
}

solve_result_t SmtContext::check()
{
    solve_result_t r;
    if (!is_available())
    {
        r.result = result_t::unknown;
        r.reason = m_impl ? m_impl->last_err : std::string(k_unavailable);
        if (r.reason.empty())
            r.reason = k_unavailable;
        return r;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    auto t0 = std::chrono::steady_clock::now();
    try
    {
        z3::check_result cr = m_impl->solver->check();
        auto t1 = std::chrono::steady_clock::now();
        r.solve_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        switch (cr)
        {
        case z3::sat:
        {
            r.result = result_t::sat;
            try
            {
                z3::model m = m_impl->solver->get_model();
                populate_model_entries(m_impl->ctx, m, r.model);
            }
            catch (const z3::exception& ex)
            {
                r.reason = z3_message(ex);
            }
            catch (...)
            {
                r.reason = "model extraction failed";
            }
            break;
        }
        case z3::unsat:
            r.result = result_t::unsat;
            break;
        case z3::unknown:
        default:
            r.result = result_t::unknown;
            try
            {
                r.reason = m_impl->solver->reason_unknown();
            }
            catch (const z3::exception&)
            {
                r.reason = "unknown";
            }
            break;
        }
    }
    catch (const z3::exception& ex)
    {
        auto t1 = std::chrono::steady_clock::now();
        r.solve_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        r.result = result_t::unknown;
        r.reason = z3_message(ex);
        m_impl->last_err = r.reason;
    }
    catch (...)
    {
        auto t1 = std::chrono::steady_clock::now();
        r.solve_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        r.result = result_t::unknown;
        r.reason = "unknown z3 error during check";
        m_impl->last_err = r.reason;
    }
    r.smtlib_dump = solver_to_smtlib2(*m_impl->solver);
    return r;
}

solve_result_t SmtContext::check_with_timeout(uint32_t timeout_ms)
{
    solve_result_t r;
    if (!is_available())
    {
        r.result = result_t::unknown;
        r.reason = m_impl ? m_impl->last_err : std::string(k_unavailable);
        if (r.reason.empty())
            r.reason = k_unavailable;
        return r;
    }
    {
        std::lock_guard<std::mutex> lk(m_impl->mtx);
        try
        {
            z3::params p(m_impl->ctx);
            p.set(":timeout", static_cast<unsigned>(timeout_ms));
            p.set("model", true);
            m_impl->solver->set(p);
        }
        catch (const z3::exception& ex)
        {
            m_impl->last_err = z3_message(ex);
        }
        catch (...)
        {
            m_impl->last_err = "unknown z3 error setting timeout";
        }
    }
    r = check();
    {
        std::lock_guard<std::mutex> lk(m_impl->mtx);
        try
        {
            z3::params p(m_impl->ctx);
            p.set(":timeout", static_cast<unsigned>(0));
            p.set("model", true);
            m_impl->solver->set(p);
        }
        catch (const z3::exception&)
        {
        }
        catch (...)
        {
        }
    }
    return r;
}

std::optional<uint64_t> SmtContext::max_value_bv(const std::string& var, int width)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return std::nullopt;
    }
    if (width <= 0 || width > 64)
    {
        m_impl->last_err = "max_value_bv requires width in [1,64]";
        return std::nullopt;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    auto it = m_impl->declared_vars.find(var);
    if (it == m_impl->declared_vars.end() || it->second.width <= 0)
    {
        m_impl->last_err = "max_value_bv: variable not declared as bv";
        return std::nullopt;
    }
    if (it->second.width != width)
    {
        m_impl->last_err = "max_value_bv: width mismatch";
        return std::nullopt;
    }
    try
    {
        z3::optimize opt(m_impl->ctx);
        z3::expr_vector cur = m_impl->solver->assertions();
        for (unsigned i = 0; i < cur.size(); ++i)
            opt.add(cur[i]);
        opt.maximize(it->second.expr_value);
        z3::check_result cr = opt.check();
        if (cr != z3::sat)
            return std::nullopt;
        z3::model m = opt.get_model();
        z3::expr v = m.eval(it->second.expr_value, true);
        uint64_t val = 0;
        if (Z3_get_numeral_uint64(m_impl->ctx, v, &val))
            return val;
        return std::nullopt;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return std::nullopt;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in max_value_bv";
        return std::nullopt;
    }
}

std::optional<uint64_t> SmtContext::min_value_bv(const std::string& var, int width)
{
    if (!is_available())
    {
        if (m_impl) m_impl->last_err = k_unavailable;
        return std::nullopt;
    }
    if (width <= 0 || width > 64)
    {
        m_impl->last_err = "min_value_bv requires width in [1,64]";
        return std::nullopt;
    }
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    auto it = m_impl->declared_vars.find(var);
    if (it == m_impl->declared_vars.end() || it->second.width <= 0)
    {
        m_impl->last_err = "min_value_bv: variable not declared as bv";
        return std::nullopt;
    }
    if (it->second.width != width)
    {
        m_impl->last_err = "min_value_bv: width mismatch";
        return std::nullopt;
    }
    try
    {
        z3::optimize opt(m_impl->ctx);
        z3::expr_vector cur = m_impl->solver->assertions();
        for (unsigned i = 0; i < cur.size(); ++i)
            opt.add(cur[i]);
        opt.minimize(it->second.expr_value);
        z3::check_result cr = opt.check();
        if (cr != z3::sat)
            return std::nullopt;
        z3::model m = opt.get_model();
        z3::expr v = m.eval(it->second.expr_value, true);
        uint64_t val = 0;
        if (Z3_get_numeral_uint64(m_impl->ctx, v, &val))
            return val;
        return std::nullopt;
    }
    catch (const z3::exception& ex)
    {
        m_impl->last_err = z3_message(ex);
        return std::nullopt;
    }
    catch (...)
    {
        m_impl->last_err = "unknown z3 error in min_value_bv";
        return std::nullopt;
    }
}

std::string SmtContext::to_smtlib2() const
{
    if (!is_available())
        return std::string();
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    return solver_to_smtlib2(*m_impl->solver);
}

bool SmtContext::smtlib2_quick_check(const std::string& formula,
                                     result_t& out_result,
                                     uint32_t timeout_ms)
{
    out_result = result_t::unknown;
    if (!ensure_z3_runtime())
        return false;
    try
    {
        z3::context ctx;
        ctx.set_enable_exceptions(true);
        z3::solver s(ctx);
        z3::params p(ctx);
        p.set(":timeout", static_cast<unsigned>(timeout_ms));
        p.set("model", true);
        s.set(p);
        z3::expr_vector exprs = ctx.parse_string(formula.c_str());
        for (unsigned i = 0; i < exprs.size(); ++i)
            s.add(exprs[i]);
        z3::check_result cr = s.check();
        if (cr == z3::sat)
            out_result = result_t::sat;
        else if (cr == z3::unsat)
            out_result = result_t::unsat;
        else
            out_result = result_t::unknown;
        return true;
    }
    catch (const z3::exception&)
    {
        out_result = result_t::unknown;
        return false;
    }
    catch (...)
    {
        out_result = result_t::unknown;
        return false;
    }
}

nlohmann::json to_json(const model_entry_t& e)
{
    nlohmann::json j;
    j["name"] = e.name;
    j["sort"] = e.sort;
    j["text"] = e.text_value;
    j["is_bitvector"] = e.is_bitvector;
    if (e.is_bitvector)
    {
        j["bv_value"] = e.bv_value;
        j["bv_width"] = e.bv_width;
        char buf[32];
        ::qsnprintf(buf, sizeof(buf), "0x%llx",
                    static_cast<unsigned long long>(e.bv_value));
        j["bv_value_hex"] = buf;
    }
    return j;
}

nlohmann::json to_json(const solve_result_t& r)
{
    nlohmann::json j;
    j["result"] = result_str(r.result);
    j["solve_ms"] = r.solve_ms;
    j["reason"] = r.reason;
    j["smtlib"] = r.smtlib_dump;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& e : r.model)
        arr.push_back(to_json(e));
    j["model"] = arr;
    return j;
}

}
}
}
