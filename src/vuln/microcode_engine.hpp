#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>
#include <string>

#include <nlohmann/json.hpp>
#include <ida.hpp>
#include <hexrays.hpp>

namespace aida
{
namespace vuln
{
namespace microcode
{

struct mba_deleter_t
{
    void operator()(mba_t* mba) const noexcept;
};

using mba_ptr_t = std::unique_ptr<mba_t, mba_deleter_t>;

struct mba_handle_t
{
    mba_ptr_t        mba;
    mba_maturity_t   maturity = MMAT_ZERO;
    ea_t             func_ea = BADADDR;

    mba_handle_t() = default;
    mba_handle_t(mba_handle_t&&) noexcept = default;
    mba_handle_t& operator=(mba_handle_t&&) noexcept = default;
    mba_handle_t(const mba_handle_t&) = delete;
    mba_handle_t& operator=(const mba_handle_t&) = delete;
};

mba_maturity_t parse_maturity(const std::string& s);
const char*    maturity_str(mba_maturity_t mat);

std::optional<mba_handle_t> generate(ea_t func_ea, mba_maturity_t mat = MMAT_LVARS);
std::vector<mba_handle_t> generate_at_maturities(ea_t func_ea, const std::vector<mba_maturity_t>& mats);

nlohmann::json dump_mba(const mba_t& mba, size_t inst_offset, size_t inst_limit);

nlohmann::json mop_to_json(const mop_t& op);
nlohmann::json minsn_to_json(const minsn_t& ins);

void iter_with_visitors(mba_t& mba,
                        const std::function<bool(int, minsn_t&)>& insn_visitor,
                        const std::function<bool(int, mop_t&, bool)>& mop_visitor = {});

std::pair<mlist_t, mlist_t> build_use_def_lists(mblock_t& blk,
                                                const minsn_t& ins,
                                                maymust_t mm = MAY_ACCESS);

struct def_use_t
{
    std::vector<ea_t>        defs;
    std::vector<ea_t>        uses;
    std::vector<std::string> reaching_defs;
    std::vector<std::string> constraints;
};

def_use_t def_use_chain(mba_t& mba, const mop_t& tracked);
def_use_t def_use_chain_for_lvar(mba_t& mba, int lvar_idx);
def_use_t def_use_chain_for_stkvar(mba_t& mba, sval_t off);
def_use_t def_use_chain_for_reg(mba_t& mba, mreg_t reg);

bool is_freed_then_used(mba_t& mba, const mop_t& ptr, ea_t& free_ea, ea_t& use_ea);
bool is_double_freed(mba_t& mba, const mop_t& ptr, ea_t& free1_ea, ea_t& free2_ea);
bool has_uninit_read(mba_t& mba, const mop_t& var, ea_t& read_ea);

bool mop_equal(const mop_t& a, const mop_t& b);
bool mop_aliases(const mop_t& a, const mop_t& b);
std::string mop_describe(const mop_t& op);

bool resolve_call_target(const minsn_t& ins, ea_t& callee_ea, std::string& callee_name);

struct call_arg_info_t
{
    int          arg_index = -1;
    mop_t        value;
    ea_t         init_ea = BADADDR;
    bool         is_literal = false;
    uint64_t     literal_value = 0;
    std::string  summary;
};

std::vector<call_arg_info_t> collect_call_arguments(const minsn_t& call_ins);

bool insn_predates(const mba_t& mba, ea_t earlier_ea, ea_t later_ea);

ea_t find_first_call_to(mba_t& mba, const std::vector<std::string>& callee_names);
std::vector<ea_t> find_all_calls_to(mba_t& mba, const std::vector<std::string>& callee_names);

bool hexrays_query_use_def(ea_t func_ea,
                           ea_t at_ea,
                           const mop_t& op,
                           bool def_not_use,
                           mlist_t* out_list,
                           qstring* err);

}
}
}
