#include <windows.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <atomic>
#include <chrono>

#include "virtualizer.hpp"
#include "vm_compiler.hpp"

namespace ad = anti_tamper::virtualizer::detail;
namespace vc = anti_tamper::vm_compiler;

static int g_failures = 0;
static int g_passes = 0;

static void check_eq_u64(const char* name, uint64_t got, uint64_t expected)
{
    if (got != expected)
    {
        std::printf("[FAIL] %s: got=0x%016llX expected=0x%016llX\n",
                    name,
                    static_cast<unsigned long long>(got),
                    static_cast<unsigned long long>(expected));
        ++g_failures;
    }
    else
    {
        std::printf("[PASS] %s: got=0x%016llX\n", name, static_cast<unsigned long long>(got));
        ++g_passes;
    }
}

static void check_true(const char* name, bool cond)
{
    if (!cond)
    {
        std::printf("[FAIL] %s\n", name);
        ++g_failures;
    }
    else
    {
        std::printf("[PASS] %s\n", name);
        ++g_passes;
    }
}

static void check_neq(const char* name, uint64_t got, uint64_t expected)
{
    if (got == expected)
    {
        std::printf("[FAIL] %s: got=0x%016llX (should differ from expected=0x%016llX)\n",
                    name,
                    static_cast<unsigned long long>(got),
                    static_cast<unsigned long long>(expected));
        ++g_failures;
    }
    else
    {
        std::printf("[PASS] %s: got=0x%016llX != 0x%016llX\n", name,
                    static_cast<unsigned long long>(got),
                    static_cast<unsigned long long>(expected));
        ++g_passes;
    }
}

struct test_vm_holder_t
{
    ad::vm_state_t vm{};
    ad::taint_sever_cell_t* taint_ring;
    uint32_t taint_ring_size;
    ad::handler_pool_t* pool;

    test_vm_holder_t()
        : taint_ring_size(ad::TAINT_SEVER_RING_SIZE), pool(nullptr)
    {
        taint_ring = new ad::taint_sever_cell_t[taint_ring_size];
        for (uint32_t i = 0; i < taint_ring_size; ++i)
        {
            taint_ring[i].tag.store(0);
            taint_ring[i].value.store(0);
            taint_ring[i].dirty.store(0);
        }
    }

    ~test_vm_holder_t()
    {
        if (vm.stack)
        {
            delete[] vm.stack;
            vm.stack = nullptr;
        }
        if (pool)
        {
            delete pool;
            pool = nullptr;
        }
        delete[] taint_ring;
    }
};

static void manual_init_vm(test_vm_holder_t& holder, uint64_t seed)
{
    ad::vm_state_t& vm = holder.vm;
    std::memset(&vm, 0, sizeof(vm));
    vm.stack_size = 4096;
    vm.stack = new uint8_t[vm.stack_size];
    std::memset(vm.stack, 0, vm.stack_size);
    vm.rsp = vm.stack_size;
    vm.halted = false;
    vm.max_insn = 100000;
    vm.insn_count = 0;
    vm.rolling_key = seed ^ 0x6A09E667F3BCC908ULL;
    vm.handler_chain_key = seed ^ 0xBB67AE8584CAA73BULL;
    vm.context_entropy = seed ^ 0x510E527FADE682D1ULL;
    vm.shuffle_counter = 0;
    ad::cipher_stream_init(vm.stream, vm.rolling_key);

    vm.continuation.next_handler = 0;
    vm.continuation.chain_nonce = seed ^ 0x3C6EF372FE94F82BULL;
    vm.ctx_crypt.reg_mask = 0;
    vm.ctx_crypt.flags_mask = 0;
    vm.ctx_crypt.rsp_mask = 0;
    vm.ctx_crypt.encrypted = false;

    for (int i = 0; i < 16; ++i)
    {
        vm.reg_shuffle[i] = static_cast<uint8_t>(i);
        vm.reg_unshuffle[i] = static_cast<uint8_t>(i);
        vm.reg_keys[i] = 0;
        vm.fake_regs[i] = 0;
        vm.fake_shuffle[i] = static_cast<uint8_t>(i);
    }
    vm.reg_xor_key = 0;
    vm.fake_decoy_key = 0;
    vm.last_op_result = 0;

    holder.pool = new ad::handler_pool_t{};
    vm.pool = holder.pool;

    for (int i = 0; i < 256; ++i)
    {
        vm.opcode_map[i] = static_cast<uint8_t>(i);
        vm.reverse_map[i] = static_cast<uint8_t>(i);
    }
    std::memcpy(vm.pool->opcode_map, vm.opcode_map, 256);
    std::memcpy(vm.pool->reverse_map, vm.reverse_map, 256);
    ad::build_handler_pool(*vm.pool, vm.reverse_map, seed ^ 0x428A2F98D728AE22ULL);
    ad::build_poly_table(*vm.pool);
    vm.pool->handler_set.initialized = false;
    ad::build_handler_set(*vm.pool);

    vm.taint_ring = holder.taint_ring;
    vm.taint_ring_size = holder.taint_ring_size;
    vm.taint_seq = 0;
    for (uint32_t i = 0; i < holder.taint_ring_size; ++i)
    {
        holder.taint_ring[i].tag.store(0);
        holder.taint_ring[i].value.store(0);
        holder.taint_ring[i].dirty.store(0);
    }
}

static void prepare_vm(test_vm_holder_t& holder, uint64_t seed)
{
    manual_init_vm(holder, seed);
}

static ad::vm_program_t build_simple_add_program(const ad::vm_state_t& vm,
                                                  uint64_t cipher_key,
                                                  uint64_t handler_chain_key,
                                                  uint64_t imm_a, uint64_t imm_b)
{
    vc::program_t prog;
    prog.set_key(cipher_key);
    prog.set_opcode_map(vm.opcode_map);

    prog.emit_load_imm(0, imm_a);
    prog.emit_load_imm(1, imm_b);
    prog.emit_add(2, 0, 1);
    prog.emit_halt();

    auto bc = prog.finalize();

    return vc::build_program(std::move(bc), vm.opcode_map, cipher_key, handler_chain_key,
                             cipher_key ^ handler_chain_key ^ 0xCAFEBABEDEADBEEFULL);
}

static bool run_basic_add_test()
{
    std::printf("\n=== Test 1: basic LOAD_IMM/ADD/HALT ===\n");
    test_vm_holder_t holder;
    const uint64_t seed = 0x1122334455667788ULL;
    prepare_vm(holder, seed);

    uint64_t cipher_key = holder.vm.rolling_key;
    uint64_t hck = holder.vm.handler_chain_key;

    auto program = build_simple_add_program(holder.vm, cipher_key, hck, 5ULL, 7ULL);

    std::printf("bytecode size: %zu, dag nodes: %zu\n",
                program.bc.size(), program.dag.size());
    for (size_t i = 0; i < program.dag.size(); ++i)
    {
        std::printf("  node[%zu]: bc_offset=%u bc_length=%u next_a=%u next_b=%u enter_hash=0x%016llX\n",
                    i, program.dag[i].bc_offset, program.dag[i].bc_length,
                    program.dag[i].next_node_a, program.dag[i].next_node_b,
                    static_cast<unsigned long long>(program.dag[i].enter_hash));
    }

    auto t_before = std::chrono::high_resolution_clock::now();
    uint64_t result = ad::vm_execute_program(holder.vm, program);
    auto t_after = std::chrono::high_resolution_clock::now();

    auto cycles = std::chrono::duration_cast<std::chrono::microseconds>(t_after - t_before).count();
    std::printf("execution: %lld microseconds for %u instructions\n",
                static_cast<long long>(cycles), holder.vm.insn_count);

    uint64_t r2 = ad::read_vreg(holder.vm, 2);
    check_eq_u64("regs[2] after ADD r2, r0(5), r1(7)", r2, 12ULL);
    check_true("vm halted normally", holder.vm.halted);
    check_eq_u64("dag_violation_code is 0", holder.vm.dag_violation_code, 0ULL);
    return r2 == 12ULL;
}

static bool run_tampering_test()
{
    std::printf("\n=== Test 2: tampering detection (flip immediate byte) ===\n");
    test_vm_holder_t holder;
    const uint64_t seed = 0x9988776655443322ULL;
    prepare_vm(holder, seed);

    uint64_t cipher_key = holder.vm.rolling_key;
    uint64_t hck = holder.vm.handler_chain_key;

    auto program = build_simple_add_program(holder.vm, cipher_key, hck, 5ULL, 7ULL);

    if (program.bc.size() < 5)
    {
        std::printf("[FAIL] bytecode too short to tamper\n");
        ++g_failures;
        return false;
    }

    program.bc[4] ^= 0x42;

    uint64_t result = ad::vm_execute_program(holder.vm, program);
    uint64_t r2 = ad::read_vreg(holder.vm, 2);

    bool tampering_detected = holder.vm.dag_violation_code != 0
                              || r2 == 0xDEADBEEFDEADBEEFULL
                              || r2 != 12ULL;
    std::printf("post-tamper r2=0x%016llX dag_violation_code=0x%016llX halted=%d\n",
                static_cast<unsigned long long>(r2),
                static_cast<unsigned long long>(holder.vm.dag_violation_code),
                holder.vm.halted ? 1 : 0);

    check_true("tampering detected (DAG hash mismatch or wrong result)", tampering_detected);
    return tampering_detected;
}

static bool run_keyed_dag_test()
{
    std::printf("\n=== Test 3: DAG enter_hash sequence depends on rolling_key ===\n");

    test_vm_holder_t holder1;
    test_vm_holder_t holder2;
    prepare_vm(holder1, 0x1111111111111111ULL);
    prepare_vm(holder2, 0x2222222222222222ULL);

    uint64_t k1 = holder1.vm.rolling_key;
    uint64_t k2 = holder2.vm.rolling_key;
    uint64_t hck1 = holder1.vm.handler_chain_key;
    uint64_t hck2 = holder2.vm.handler_chain_key;

    auto program1 = build_simple_add_program(holder1.vm, k1, hck1, 5ULL, 7ULL);
    auto program2 = build_simple_add_program(holder2.vm, k2, hck2, 5ULL, 7ULL);

    bool any_diff = false;
    if (program1.dag.size() == program2.dag.size())
    {
        for (size_t i = 0; i < program1.dag.size(); ++i)
        {
            if (program1.dag[i].enter_hash != program2.dag[i].enter_hash)
            {
                any_diff = true;
                break;
            }
        }
    }
    else
    {
        any_diff = true;
    }

    std::printf("dag1 size: %zu, dag2 size: %zu, hashes differ: %d\n",
                program1.dag.size(), program2.dag.size(), any_diff ? 1 : 0);

    for (size_t i = 0; i < (program1.dag.size() < program2.dag.size() ? program1.dag.size() : program2.dag.size()); ++i)
    {
        std::printf("  node[%zu]: hash1=0x%016llX hash2=0x%016llX\n",
                    i,
                    static_cast<unsigned long long>(program1.dag[i].enter_hash),
                    static_cast<unsigned long long>(program2.dag[i].enter_hash));
    }

    check_true("different rolling_keys produce different DAG enter_hash sequences", any_diff);
    return any_diff;
}

static ad::vm_program_t build_branch_program(const ad::vm_state_t& vm,
                                              uint64_t cipher_key,
                                              uint64_t handler_chain_key,
                                              uint64_t lhs, uint64_t rhs)
{
    vc::program_t prog;
    prog.set_key(cipher_key);
    prog.set_opcode_map(vm.opcode_map);

    auto label_taken = prog.create_label();
    auto label_after = prog.create_label();

    prog.emit_load_imm(0, lhs);
    prog.emit_load_imm(1, rhs);
    prog.emit_cmp(0, 1);
    prog.emit_jz_label(label_taken);

    prog.emit_load_imm(2, 0xAAAAAAAAULL);
    prog.emit_jmp_label(label_after);

    prog.bind_label(label_taken);
    prog.emit_load_imm(2, 0xBBBBBBBBULL);

    prog.bind_label(label_after);
    prog.emit_halt();

    auto bc = prog.finalize();
    return vc::build_program(std::move(bc), vm.opcode_map, cipher_key, handler_chain_key,
                             cipher_key ^ handler_chain_key ^ 0xCAFEBABEDEADBEEFULL);
}

static bool run_branch_test()
{
    std::printf("\n=== Test 4: branch dispatch (JZ taken vs not-taken) ===\n");

    bool ok = true;

    {
        test_vm_holder_t holder;
        prepare_vm(holder, 0xAABBCCDDEEFF1122ULL);
        auto prog = build_branch_program(holder.vm, holder.vm.rolling_key,
                                          holder.vm.handler_chain_key,
                                          0x42ULL, 0x42ULL);
        ad::vm_execute_program(holder.vm, prog);
        uint64_t r2 = ad::read_vreg(holder.vm, 2);
        std::printf("equal case (lhs==rhs): r2=0x%016llX dag_node=%u halted=%d insn_count=%u\n",
                    static_cast<unsigned long long>(r2),
                    holder.vm.dag_node, holder.vm.halted, holder.vm.insn_count);
        if (r2 != 0xBBBBBBBBULL)
        {
            ok = false;
        }
        check_eq_u64("JZ taken branch loads 0xBBBBBBBB", r2, 0xBBBBBBBBULL);
    }

    {
        test_vm_holder_t holder;
        prepare_vm(holder, 0x11FFEEDDCCBBAA99ULL);
        auto prog = build_branch_program(holder.vm, holder.vm.rolling_key,
                                          holder.vm.handler_chain_key,
                                          0x42ULL, 0x99ULL);
        ad::vm_execute_program(holder.vm, prog);
        uint64_t r2 = ad::read_vreg(holder.vm, 2);
        std::printf("inequal case (lhs!=rhs): r2=0x%016llX\n", static_cast<unsigned long long>(r2));
        if (r2 != 0xAAAAAAAAULL)
        {
            ok = false;
        }
        check_eq_u64("JZ fall-through loads 0xAAAAAAAA", r2, 0xAAAAAAAAULL);
    }

    return ok;
}

static ad::vm_program_t build_vcall_program(const ad::vm_state_t& vm,
                                             uint64_t cipher_key,
                                             uint64_t handler_chain_key)
{
    vc::program_t prog;
    prog.set_key(cipher_key);
    prog.set_opcode_map(vm.opcode_map);

    auto label_func = prog.create_label();
    auto label_end  = prog.create_label();

    prog.emit_load_imm(0, 0xAAULL);
    prog.emit_load_imm(1, 0x55ULL);
    prog.emit_vcall_label(label_func);
    prog.emit_jmp_label(label_end);

    prog.bind_label(label_func);
    prog.emit_xor(2, 0, 1);
    prog.emit_vret();

    prog.bind_label(label_end);
    prog.emit_load_imm(3, 0xDEADBEEFULL);
    prog.emit_halt();

    auto bc = prog.finalize();
    return vc::build_program(std::move(bc), vm.opcode_map, cipher_key, handler_chain_key,
                             cipher_key ^ handler_chain_key ^ 0xCAFEBABEDEADBEEFULL);
}

static bool run_vcall_test()
{
    std::printf("\n=== Test 5: VCALL/VRET round trip ===\n");

    test_vm_holder_t holder;
    prepare_vm(holder, 0xCC55BBAA77882244ULL);

    auto prog = build_vcall_program(holder.vm, holder.vm.rolling_key,
                                     holder.vm.handler_chain_key);
    ad::vm_execute_program(holder.vm, prog);

    uint64_t r0 = ad::read_vreg(holder.vm, 0);
    uint64_t r1 = ad::read_vreg(holder.vm, 1);
    uint64_t r3 = ad::read_vreg(holder.vm, 3);
    std::printf("after vcall: r0=0x%016llX r1=0x%016llX r3=0x%016llX dag_node=%u halted=%d insn_count=%u\n",
                static_cast<unsigned long long>(r0),
                static_cast<unsigned long long>(r1),
                static_cast<unsigned long long>(r3),
                holder.vm.dag_node, holder.vm.halted, holder.vm.insn_count);

    bool flow_ok = (r3 == 0xDEADBEEFULL) && (r0 == 0xAAULL) && (r1 == 0x55ULL) && holder.vm.halted;
    check_true("VCALL/VRET control flow returns to caller (r3 loaded after VRET)", flow_ok);
    return flow_ok;
}

static ad::vm_program_t build_taint_program(const ad::vm_state_t& vm,
                                              uint64_t cipher_key,
                                              uint64_t handler_chain_key,
                                              uint64_t value)
{
    vc::program_t prog;
    prog.set_key(cipher_key);
    prog.set_opcode_map(vm.opcode_map);

    prog.emit_load_imm(0, value);
    prog.emit_store_reg(3, 0);
    prog.emit_load_reg(4, 3);
    prog.emit_halt();

    auto bc = prog.finalize();
    return vc::build_program(std::move(bc), vm.opcode_map, cipher_key, handler_chain_key,
                             cipher_key ^ handler_chain_key ^ 0xCAFEBABEDEADBEEFULL);
}

static bool run_taint_test()
{
    std::printf("\n=== Test 6: taint-severing (store_reg / load_reg through ring) ===\n");

    test_vm_holder_t holder;
    prepare_vm(holder, 0xFEEDBEEFCAFEBABEULL);

    const uint64_t expected_value = 0x4242424242424242ULL;
    auto prog = build_taint_program(holder.vm, holder.vm.rolling_key,
                                     holder.vm.handler_chain_key,
                                     expected_value);
    ad::vm_execute_program(holder.vm, prog);

    uint64_t r4 = ad::read_vreg(holder.vm, 4);
    std::printf("after store/load through taint ring: r4=0x%016llX\n",
                static_cast<unsigned long long>(r4));

    check_eq_u64("taint-sever store_reg / load_reg roundtrip",
                 r4, expected_value);
    return r4 == expected_value;
}

static bool run_microbench()
{
    std::printf("\n=== Microbenchmark: cycles per VM instruction ===\n");

    test_vm_holder_t holder_dag;
    prepare_vm(holder_dag, 0x9988776655443322ULL);

    const int kIters = 1000;
    auto t0 = std::chrono::high_resolution_clock::now();
    uint64_t accumulator_dag = 0;
    uint32_t total_insns_dag = 0;
    for (int i = 0; i < kIters; ++i)
    {
        test_vm_holder_t h;
        prepare_vm(h, 0x9988776655443322ULL ^ static_cast<uint64_t>(i));
        auto p = build_simple_add_program(h.vm, h.vm.rolling_key,
                                            h.vm.handler_chain_key, 5ULL, 7ULL);
        accumulator_dag += ad::vm_execute_program(h.vm, p);
        total_insns_dag += h.vm.insn_count;
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    auto t2 = std::chrono::high_resolution_clock::now();
    uint64_t accumulator_lin = 0;
    uint32_t total_insns_lin = 0;
    for (int i = 0; i < kIters; ++i)
    {
        test_vm_holder_t h;
        prepare_vm(h, 0x9988776655443322ULL ^ static_cast<uint64_t>(i));
        vc::program_t prog;
        prog.set_key(h.vm.rolling_key);
        prog.set_opcode_map(h.vm.opcode_map);
        prog.emit_load_imm(0, 5ULL);
        prog.emit_load_imm(1, 7ULL);
        prog.emit_add(2, 0, 1);
        prog.emit_halt();
        auto bc = prog.finalize();
        accumulator_lin += ad::vm_execute(h.vm, bc.data(), static_cast<uint32_t>(bc.size()));
        total_insns_lin += h.vm.insn_count;
    }
    auto t3 = std::chrono::high_resolution_clock::now();

    auto dag_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    auto lin_us = std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count();

    std::printf("DAG mode: %lld us across %u insns (%.2f us/insn)\n",
                static_cast<long long>(dag_us),
                total_insns_dag,
                total_insns_dag ? static_cast<double>(dag_us) / total_insns_dag : 0.0);
    std::printf("Linear mode: %lld us across %u insns (%.2f us/insn)\n",
                static_cast<long long>(lin_us),
                total_insns_lin,
                total_insns_lin ? static_cast<double>(lin_us) / total_insns_lin : 0.0);

    std::printf("DAG accumulator: 0x%016llX, Linear accumulator: 0x%016llX\n",
                static_cast<unsigned long long>(accumulator_dag),
                static_cast<unsigned long long>(accumulator_lin));

    return true;
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== DAG_DISPATCH_TEST starting ===\n");

    bool ok1 = run_basic_add_test();
    bool ok2 = run_tampering_test();
    bool ok3 = run_keyed_dag_test();
    bool ok4 = run_branch_test();
    bool ok5 = run_vcall_test();
    bool ok6 = run_taint_test();
    run_microbench();

    std::printf("\n=== DAG_DISPATCH_TEST summary: %d passes, %d failures ===\n",
                g_passes, g_failures);

    bool all_ok = ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && (g_failures == 0);
    if (all_ok)
    {
        std::printf("\nDAG_DISPATCH_TEST_PASSED\n");
        return 0;
    }
    std::printf("\nDAG_DISPATCH_TEST_FAILED\n");
    return 1;
}
