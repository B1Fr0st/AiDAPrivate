import sys

INSTRUCTION = 56
OPERAND_HOT = 32
OPERAND_COLD = 32
TARGET = 48
BLOCK = 64
CHUNK = 64
MEMBERSHIP = 40
FUNCTION = 112
EDGE = 72
XREF = 48
STRING = 72
SYMBOL = 64
COVERAGE = 32
ADDRESS_EXPRESSION = 12
ADDRESS_RANGE = 24

GIB = 1 << 30

COLD_RATIO = 0.40

COUNTS = {
    "instructions": 47_500_000,
    "operand_facts": 109_000_000,
    "target_facts": 16_600_000,
    "blocks": 7_100_000,
    "function_chunks": 1_500_000,
    "function_block_memberships": 7_100_000,
    "functions": 1_190_000,
    "edges": 17_800_000,
    "xrefs": 23_800_000,
    "strings": 300_000,
    "symbols": 400_000,
    "coverage": 50_000,
}

SIZES = {
    "instructions": INSTRUCTION,
    "operand_facts": OPERAND_HOT + COLD_RATIO * OPERAND_COLD,
    "target_facts": TARGET,
    "blocks": BLOCK,
    "function_chunks": CHUNK,
    "function_block_memberships": MEMBERSHIP,
    "functions": FUNCTION,
    "edges": EDGE,
    "xrefs": XREF,
    "strings": STRING,
    "symbols": SYMBOL,
    "coverage": COVERAGE,
}


def clamp(value, floor, ceiling):
    return max(floor, min(ceiling, value))


def domain_bytes():
    return {name: COUNTS[name] * SIZES[name] for name in COUNTS}


def main():
    operand_avg = OPERAND_HOT + COLD_RATIO * OPERAND_COLD
    per_insn = INSTRUCTION + 2.29 * operand_avg
    total = sum(domain_bytes().values())
    resident_8gb = (
        COUNTS["blocks"] * BLOCK
        + COUNTS["function_chunks"] * CHUNK
        + COUNTS["function_block_memberships"] * MEMBERSHIP
        + COUNTS["functions"] * FUNCTION
        + 0.03 * GIB
        + COUNTS["strings"] * STRING
        + COUNTS["symbols"] * SYMBOL
    )
    print("operand average bytes: %.1f (target <= 44.8)" % operand_avg)
    print("instructions+operands per insn: %.1f (target <= 180)" % per_insn)
    print("new-layout snapshot total: %.2f GiB" % (total / GIB))
    print("8GB hot-resident (xrefs paged): %.2f GiB (target ~0.96)" % (resident_8gb / GIB))
    total_records = sum(COUNTS.values())
    print("total records: %.1fM (< 1e9: %s)" % (total_records / 1e6, total_records < 1_000_000_000))
    usable_8gb = 4 * GIB
    resident_budget = clamp(usable_8gb // 6, 2 * GIB, 8 * GIB)
    page_cache = clamp(usable_8gb // 12, 1 * GIB, 4 * GIB)
    staging = clamp(usable_8gb // 16, 512 << 20, 4 * GIB)
    print("8GB resident budget: %.2f GiB, page cache: %.2f GiB, staging cap: %.2f GiB"
          % (resident_budget / GIB, page_cache / GIB, staging / GIB))
    sustained = resident_8gb + COUNTS["xrefs"] * XREF + page_cache + int(0.75 * GIB)
    print("8GB sustained working set (xrefs resident): %.2f GiB (envelope <= 6 GiB: %s)"
          % (sustained / GIB, sustained <= 6 * GIB))
    ok = operand_avg <= 44.8 + 1e-9 and per_insn <= 180 and total_records < 1_000_000_000
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
