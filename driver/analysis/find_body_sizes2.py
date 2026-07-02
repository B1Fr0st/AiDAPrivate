import idautils
import idc

target_funcs = [0x1407022d0, 0x140651ea0]

results = []
seen = set()

for func_addr in target_funcs:
    for xref in idautils.XrefsTo(func_addr):
        caller = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
        if caller == idc.BADADDR:
            continue
        if caller in seen:
            continue
        seen.add(caller)
        name = idc.get_func_name(caller)
        results.append((name, hex(caller)))

for name, addr in sorted(results, key=lambda x: x[0]):
    print(f"{name:50s} {addr}")
