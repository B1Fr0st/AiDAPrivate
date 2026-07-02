import idautils
import idaapi
import idc
import ida_bytes
import ida_xref

target_funcs = [0x1407022d0, 0x140651ea0]  # ObCreateObject, ObCreateObjectEx

results = []

for func_addr in target_funcs:
    for xref in idautils.XrefsTo(func_addr):
        caller = idaapi.get_func(xref.frm)
        if not caller:
            continue
        caller_name = idc.get_func_name(caller.start_ea)
        
        # Find the call instruction
        call_ea = xref.frm
        
        # In x64, the 6th parameter (a6 = body_size) is at [rsp+28h]
        # The 7th (a7 = PagedCharge) is at [rsp+30h]
        # The 8th (a8 = NonPagedCharge) is at [rsp+38h]
        
        # Search backwards from call for mov [rsp+XX], value patterns
        # to find the body size parameter
        body_size = None
        paged_charge = None
        nonpaged_charge = None
        
        # Search up to 40 instructions before the call
        ea = call_ea
        for i in range(40):
            ea = idc.prev_head(ea)
            if ea == idc.BADADDR:
                break
            
            mnem = idc.print_insn_mnem(ea)
            if mnem != 'mov' and mnem != 'movzx':
                continue
            
            # Get operands
            op0 = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            disasm = idc.GetDisasm(ea)
            
            # Look for stack stores to [rsp+28h] (body_size)
            # The stack offset might vary due to frame layout
            # Look for patterns like: mov dword ptr [rsp+XXh], imm
            
            # Check for immediate values that could be body sizes
            try:
                op1_val = idc.get_operand_value(ea, 1)
            except:
                op1_val = None
            
            if op1_val is not None and op1_val > 0 and op1_val < 0x10000:
                # Check if this is a stack store
                if 'rsp' in op0.lower() and 'dword' in disasm.lower():
                    # Try to determine which parameter
                    # We need the stack frame offset
                    frame = idaapi.get_frame(caller.start_ea)
                    if frame:
                        # The exact mapping depends on the function's stack frame
                        # Let's just record all interesting values
                        pass
        
        # Alternative: just record the caller and we'll manually check
        results.append((caller_name, hex(caller.start_ea), hex(call_ea)))

# Print results
for name, func_ea, call_ea in results:
    print(f"{name:45s} func={func_ea} call={call_ea}")
