import idautils
import idc
import ida_hexrays
import re

target_funcs = [0x1407022d0, 0x140651ea0]

callers = set()
for func_addr in target_funcs:
    for xref in idautils.XrefsTo(func_addr):
        caller = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
        if caller != idc.BADADDR:
            callers.add(caller)

results = []

for caller_ea in sorted(callers):
    name = idc.get_func_name(caller_ea)
    
    try:
        cfunc = ida_hexrays.decompile(caller_ea)
        if not cfunc:
            continue
        code = str(cfunc)
        
        # Find ObCreateObject or ObCreateObjectEx calls
        for match in re.finditer(r'ObCreateObject(?:Ex)?\s*\(', code):
            # Get surrounding context
            start = max(0, match.start() - 200)
            end = min(len(code), match.end() + 500)
            context = code[start:end]
            
            # Look for the 6th parameter (body_size)
            # The call format is: ObCreateObjectEx(a1, a2, a3, a4, a5, BODY_SIZE, ...)
            # Try to extract the body size
            
            # Find the call and its arguments
            call_start = match.start()
            # Find matching closing paren
            depth = 0
            pos = match.end() - 1  # at '('
            while pos < len(code):
                if code[pos] == '(':
                    depth += 1
                elif code[pos] == ')':
                    depth -= 1
                    if depth == 0:
                        break
                pos += 1
            
            call_text = code[match.start():pos+1]
            
            # Extract all arguments
            args = []
            arg_start = call_text.index('(') + 1
            arg_depth = 0
            last_comma = arg_start
            for i in range(arg_start, len(call_text)):
                c = call_text[i]
                if c == '(':
                    arg_depth += 1
                elif c == ')':
                    if arg_depth == 0:
                        args.append(call_text[last_comma:i].strip())
                        break
                    arg_depth -= 1
                elif c == ',' and arg_depth == 0:
                    args.append(call_text[last_comma:i].strip())
                    last_comma = i + 1
            
            # The 6th argument (index 5) is body_size
            body_size_str = args[5] if len(args) > 5 else "?"
            
            # Try to convert to int
            body_size = None
            try:
                body_size = int(body_size_str, 0)
            except:
                # Try to evaluate simple expressions
                try:
                    body_size = eval(body_size_str.replace('0x', '').replace(',', ''))
                except:
                    pass
            
            results.append((name, body_size_str, body_size, call_text[:200]))
            break  # Only first call per function
            
    except Exception as e:
        results.append((name, "ERROR", None, str(e)))

# Sort by body size
results_with_size = [r for r in results if r[2] is not None]
results_without = [r for r in results if r[2] is None]

print("=== Objects with body sizes ===")
for name, bstr, bval, ctx in sorted(results_with_size, key=lambda x: x[2]):
    # Calculate LFH buckets
    named_total = bval + 112
    unnamed_total = bval + 80
    named_bucket = None
    unnamed_bucket = None
    
    lfh = [16,32,48,64,80,96,112,128,144,160,176,192,208,224,240,256,272,288,304,320,352,384,416,448,480,512,560,608,640,672,704,736,768,800,832,864,896,928,960,992,1024,1088,1152,1216,1280,1360,1440,1520,1600,1680,1760,1840,1920,2000,2080]
    for b in lfh:
        if named_total <= b:
            named_bucket = b
            break
    for b in lfh:
        if unnamed_total <= b:
            unnamed_bucket = b
            break
    
    m640 = "***640***" if (609 <= named_total <= 640 or 609 <= unnamed_total <= 640) else ""
    m1024 = "***1024***" if (993 <= named_total <= 1024 or 993 <= unnamed_total <= 1024) else ""
    
    print(f"{name:45s} body={bstr:>6s} ({bval:4d})  named={named_total:4d}({named_bucket}) unnamed={unnamed_total:4d}({unnamed_bucket}) {m640} {m1024}")

print("\n=== Objects without body sizes ===")
for name, bstr, bval, ctx in results_without:
    print(f"{name:45s} body={bstr}")
