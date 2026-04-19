"""
find_named_funcs.py - Dump functions whose name matches given substrings,
and also decompile them.

Env:
  IDA_NAME_PATTERNS : JSON list of substrings, e.g. ["OnvifHandle","HTTPRPCHandler","RPCSession","ONVIF_HandleRequest","UploadFileWithName"]
  IDA_EXPORT_DIR
  IDA_BINARY_TAG
"""
import os, json, time
import idaapi, idautils, idc, ida_funcs

def main():
    t0 = time.time()
    idaapi.auto_wait()
    print(f"[named] analysis in {time.time()-t0:.1f}s")
    patterns = json.loads(os.environ.get("IDA_NAME_PATTERNS", "[]"))
    out_dir = os.environ.get("IDA_EXPORT_DIR", ".")
    tag = os.environ.get("IDA_BINARY_TAG", "")
    os.makedirs(out_dir, exist_ok=True)

    has_hex = False
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            has_hex = True
    except Exception:
        pass

    # Walk all functions, match any pattern
    matched = {}
    for fea in idautils.Functions():
        name = idc.get_func_name(fea) or ""
        demangled = idc.demangle_name(name, idc.INF_SHORT_DN) or ""
        bag = name + "\n" + demangled
        for p in patterns:
            if p in bag:
                matched.setdefault(fea, (name, demangled, []))[2].append(p)
                break
    print(f"[named] matched {len(matched)} funcs")

    functions = {}
    for idx, (fea, (name, demangled, why)) in enumerate(matched.items()):
        func = ida_funcs.get_func(fea)
        if not func:
            continue
        size = func.end_ea - func.start_ea
        pseudo = ""
        if has_hex:
            try:
                cf = ida_hexrays.decompile(fea)
                if cf:
                    pseudo = str(cf)
            except Exception:
                pass
        disasm_lines = []
        cur = fea
        while cur < func.end_ea:
            disasm_lines.append(idc.generate_disasm_line(cur, 0) or "")
            nxt = idc.next_head(cur, func.end_ea)
            if nxt <= cur:
                break
            cur = nxt
        calls = []
        strings = []
        for h in idautils.Heads(fea, func.end_ea):
            for ref in idautils.CodeRefsFrom(h, 0):
                n = idc.get_func_name(ref)
                if n and n != name:
                    calls.append(n)
            for ref in idautils.DataRefsFrom(h):
                s = idc.get_strlit_contents(ref, -1, -1)
                if s:
                    try:
                        strings.append(s.decode("utf-8", errors="replace"))
                    except Exception:
                        pass

        functions[hex(fea)] = {
            "name": name, "demangled": demangled,
            "addr": hex(fea), "size": size,
            "matched_pattern": why,
            "pseudocode": pseudo, "disasm": "\n".join(disasm_lines[:500]),
            "calls": calls[:80], "strings": strings[:50],
        }
        if (idx+1) % 20 == 0:
            print(f"[named] decompiled {idx+1}/{len(matched)}")

    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path)
    suffix = f"_{tag}" if tag else ""
    out_path = os.path.join(out_dir, f"{binary_name}{suffix}_named.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"binary": binary_name, "tag": tag, "patterns": patterns, "functions": functions}, f, ensure_ascii=False)
    print(f"[named] wrote {out_path} ({len(functions)} funcs, elapsed {time.time()-t0:.1f}s)")

if __name__ == "__main__":
    main()
    idc.qexit(0)
