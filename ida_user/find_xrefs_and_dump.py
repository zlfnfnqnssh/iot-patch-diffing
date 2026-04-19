"""
find_xrefs_and_dump.py - Given a list of string literals, find all functions that
reference those strings, then decompile each such function.

Env:
  IDA_TARGET_STRINGS : JSON list of strings to search for  (e.g. ["Src/OnvifHandler.cpp","strncpy"])
  IDA_EXPORT_DIR     : output dir
  IDA_BINARY_TAG     : "old" / "new" / ""

Output:
  <binary>_<tag>_xrefs.json : {"query":[...], "functions": { "0xADDR": {...same schema as decompile_selected...} }}
"""
import os, json, time
import idaapi, idautils, idc, ida_funcs, ida_bytes, ida_strlist

def main():
    t0 = time.time()
    idaapi.auto_wait()
    print(f"[xref] analysis done in {time.time()-t0:.1f}s")

    targets = json.loads(os.environ.get("IDA_TARGET_STRINGS", "[]"))
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

    # Build string table -> addresses
    ida_strlist.build_strlist()
    str_addrs = {}  # target -> list of EA
    for i in range(ida_strlist.get_strlist_qty()):
        si = idaapi.string_info_t()
        if not ida_strlist.get_strlist_item(si, i):
            continue
        try:
            s = idc.get_strlit_contents(si.ea, si.length, si.type)
            if not s:
                continue
            s = s.decode("utf-8", errors="ignore")
        except Exception:
            continue
        for t in targets:
            if t in s:
                str_addrs.setdefault(t, []).append(si.ea)
    print(f"[xref] found string hits: { {k: len(v) for k,v in str_addrs.items()} }")

    # For each string EA, find all xrefs from code, map to function
    func_set = {}  # func_ea -> [triggering_string, ...]
    for target, eas in str_addrs.items():
        for ea in eas:
            for xref in idautils.XrefsTo(ea, 0):
                fea = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
                if fea == idc.BADADDR:
                    continue
                func_set.setdefault(fea, set()).add(target)
    print(f"[xref] matched functions: {len(func_set)}")

    functions = {}
    for idx, (fea, why) in enumerate(func_set.items()):
        func = ida_funcs.get_func(fea)
        if not func:
            continue
        name = idc.get_func_name(fea) or f"sub_{fea:X}"
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
            "name": name, "addr": hex(fea), "size": size,
            "pseudocode": pseudo, "disasm": "\n".join(disasm_lines[:400]),
            "calls": calls[:60], "strings": strings[:40],
            "triggered_by": sorted(list(why)),
        }
        if (idx+1) % 20 == 0:
            print(f"[xref] decompiled {idx+1}/{len(func_set)}")

    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path)
    suffix = f"_{tag}" if tag else ""
    out_path = os.path.join(out_dir, f"{binary_name}{suffix}_xrefs.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"binary": binary_name, "tag": tag, "query": targets, "functions": functions}, f, ensure_ascii=False)
    print(f"[xref] wrote {out_path} ({len(functions)} funcs, elapsed {time.time()-t0:.1f}s)")

if __name__ == "__main__":
    main()
    idc.qexit(0)
