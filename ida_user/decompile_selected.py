"""
decompile_selected.py - IDA에서 지정한 함수들만 디컴파일

환경변수:
    IDA_SELECTED_FUNCS : JSON 파일 경로 (decompile 대상 함수 주소 리스트)
    IDA_EXPORT_DIR     : 출력 디렉토리
    IDA_BINARY_TAG     : "old" / "new"

입력 JSON 스키마:
    { "addresses": ["0x19e530", "0x583948", ...] }

출력 JSON 스키마 (extract_with_decompile와 호환):
    {
      "binary": "...",
      "tag": "old",
      "functions": {
         "0x19e530": {
            "name": "...", "addr": "0x19e530", "size": 1234,
            "pseudocode": "...", "disasm": "...",
            "calls": [...], "strings": [...]
         }
      }
    }
"""
import os
import json
import time

import idaapi
import idautils
import idc
import ida_funcs
import ida_bytes


def main():
    t0 = time.time()
    idaapi.auto_wait()
    print(f"[sel] analysis ready in {time.time()-t0:.1f}s")

    sel_path = os.environ.get("IDA_SELECTED_FUNCS", "")
    out_dir = os.environ.get("IDA_EXPORT_DIR", ".")
    tag = os.environ.get("IDA_BINARY_TAG", "")

    if not sel_path or not os.path.exists(sel_path):
        print(f"[sel] ERROR: IDA_SELECTED_FUNCS not found: {sel_path}")
        idc.qexit(1)
        return

    with open(sel_path, "r", encoding="utf-8") as f:
        sel = json.load(f)
    addrs_raw = sel.get("addresses", [])
    addrs = []
    for a in addrs_raw:
        if isinstance(a, str):
            a = int(a, 16) if a.startswith("0x") else int(a)
        addrs.append(a)

    print(f"[sel] target funcs: {len(addrs)}")

    has_hexrays = False
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            has_hexrays = True
    except Exception:
        pass

    functions = {}
    ok = 0
    fail = 0
    for idx, ea in enumerate(addrs):
        func = ida_funcs.get_func(ea)
        if not func:
            fail += 1
            continue
        fea = func.start_ea
        name = idc.get_func_name(fea) or f"sub_{fea:X}"
        size = func.end_ea - fea

        pseudocode = ""
        if has_hexrays:
            try:
                cf = ida_hexrays.decompile(fea)
                if cf:
                    pseudocode = str(cf)
                    ok += 1
            except Exception:
                fail += 1
        # disasm
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
            "name": name,
            "addr": hex(fea),
            "size": size,
            "pseudocode": pseudocode,
            "disasm": "\n".join(disasm_lines),
            "calls": calls[:40],
            "strings": strings[:30],
        }

        if (idx + 1) % 50 == 0:
            print(f"[sel] {idx+1}/{len(addrs)} ok={ok} fail={fail}")

    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path)
    suffix = f"_{tag}" if tag else ""
    out_path = os.path.join(out_dir, f"{binary_name}{suffix}_selected.json")
    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "binary": binary_name,
            "tag": tag,
            "has_pseudocode": has_hexrays,
            "functions": functions,
            "stats": {"requested": len(addrs), "ok": ok, "fail": fail},
        }, f, ensure_ascii=False)
    print(f"[sel] wrote {out_path} ({ok} ok / {fail} fail)")


if __name__ == "__main__":
    main()
    idc.qexit(0)
