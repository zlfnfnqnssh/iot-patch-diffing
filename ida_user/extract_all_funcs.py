"""extract_all_funcs.py - IDA 전체 함수 pseudocode + metadata 덤프

기존 extract_with_decompile.py 와 유사하지만:
  - "changed only" 필터 없음 (모든 함수)
  - 체크포인트 저장 지원 (50 funcs 마다 partial JSON flush)
  - 재시작 가능 (IDA_RESUME=1 이면 기존 partial 읽고 이어감)

Env:
    IDA_EXPORT_DIR
    IDA_BINARY_TAG
    IDA_MIN_FUNC_SIZE   (default 8)  - 이 이하 함수 스킵
    IDA_CHECKPOINT_EVERY (default 50)
    IDA_RESUME          (default 1)  - 기존 partial JSON 있으면 이어가기
    IDA_MAX_FUNCS       (선택; 디버그용 상한)
"""
import os
import json
import time

import idaapi
import idautils
import idc
import ida_funcs


def main():
    t0 = time.time()
    idaapi.auto_wait()
    print(f"[all] analysis done in {time.time()-t0:.1f}s")

    out_dir = os.environ.get("IDA_EXPORT_DIR", ".")
    tag = os.environ.get("IDA_BINARY_TAG", "")
    min_size = int(os.environ.get("IDA_MIN_FUNC_SIZE", "8"))
    checkpoint_every = int(os.environ.get("IDA_CHECKPOINT_EVERY", "50"))
    resume = os.environ.get("IDA_RESUME", "1") == "1"
    max_funcs = int(os.environ.get("IDA_MAX_FUNCS", "0") or 0)

    os.makedirs(out_dir, exist_ok=True)
    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path)
    suffix = f"_{tag}" if tag else ""
    out_path = os.path.join(out_dir, f"{binary_name}{suffix}.json")
    partial_path = out_path + ".partial"

    has_hex = False
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            has_hex = True
            print("[all] Hex-Rays: available")
    except Exception:
        pass

    functions = {}
    stats = {"total": 0, "decompiled": 0, "decompile_failed": 0, "skipped_small": 0, "skipped_done": 0}

    if resume and os.path.exists(partial_path):
        try:
            prev = json.load(open(partial_path, "r", encoding="utf-8"))
            functions = prev.get("functions", {})
            print(f"[all] resumed {len(functions)} functions from partial")
        except Exception as e:
            print(f"[all] resume failed: {e}")

    done_keys = set(functions.keys())

    func_eas = list(idautils.Functions())
    total = len(func_eas)
    print(f"[all] total entries: {total}")
    if max_funcs:
        func_eas = func_eas[:max_funcs]

    def save_partial():
        payload = {
            "binary": binary_name, "tag": tag, "has_pseudocode": has_hex,
            "stats": stats, "functions": functions,
            "elapsed": time.time() - t0,
            "checkpoint_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        tmp = partial_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        os.replace(tmp, partial_path)

    for idx, fea in enumerate(func_eas):
        func = ida_funcs.get_func(fea)
        if not func:
            continue
        size = func.end_ea - func.start_ea
        if size < min_size:
            stats["skipped_small"] += 1
            continue

        key = hex(fea)
        if key in done_keys:
            stats["skipped_done"] += 1
            continue

        name = idc.get_func_name(fea) or f"sub_{fea:X}"
        pseudo = ""
        if has_hex:
            try:
                cf = ida_hexrays.decompile(fea)
                if cf:
                    pseudo = str(cf)
                    stats["decompiled"] += 1
                else:
                    stats["decompile_failed"] += 1
            except Exception:
                stats["decompile_failed"] += 1

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

        functions[key] = {
            "name": name, "addr": key, "size": size,
            "pseudocode": pseudo,
            "disasm": "\n".join(disasm_lines[:500]),
            "calls": calls[:80],
            "strings": strings[:60],
        }
        stats["total"] += 1

        if stats["total"] % checkpoint_every == 0:
            elapsed = time.time() - t0
            rate = stats["total"] / elapsed if elapsed else 0
            eta = (total - idx - 1) / rate if rate else 0
            print(f"[all] {idx+1}/{total} ok={stats['decompiled']} fail={stats['decompile_failed']} skip_small={stats['skipped_small']} skip_done={stats['skipped_done']} | rate={rate:.1f}/s eta={eta/60:.1f}min")
            save_partial()

    # Final write
    payload = {
        "binary": binary_name, "tag": tag, "has_pseudocode": has_hex,
        "stats": stats, "functions": functions,
        "elapsed": time.time() - t0,
        "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)

    if os.path.exists(partial_path):
        try:
            os.remove(partial_path)
        except Exception:
            pass

    print(f"[all] wrote {out_path} ({len(functions)} funcs, elapsed {time.time()-t0:.1f}s)")
    print(f"[all] stats: {stats}")


if __name__ == "__main__":
    main()
    idc.qexit(0)
