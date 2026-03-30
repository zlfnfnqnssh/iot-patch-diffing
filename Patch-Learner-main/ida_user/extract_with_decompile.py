"""
extract_with_decompile.py - IDA 함수 추출 (디컴파일 + BinExport 통합)

한 번의 IDA 실행으로:
  1. 모든 함수의 pseudocode (Hex-Rays) / disassembly 추출
  2. 함수 메타데이터 (name, addr, size, mnem_hash, calls, strings) 추출
  3. BinExport 파일 생성 (BinDiff 매칭용)

환경변수:
    IDA_EXPORT_DIR  : 출력 디렉토리 (필수)
    IDA_BINARY_TAG  : 출력 파일 태그 ("old" / "new")

사용:
    set IDA_EXPORT_DIR=C:\\output
    set IDA_BINARY_TAG=old
    idat64.exe -A -OBinExportModule:C:\\output\\binary_old.BinExport ^
               -S"extract_with_decompile.py" -L"log.txt" binary
"""
import os
import json
import hashlib
import time

import idaapi
import idautils
import idc
import ida_funcs


def extract_all():
    start_time = time.time()
    idaapi.auto_wait()
    analysis_time = time.time() - start_time

    output_dir = os.environ.get("IDA_EXPORT_DIR", ".")
    tag = os.environ.get("IDA_BINARY_TAG", "")
    os.makedirs(output_dir, exist_ok=True)

    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path)

    print(f"[extract] Binary: {binary_name} (tag={tag})")
    print(f"[extract] Analysis: {analysis_time:.1f}s")

    # ── Hex-Rays 디컴파일러 확인 ──────────────────────────────────
    has_hexrays = False
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            has_hexrays = True
            print("[extract] Hex-Rays: available")
    except Exception as e:
        print(f"[extract] Hex-Rays: not available ({e})")

    # ── 함수 추출 ─────────────────────────────────────────────────
    functions = {}
    stats = {
        "total": 0,
        "decompiled": 0,
        "decompile_failed": 0,
        "skipped_small": 0,
    }

    func_eas = list(idautils.Functions())
    total_funcs = len(func_eas)
    print(f"[extract] Total function entries: {total_funcs}")

    for idx, func_ea in enumerate(func_eas):
        if (idx + 1) % 200 == 0:
            elapsed = time.time() - start_time
            print(f"[extract] {idx+1}/{total_funcs} ({elapsed:.0f}s)")

        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        name = idc.get_func_name(func_ea)
        size = func.end_ea - func.start_ea

        if size < 4:
            stats["skipped_small"] += 1
            continue

        # ── Disassembly + Mnemonics ───────────────────────────────
        mnemonics = []
        disasm_lines = []
        strings_ref = []
        calls = []
        constants = []

        for head in idautils.Heads(func.start_ea, func.end_ea):
            flags = idc.get_full_flags(head)
            if not idc.is_code(flags):
                continue

            mnemonics.append(idc.print_insn_mnem(head))
            disasm_lines.append(idc.generate_disasm_line(head, 0))

            # 문자열 참조
            for ref in idautils.DataRefsFrom(head):
                s = idc.get_strlit_contents(ref)
                if s:
                    try:
                        decoded = s.decode("utf-8", errors="replace")
                        if decoded not in strings_ref:
                            strings_ref.append(decoded)
                    except Exception:
                        pass

            # 호출 함수
            for ref in idautils.CodeRefsFrom(head, False):
                callee = idc.get_func_name(ref)
                if callee and callee != name and callee not in calls:
                    calls.append(callee)

            # 상수
            for i in range(3):
                if idc.get_operand_type(head, i) == idc.o_imm:
                    val = idc.get_operand_value(head, i)
                    if 0 < val < 0x10000 and val not in constants:
                        constants.append(val)

        if not mnemonics:
            continue

        stats["total"] += 1

        # ── Pseudocode (Hex-Rays) ────────────────────────────────
        pseudocode = None
        if has_hexrays:
            try:
                import ida_hexrays
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    sv = cfunc.get_pseudocode()
                    lines = []
                    for i in range(sv.size()):
                        lines.append(idaapi.tag_remove(sv[i].line))
                    pseudocode = "\n".join(lines)
                    stats["decompiled"] += 1
            except Exception:
                stats["decompile_failed"] += 1

        # ── 메타데이터 ───────────────────────────────────────────
        bb_count = sum(1 for _ in idaapi.FlowChart(func))
        mnem_hash = hashlib.md5(" ".join(mnemonics).encode()).hexdigest()

        functions[name] = {
            "addr": hex(func_ea),
            "size": size,
            "bb_count": bb_count,
            "insn_count": len(mnemonics),
            "mnem_hash": mnem_hash,
            "pseudocode": pseudocode,
            "disasm": "\n".join(disasm_lines),
            "calls": calls,
            "strings": strings_ref,
            "constants": constants,
        }

    # ── JSON 저장 ─────────────────────────────────────────────────
    suffix = f"_{tag}" if tag else ""
    out_path = os.path.join(output_dir, f"{binary_name}{suffix}.json")

    output_data = {
        "binary": binary_name,
        "binary_path": binary_path,
        "tag": tag,
        "has_pseudocode": has_hexrays,
        "stats": stats,
        "functions": functions,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False)

    elapsed = time.time() - start_time
    print(f"[extract] Saved: {out_path}")
    print(f"[extract] Functions: {stats['total']}")
    if has_hexrays:
        print(f"[extract] Decompiled: {stats['decompiled']}, "
              f"Failed: {stats['decompile_failed']}")
    print(f"[extract] Time: {elapsed:.1f}s")

    # ── BinExport 트리거 (플러그인이 -O 옵션으로 로드된 경우) ────
    try:
        import ida_loader
        ret = ida_loader.load_and_run_plugin("binexport12_ida64", 0)
        print(f"[extract] BinExport: {'OK' if ret else 'plugin returned false'}")
    except Exception as e:
        print(f"[extract] BinExport: failed ({e})")


if __name__ == "__main__":
    extract_all()
    idc.qexit(0)
