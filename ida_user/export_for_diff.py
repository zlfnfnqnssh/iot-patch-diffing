"""
export_for_diff.py — IDA 함수 특성 추출 (mnemonic 기반, 주소 무관)

사용:
    set IDA_EXPORT_OUTPUT=output.json
    idat64.exe -A -S"export_for_diff.py" -L"log.txt" binary

내보내는 정보 (함수별):
    name      : 함수명
    addr      : 시작 주소 (hex)
    size      : 크기 (바이트)
    bb_count  : 기본 블록 수
    mnem_hash : mnemonic 시퀀스 MD5 (주소 무관 → 위치 변해도 동일)
    mnemonics : mnemonic 리스트 (유사도 비교용)
    calls     : 호출하는 함수명 리스트
    strings   : 참조하는 문자열 리스트
    constants : 참조하는 상수 리스트
"""
import os
import json
import hashlib

import idaapi
import idautils
import idc
import ida_funcs


def export_functions():
    """모든 함수의 특성을 추출하여 JSON으로 저장."""
    idaapi.auto_wait()

    output_path = os.environ.get("IDA_EXPORT_OUTPUT", "functions_export.json")
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    results = []
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        name = idc.get_func_name(func_ea)
        size = func.end_ea - func.start_ea
        if size < 4:
            continue

        mnemonics = []
        strings = set()
        calls = set()
        constants = set()

        for head in idautils.Heads(func.start_ea, func.end_ea):
            flags = idc.get_full_flags(head)
            if not idc.is_code(flags):
                continue

            mnemonics.append(idc.print_insn_mnem(head))

            # 문자열 참조
            for ref in idautils.DataRefsFrom(head):
                s = idc.get_strlit_contents(ref)
                if s:
                    try:
                        strings.add(s.decode("utf-8", errors="replace"))
                    except Exception:
                        pass

            # 함수 호출
            for ref in idautils.CodeRefsFrom(head, False):
                callee = idc.get_func_name(ref)
                if callee and callee != name:
                    calls.add(callee)

            # 상수 (주소가 아닌 작은 값)
            for i in range(3):
                if idc.get_operand_type(head, i) == idc.o_imm:
                    val = idc.get_operand_value(head, i)
                    if 0 < val < 0x10000:
                        constants.add(val)

        if not mnemonics:
            continue

        bb_count = sum(1 for _ in idaapi.FlowChart(func))
        mnem_hash = hashlib.md5(" ".join(mnemonics).encode()).hexdigest()

        results.append({
            "name": name,
            "addr": hex(func_ea),
            "size": size,
            "bb_count": bb_count,
            "mnem_hash": mnem_hash,
            "mnemonics": mnemonics,
            "calls": sorted(calls),
            "strings": sorted(strings),
            "constants": sorted(constants),
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False)

    print(f"[export_for_diff] {len(results)} functions -> {output_path}")


if __name__ == "__main__":
    export_functions()
    idc.qexit(0)
