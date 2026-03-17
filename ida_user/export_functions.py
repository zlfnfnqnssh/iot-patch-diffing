"""
export_functions.py — IDA -S 플래그용 함수 정보 JSON 내보내기 스크립트

사용:
  idat64.exe -A -Sexport_functions.py -o{idb} {binary}
  환경변수 IDA_FUNCS_OUT 으로 출력 JSON 경로 전달

내보내는 정보 (함수별):
  addr   : 시작 주소 (hex)
  name   : 함수명
  size   : 크기 (바이트)
  hash   : 함수 바이트 SHA256 (변경 감지용)
"""
import json
import os
import hashlib
import idaapi
import idautils
import idc
import ida_bytes

# 자동 분석 완료 대기
idaapi.auto_wait()

out_path = os.environ.get("IDA_FUNCS_OUT", "")
if not out_path:
    print("[export_functions] IDA_FUNCS_OUT 환경변수 없음")
    idc.qexit(1)

funcs = []
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    func_end = idc.get_func_attr(ea, idc.FUNCATTR_END)
    size = func_end - ea if func_end > ea else 0

    # 함수 바이트 읽기 및 SHA256
    if size > 0:
        raw = ida_bytes.get_bytes(ea, size) or b""
    else:
        raw = b""
    func_hash = hashlib.sha256(raw).hexdigest()

    funcs.append({
        "addr": hex(ea),
        "name": name,
        "size": size,
        "hash": func_hash,
    })

print(f"[export_functions] {len(funcs)}개 함수 내보내기 → {out_path}")

os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(funcs, f, ensure_ascii=False)

idc.qexit(0)
