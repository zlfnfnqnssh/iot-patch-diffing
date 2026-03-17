"""
auto_quit.py — IDA -S 플래그용 BinExport 내보내기 + 자동 종료 스크립트

사용:
  idat64.exe -A -Sauto_quit.py -Obinexport2:{PATH} -o{idb} {binary}
  환경변수 BINEXPORT_OUT 으로 최종 출력 경로 전달 (선택적)

흐름:
  1. auto_wait() — 자동 분석 완료 대기
  2. RunPlugin("binexport12_ida64", 2) — BinExport 직접 실행
     (-Obinexport2:PATH 가 이미 출력 경로를 설정해 놓음)
  3. 파일 생성 확인 후 qexit(0)
"""
import os
import shutil
import idaapi
import idc

# 1. 자동 분석 완료 대기
idaapi.auto_wait()

# 2. BinExport 플러그인 직접 실행
#    - idat64 배치 모드에서 run(arg)는 -Obinexport2:PATH 로 설정된 경로로 내보냄
#    - arg=2 는 non-interactive (배치) 내보내기
try:
    ret = idc.RunPlugin("binexport12_ida64", 2)
    print(f"[auto_quit] RunPlugin binexport12_ida64(2) → {ret}")
except Exception as e:
    print(f"[auto_quit] RunPlugin 오류: {e}")

# 3. BINEXPORT_OUT 환경변수로 지정된 경로가 있으면 파일 존재 확인
out_path = os.environ.get("BINEXPORT_OUT", "")
if out_path:
    if os.path.exists(out_path):
        print(f"[auto_quit] BinExport 생성 확인: {out_path}")
    else:
        # 기본 경로 탐색: IDB 파일명 + ".BinExport"
        idb_path = idc.get_idb_path()
        stem = os.path.splitext(idb_path)[0]
        default_bex = stem + ".BinExport"
        if os.path.exists(default_bex):
            shutil.move(default_bex, out_path)
            print(f"[auto_quit] BinExport 이동: {default_bex} → {out_path}")
        else:
            print(f"[auto_quit] BinExport 파일 없음 (경로: {out_path})")

# 4. IDA 종료
idc.qexit(0)
