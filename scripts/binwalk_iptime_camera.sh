#!/usr/bin/env bash
# iptime_camera 폴더 하위 bin 에 대해 binwalk -e 일괄 수행.
# 각 bin 의 추출 결과는 output/iptime_camera/<model>/<stem>/extracted/ 로 이동.
#
# 사용법:
#   bash scripts/binwalk_iptime_camera.sh               # 전체 (A/T 시리즈 포함)
#   MODELS="c200 c200e c300 c500" bash scripts/binwalk_iptime_camera.sh    # 카메라만
#   MODELS="c200" bash scripts/binwalk_iptime_camera.sh  # 단일 모델
#
# 환경변수:
#   MODELS     (옵션) 공백구분 모델 이름 리스트. 미지정 = 전체.
#   SKIP_EXISTING (기본 1) 이미 .extracted_ok 가 있는 bin 은 스킵.
#   WSL_DISTRO (기본 Ubuntu) WSL 배포판 이름.
#
set -euo pipefail
cd "$(dirname "$0")/.."

SRC_ROOT="data/firmware/iptime_camera"
OUT_ROOT="output/iptime_camera"
WSL_DISTRO="${WSL_DISTRO:-Ubuntu}"
SKIP_EXISTING="${SKIP_EXISTING:-1}"
MODELS="${MODELS:-}"

mkdir -p "$OUT_ROOT"

# 모델 목록 결정
if [ -z "$MODELS" ]; then
  MODELS=$(ls -1 "$SRC_ROOT" 2>/dev/null | xargs)
fi
echo "[binwalk] 대상 모델: $MODELS"

# batch 시작 전 WSL 1회 재시작 (stale 인스턴스 정리)
echo "[binwalk] WSL 재시작 중..."
wsl --shutdown 2>/dev/null || true
sleep 2

# WSL 경로 변환 헬퍼 — Git Bash 의 /d/... 가 아니라 WSL 의 /mnt/d/... 형태로 반환
to_wsl_path() {
  local p="$1"
  # 상대 경로면 현재 CWD 기준 절대화 (Windows 경로 기준)
  local abs_win
  if command -v cygpath >/dev/null 2>&1; then
    # cygpath -m 은 Windows 형식 (D:/Task/...), -w 는 backslash (D:\...) 반환
    abs_win=$(cygpath -m -a "$p" 2>/dev/null)
  else
    abs_win="$p"
  fi
  # D:/Task/... → /mnt/d/Task/... 로 변환
  echo "$abs_win" | sed -E 's|^([A-Za-z]):/|/mnt/\L\1/|'
}

total=0
done_ok=0
skipped=0
failed=0

for model in $MODELS; do
  model_dir="$SRC_ROOT/$model"
  [ -d "$model_dir" ] || { echo "  [skip] $model (디렉토리 없음)"; continue; }

  mkdir -p "$OUT_ROOT/$model"

  for bin in "$model_dir"/*.bin; do
    [ -f "$bin" ] || continue
    total=$((total+1))
    stem=$(basename "$bin" .bin)
    out_dir="$OUT_ROOT/$model/$stem"

    if [ "$SKIP_EXISTING" = "1" ] && [ -f "$out_dir/.extracted_ok" ]; then
      echo "  [skip] $model/$stem (이미 추출됨)"
      skipped=$((skipped+1))
      continue
    fi

    mkdir -p "$out_dir"
    wsl_bin=$(to_wsl_path "$bin")
    wsl_out=$(to_wsl_path "$out_dir")

    echo "  [bw] $model/$stem  (src=$wsl_bin  out=$wsl_out)"

    # binwalk -e 실행 (WSL). --shutdown 은 batch 시작 전 1회만 하므로 여기서 안 함.
    if wsl -d "$WSL_DISTRO" -- bash -lc "
        PATH=/usr/local/bin:/usr/bin:/bin
        cd '$wsl_out' || { echo '[err] cd 실패: $wsl_out'; exit 1; }
        binwalk -e '$wsl_bin' 2>&1 | tail -20
    "; then
      # 산출물이 <bin_name>.extracted 로 생기면 out_dir 안에 정렬
      ext_name="_$(basename "$bin").extracted"
      if [ -d "$out_dir/$ext_name" ]; then
        touch "$out_dir/.extracted_ok"
        done_ok=$((done_ok+1))
        echo "    [ok] $out_dir/$ext_name"
      else
        echo "    [warn] extracted dir not found; check log"
        failed=$((failed+1))
      fi
    else
      echo "    [err] binwalk 실패"
      failed=$((failed+1))
    fi
  done
done

echo ""
echo "============================================================"
echo "[binwalk] 총 $total   성공 $done_ok   스킵 $skipped   실패 $failed"
echo "============================================================"
