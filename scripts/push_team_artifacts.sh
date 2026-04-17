#!/usr/bin/env bash
# 팀 공유 아티팩트만 stage + commit + push.
# DB/펌웨어/개인 설정은 .gitignore가 막으므로 전체 add -A 대비 안전.
#
# 사용법:
#   bash scripts/push_team_artifacts.sh "stage2: session 78 progress"
#   bash scripts/push_team_artifacts.sh             # 메시지 생략 시 기본값
#
# 환경변수:
#   PUSH_REMOTE (기본 origin)  — 어느 리모트로 push할지
#   PUSH_BRANCH (기본 현재 브랜치)
#   SKIP_PUSH=1                — 커밋만 하고 push 스킵

set -euo pipefail
cd "$(dirname "$0")/.."

MSG="${1:-stage2: batch progress update (auto)}"
REMOTE="${PUSH_REMOTE:-origin}"
BRANCH="${PUSH_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"

# 팀 공유 경로만 stage (gitignore 규칙과 이중 방어)
TEAM_PATHS=(
  ".claude/skills/stage2/"
  "docs/pattern-card-spec.md"
  "docs/architecture-decisions.md"
  "docs/pipeline.md"
  "docs/dev-notes.md"
  "docs/stage2-runbook.md"
  "data/handoff/"
  "src/stage2/"
  "scripts/push_team_artifacts.sh"
  "CLAUDE.md"
  ".gitignore"
)

STAGED=0
for p in "${TEAM_PATHS[@]}"; do
  if [ -e "$p" ]; then
    git add "$p" 2>/dev/null || true
    STAGED=1
  fi
done

# staged 변경이 없으면 조용히 종료
if git diff --cached --quiet; then
  echo "[push_team] no changes to commit"
  exit 0
fi

echo "[push_team] staged changes:"
git diff --cached --name-only | sed 's/^/  /'

git commit -m "$MSG" --no-verify

if [ "${SKIP_PUSH:-0}" = "1" ]; then
  echo "[push_team] SKIP_PUSH=1 — committed locally only."
  exit 0
fi

echo "[push_team] pushing to ${REMOTE} ${BRANCH}..."
git push "$REMOTE" "HEAD:${BRANCH}"
echo "[push_team] done."
