"""
Multi-Agent 패턴 카드 생성 파이프라인 (Claude Code Agent 기반).

토스 보안팀의 Discovery → Analysis 2단계 구조를 적용.
API를 사용하지 않고, Claude Code의 Agent 도구로 실행한다.

구조:
  Manager (Opus) → Discovery Agent (Sonnet) → Analysis Agent×2 (Sonnet) → Review (Opus)

사용법:
  1. prepare_discovery()로 후보 목록 생성 → discovery_input.json
  2. Claude Code Agent(Discovery)가 필터링 → discovery_output.json
  3. prepare_analysis()로 분석 배치 분할 → analysis_batch_*.json
  4. Claude Code Agent(Analysis)×2가 패턴 카드 생성 → llm_cards_batch_*.json
  5. merge_and_validate()로 최종 병합 + Pydantic 검증 → llm_pattern_cards.json
"""

import json
import sys
from pathlib import Path

from pattern_card_schema import PatternCard, DiscoveryResult, auto_fix, validate_card


# ── 경로 설정 ─────────────────────────────────────────────────────

DEFAULT_BASE = Path(r"c:/Users/deser/Desktop/project/Patch-Learner-main/firmware/ubiquiti_s2/diffs/UVC_vs_uvc")


# ── 프롬프트 템플릿 ───────────────────────────────────────────────

DISCOVERY_PROMPT = """You are a firmware security triage specialist.

Your job is to QUICKLY assess each candidate function and decide if it's worth deep analysis.
Do NOT analyze in detail — just decide: is this a real security change or just a rebuild/refactor?

## Criteria for security-relevant:
- Cryptographic algorithm changes (key sizes, modes, padding)
- Authentication/authorization logic changes
- Input validation additions or removals
- Memory safety fixes (bounds checks, NULL checks)
- Network protocol handling changes
- Privilege escalation fixes

## Criteria for NOT security-relevant:
- Simple recompilation differences (address changes only)
- Cosmetic changes (variable renaming, formatting)
- Debug/logging changes with no security impact
- Version string updates

For each function, read the diff file and output JSON:
```json
{{
  "binary": "...",
  "function": "...",
  "is_security_candidate": true/false,
  "reason": "brief explanation",
  "estimated_severity": "HIGH/MEDIUM/LOW/INFO"
}}
```

## Candidates to triage:
{candidates}
"""

ANALYSIS_PROMPT = """You are a firmware security analyst specializing in IoT embedded systems.

Analyze the following function that was changed between two firmware versions.
The code is ARM Linux embedded firmware pseudocode decompiled by IDA Pro (Hex-Rays).

## Function Information
- Binary: {binary}
- Function name: {function}
- Discovery assessment: {discovery_reason}

## Before (old firmware):
```c
{old_code}
```

## After (new firmware):
```c
{new_code}
```

## Diff:
```diff
{diff_code}
```

Analyze this change and respond in the following JSON format only (no markdown, no extra text):
{{
  "vulnerability_type": "one of: Buffer Overflow / Command Injection / Authentication Bypass / Format String / Integer Overflow / Use After Free / NULL Pointer Dereference / Path Traversal / Cryptographic Weakness / Input Validation / Access Control / Information Disclosure / Memory Corruption / Race Condition / Logic Error / Double Free / Other",
  "cwe": "CWE-XXX",
  "severity": "CRITICAL / HIGH / MEDIUM / LOW / INFO",
  "confidence": "HIGH / MEDIUM / LOW",
  "summary": "One sentence: what vulnerability was fixed",
  "vulnerability_detail": "2-3 sentences explaining the vulnerability in the old code",
  "fix_detail": "2-3 sentences explaining what the fix does",
  "attack_scenario": "Brief description of how an attacker could exploit this",
  "detection_keywords": ["keyword1", "keyword2"],
  "cve_similar": "CVE number if this resembles a known CVE pattern, or null",
  "is_security_relevant": true/false
}}"""

REVIEW_PROMPT = """You are a senior security reviewer. Review these pattern cards for quality:

1. Check if severity ratings are appropriate
2. Check if vulnerability_type matches the actual change
3. Check if is_security_relevant is correct (false positives?)
4. Flag any cards that need re-analysis

Cards to review:
{cards}

For each card, respond:
```json
{{
  "id": "LPC-XXX",
  "approved": true/false,
  "adjusted_severity": "only if changed",
  "adjusted_is_security_relevant": "only if changed",
  "review_note": "why adjusted or approved"
}}
```
"""


# ── Step 1: Discovery 준비 ────────────────────────────────────────

def prepare_discovery(base_dir: Path = DEFAULT_BASE, top_n: int = 50) -> Path:
    """security_candidates.json에서 후보를 읽고 Discovery 입력 파일 생성."""
    candidates_file = base_dir / "security_candidates.json"
    diff_dir = base_dir / "function_diffs"

    with open(candidates_file, encoding="utf-8") as f:
        candidates = json.load(f)

    top = candidates[:top_n]
    discovery_input = []

    for cand in top:
        binary = cand["binary"]
        func = cand["function"]
        bin_dir = diff_dir / binary
        diff_file = bin_dir / f"{func}.c.diff"

        diff_text = ""
        if diff_file.exists():
            diff_text = diff_file.read_text(encoding="utf-8", errors="replace")[:2000]

        discovery_input.append({
            "binary": binary,
            "function": func,
            "score": cand["score"],
            "priority_bin": cand.get("priority_bin", False),
            "lines_added": cand.get("lines_added", 0),
            "lines_removed": cand.get("lines_removed", 0),
            "diff_preview": diff_text,
        })

    output_path = base_dir / "discovery_input.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(discovery_input, f, indent=2, ensure_ascii=False)

    print(f"[Step 1] Discovery 입력 생성: {len(discovery_input)}개 후보")
    print(f"         저장: {output_path}")
    return output_path


# ── Step 2: Discovery 결과 처리 ───────────────────────────────────

def process_discovery(base_dir: Path = DEFAULT_BASE) -> tuple[list[dict], list[dict]]:
    """Discovery 에이전트 결과를 파싱하여 보안 후보와 비보안 후보를 분리."""
    discovery_file = base_dir / "discovery_output.json"

    with open(discovery_file, encoding="utf-8") as f:
        results = json.load(f)

    security = [r for r in results if r.get("is_security_candidate", False)]
    non_security = [r for r in results if not r.get("is_security_candidate", False)]

    print(f"[Step 2] Discovery 결과:")
    print(f"         보안 후보: {len(security)}개")
    print(f"         비보안: {len(non_security)}개")
    print(f"         필터링 비율: {len(non_security)}/{len(results)} ({100*len(non_security)//max(len(results),1)}% 제거)")

    return security, non_security


# ── Step 3: Analysis 배치 분할 ────────────────────────────────────

def prepare_analysis(base_dir: Path = DEFAULT_BASE, num_agents: int = 2) -> list[Path]:
    """보안 후보를 에이전트 수만큼 배치로 분할."""
    security, _ = process_discovery(base_dir)
    diff_dir = base_dir / "function_diffs"

    # 배치 분할 (라운드로빈)
    batches = [[] for _ in range(num_agents)]
    for i, cand in enumerate(security):
        binary = cand["binary"]
        func = cand["function"]
        bin_dir = diff_dir / binary

        old_file = bin_dir / f"{func}_old.c"
        new_file = bin_dir / f"{func}_new.c"
        diff_file = bin_dir / f"{func}.c.diff"

        entry = {
            "binary": binary,
            "function": func,
            "discovery_reason": cand.get("reason", ""),
            "estimated_severity": cand.get("estimated_severity", "MEDIUM"),
            "old_code_path": str(old_file),
            "new_code_path": str(new_file),
            "diff_path": str(diff_file),
        }
        batches[i % num_agents].append(entry)

    output_paths = []
    for idx, batch in enumerate(batches):
        path = base_dir / f"analysis_batch_{idx+1}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(batch, f, indent=2, ensure_ascii=False)
        output_paths.append(path)
        print(f"         Agent {idx+1}: {len(batch)}개 함수 → {path.name}")

    return output_paths


# ── Step 4: 병합 + Pydantic 검증 ─────────────────────────────────

def merge_and_validate(base_dir: Path = DEFAULT_BASE, num_agents: int = 2) -> Path:
    """에이전트 결과를 병합하고 Pydantic으로 검증."""
    all_cards = []

    # 배치 결과 로드
    for idx in range(1, num_agents + 1):
        batch_file = base_dir / f"llm_cards_batch{idx}.json"
        if batch_file.exists():
            with open(batch_file, encoding="utf-8") as f:
                batch = json.load(f)
            all_cards.extend(batch)
            print(f"[Step 4] Batch {idx}: {len(batch)}개 로드")

    # Pydantic 검증
    valid_cards = []
    invalid_cards = []
    auto_fixed_count = 0

    for i, data in enumerate(all_cards):
        card_id = data.get("id", f"LPC-{i+1:03d}")

        # ID가 없으면 부여
        if "id" not in data:
            data["id"] = card_id

        # 자동 보정
        fixed = auto_fix(data)
        if fixed != data:
            auto_fixed_count += 1

        card, errors = validate_card(fixed)
        if card:
            valid_cards.append(card.model_dump())
        else:
            print(f"  [INVALID] {card_id}: {errors[0][:100]}")
            invalid_cards.append(data)

    # 심각도순 정렬
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    valid_cards.sort(key=lambda c: (severity_order.get(c["severity"], 9), c["id"]))

    # ID 재부여
    for i, card in enumerate(valid_cards):
        card["id"] = f"LPC-{i+1:03d}"

    # 저장
    output_path = base_dir / "llm_pattern_cards.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(valid_cards, f, indent=2, ensure_ascii=False)

    # 통계
    print(f"\n=== 최종 결과 ===")
    print(f"전체: {len(all_cards)}개 → 유효: {len(valid_cards)}개, 무효: {len(invalid_cards)}개")
    print(f"자동 보정: {auto_fixed_count}개")

    sec_count = sum(1 for c in valid_cards if c["is_security_relevant"])
    print(f"보안 관련: {sec_count}개")

    by_sev = {}
    for c in valid_cards:
        s = c["severity"]
        by_sev[s] = by_sev.get(s, 0) + 1
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if s in by_sev:
            print(f"  {s}: {by_sev[s]}개")

    print(f"\n저장: {output_path}")
    return output_path


# ── CLI ───────────────────────────────────────────────────────────

def main():
    usage = """
Multi-Agent 패턴 카드 파이프라인

사용법:
  python multi_agent_pipeline.py discovery [base_dir]   — Step 1: Discovery 입력 생성
  python multi_agent_pipeline.py process [base_dir]     — Step 2: Discovery 결과 처리
  python multi_agent_pipeline.py analysis [base_dir]    — Step 3: Analysis 배치 분할
  python multi_agent_pipeline.py merge [base_dir]       — Step 4: 병합 + 검증
  python multi_agent_pipeline.py all [base_dir]         — 전체 (Step 1만, 나머지는 Agent가 수행)

워크플로우:
  1. discovery → discovery_input.json 생성
  2. [Agent] Discovery Agent가 필터링 → discovery_output.json 생성
  3. analysis → analysis_batch_*.json 생성
  4. [Agent] Analysis Agent×2가 분석 → llm_cards_batch*.json 생성
  5. merge → Pydantic 검증 + 병합 → llm_pattern_cards.json
"""

    if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)

    cmd = sys.argv[1]
    base_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_BASE

    if cmd == "discovery":
        prepare_discovery(base_dir)
    elif cmd == "process":
        process_discovery(base_dir)
    elif cmd == "analysis":
        prepare_analysis(base_dir)
    elif cmd == "merge":
        merge_and_validate(base_dir)
    elif cmd == "all":
        prepare_discovery(base_dir)
        print("\n→ 다음: Discovery Agent가 discovery_input.json을 분석하여 discovery_output.json 생성")
    else:
        print(f"알 수 없는 명령: {cmd}")
        print(usage)
        sys.exit(1)


if __name__ == "__main__":
    main()
