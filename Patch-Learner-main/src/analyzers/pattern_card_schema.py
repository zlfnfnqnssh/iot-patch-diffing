"""
패턴 카드 Pydantic 스키마 및 검증 모듈.

LLM이 생성한 패턴 카드 JSON을 구조화된 스키마로 검증하고,
잘못된 필드를 자동 보정한다.
"""

import json
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Enum 정의 ─────────────────────────────────────────────────────

class VulnerabilityType(str, Enum):
    BUFFER_OVERFLOW = "Buffer Overflow"
    COMMAND_INJECTION = "Command Injection"
    AUTH_BYPASS = "Authentication Bypass"
    FORMAT_STRING = "Format String"
    INTEGER_OVERFLOW = "Integer Overflow"
    USE_AFTER_FREE = "Use After Free"
    NULL_POINTER = "NULL Pointer Dereference"
    PATH_TRAVERSAL = "Path Traversal"
    CRYPTO_WEAKNESS = "Cryptographic Weakness"
    INPUT_VALIDATION = "Input Validation"
    ACCESS_CONTROL = "Access Control"
    INFO_DISCLOSURE = "Information Disclosure"
    MEMORY_CORRUPTION = "Memory Corruption"
    RACE_CONDITION = "Race Condition"
    LOGIC_ERROR = "Logic Error"
    DOUBLE_FREE = "Double Free"
    OTHER = "Other"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ── 패턴 카드 스키마 ──────────────────────────────────────────────

class PatternCard(BaseModel):
    """LLM 기반 패턴 카드 스키마."""

    id: str = Field(description="카드 고유 ID (예: LPC-001)")
    binary: str = Field(description="바이너리 이름")
    function: str = Field(description="함수 이름")

    vulnerability_type: VulnerabilityType
    cwe: str = Field(description="CWE 번호 (예: CWE-120)")
    severity: Severity
    confidence: Confidence
    is_security_relevant: bool

    summary: str = Field(min_length=10, description="취약점 한 줄 요약")
    vulnerability_detail: str = Field(min_length=10, description="취약점 상세 설명")
    fix_detail: str = Field(min_length=10, description="수정 내용 설명")
    attack_scenario: str = Field(min_length=10, description="공격 시나리오")
    detection_keywords: list[str] = Field(min_length=1, description="탐지 키워드")
    cve_similar: Optional[str] = Field(default=None, description="유사 CVE (예: CVE-2021-36260)")

    # 메타데이터 (선택)
    score: Optional[int] = None
    priority_bin: Optional[bool] = None
    lines_added: Optional[int] = None
    lines_removed: Optional[int] = None

    @field_validator("cwe")
    @classmethod
    def validate_cwe(cls, v: str) -> str:
        v = v.strip().upper()
        if not re.match(r"^CWE-\d+$", v):
            # "CWE120" → "CWE-120", "120" → "CWE-120"
            nums = re.findall(r"\d+", v)
            if nums:
                return f"CWE-{nums[0]}"
            raise ValueError(f"유효하지 않은 CWE 형식: {v}")
        return v

    @field_validator("cve_similar")
    @classmethod
    def validate_cve(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.lower() in ("null", "none", "n/a", ""):
            return None
        v = v.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d+$", v):
            raise ValueError(f"유효하지 않은 CVE 형식: {v}")
        return v

    @field_validator("vulnerability_type", mode="before")
    @classmethod
    def normalize_vuln_type(cls, v: str) -> str:
        """비정형 입력을 표준 VulnerabilityType으로 매핑."""
        if isinstance(v, VulnerabilityType):
            return v
        v_lower = v.strip().lower()
        mapping = {
            "buffer overflow": "Buffer Overflow",
            "bof": "Buffer Overflow",
            "stack overflow": "Buffer Overflow",
            "heap overflow": "Buffer Overflow",
            "command injection": "Command Injection",
            "os command injection": "Command Injection",
            "cmd injection": "Command Injection",
            "authentication bypass": "Authentication Bypass",
            "auth bypass": "Authentication Bypass",
            "format string": "Format String",
            "format string bug": "Format String",
            "integer overflow": "Integer Overflow",
            "int overflow": "Integer Overflow",
            "use after free": "Use After Free",
            "uaf": "Use After Free",
            "null pointer dereference": "NULL Pointer Dereference",
            "null deref": "NULL Pointer Dereference",
            "null pointer": "NULL Pointer Dereference",
            "path traversal": "Path Traversal",
            "directory traversal": "Path Traversal",
            "cryptographic weakness": "Cryptographic Weakness",
            "crypto weakness": "Cryptographic Weakness",
            "weak cryptography": "Cryptographic Weakness",
            "cryptographic improvement": "Cryptographic Weakness",
            "input validation": "Input Validation",
            "input validation missing": "Input Validation",
            "improper input validation": "Input Validation",
            "access control": "Access Control",
            "information disclosure": "Information Disclosure",
            "info disclosure": "Information Disclosure",
            "info leak": "Information Disclosure",
            "memory corruption": "Memory Corruption",
            "race condition": "Race Condition",
            "toctou": "Race Condition",
            "logic error": "Logic Error",
            "logic bug": "Logic Error",
            "double free": "Double Free",
        }
        return mapping.get(v_lower, v)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        if isinstance(v, Severity):
            return v
        return v.strip().upper()

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, v: str) -> str:
        if isinstance(v, Confidence):
            return v
        return v.strip().upper()


# ── Discovery 결과 스키마 ─────────────────────────────────────────

class DiscoveryResult(BaseModel):
    """Discovery 에이전트의 필터링 결과."""

    binary: str
    function: str
    is_security_candidate: bool = Field(description="보안 관련 후보 여부")
    reason: str = Field(min_length=5, description="판단 근거")
    estimated_severity: Severity = Field(description="예상 심각도")


class DiscoveryBatch(BaseModel):
    """Discovery 에이전트 배치 결과."""

    results: list[DiscoveryResult]
    total_analyzed: int
    security_candidates: int

    @model_validator(mode="after")
    def check_counts(self):
        actual = sum(1 for r in self.results if r.is_security_candidate)
        if actual != self.security_candidates:
            self.security_candidates = actual
        return self


# ── 검증 함수 ─────────────────────────────────────────────────────

def validate_card(data: dict) -> tuple[PatternCard | None, list[str]]:
    """단일 패턴 카드 검증. (card, errors) 반환."""
    errors = []
    try:
        card = PatternCard(**data)
        return card, []
    except Exception as e:
        return None, [str(e)]


def validate_cards_file(filepath: str | Path) -> dict:
    """JSON 파일의 전체 패턴 카드를 검증하고 결과 리포트 반환."""
    filepath = Path(filepath)
    with open(filepath, encoding="utf-8") as f:
        cards_data = json.load(f)

    valid = []
    invalid = []
    auto_fixed = []

    for i, data in enumerate(cards_data):
        card_id = data.get("id", f"unknown-{i}")

        # 자동 보정 시도
        fixed_data = auto_fix(data)
        card, errors = validate_card(fixed_data)

        if card:
            if fixed_data != data:
                auto_fixed.append({"id": card_id, "fixes": _diff_keys(data, fixed_data)})
            valid.append(card.model_dump())
        else:
            invalid.append({"id": card_id, "errors": errors, "data": data})

    report = {
        "file": str(filepath),
        "total": len(cards_data),
        "valid": len(valid),
        "invalid": len(invalid),
        "auto_fixed": len(auto_fixed),
        "invalid_details": invalid,
        "auto_fix_details": auto_fixed,
    }

    return report, valid


def auto_fix(data: dict) -> dict:
    """자동 보정 가능한 필드 수정."""
    fixed = dict(data)

    # cve_similar: "null" 문자열 → None
    if fixed.get("cve_similar") in ("null", "None", "N/A", ""):
        fixed["cve_similar"] = None

    # severity 대소문자
    if "severity" in fixed and isinstance(fixed["severity"], str):
        fixed["severity"] = fixed["severity"].strip().upper()

    # confidence 대소문자
    if "confidence" in fixed and isinstance(fixed["confidence"], str):
        fixed["confidence"] = fixed["confidence"].strip().upper()

    # cwe 형식 보정
    if "cwe" in fixed and isinstance(fixed["cwe"], str):
        cwe = fixed["cwe"].strip()
        if re.match(r"^\d+$", cwe):
            fixed["cwe"] = f"CWE-{cwe}"
        elif re.match(r"^CWE\d+$", cwe, re.IGNORECASE):
            fixed["cwe"] = f"CWE-{re.findall(r'[0-9]+', cwe)[0]}"

    # is_security_relevant: 문자열 → bool
    if isinstance(fixed.get("is_security_relevant"), str):
        fixed["is_security_relevant"] = fixed["is_security_relevant"].lower() == "true"

    # 짧은 텍스트 필드 보정 (비보안 카드에서 "해당 없음" 등)
    short_fields = ["summary", "vulnerability_detail", "fix_detail", "attack_scenario"]
    for field in short_fields:
        val = fixed.get(field, "")
        if isinstance(val, str) and 0 < len(val) < 10:
            fixed[field] = f"{val} (상세 분석 불필요)" if not fixed.get("is_security_relevant") else val

    return fixed


def _diff_keys(original: dict, fixed: dict) -> list[str]:
    """어떤 키가 변경되었는지 반환."""
    changed = []
    for k in fixed:
        if k in original and fixed[k] != original[k]:
            changed.append(f"{k}: {original[k]!r} → {fixed[k]!r}")
    return changed


# ── CLI ───────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python pattern_card_schema.py <pattern_cards.json>")
        print("       검증 결과와 통계를 출력합니다.")
        sys.exit(1)

    filepath = Path(sys.argv[1])
    if not filepath.exists():
        print(f"파일 없음: {filepath}")
        sys.exit(1)

    report, valid_cards = validate_cards_file(filepath)

    print(f"\n=== 패턴 카드 검증 결과 ===")
    print(f"파일: {report['file']}")
    print(f"전체: {report['total']}개")
    print(f"유효: {report['valid']}개")
    print(f"자동 보정: {report['auto_fixed']}개")
    print(f"무효: {report['invalid']}개")

    if report["auto_fix_details"]:
        print(f"\n--- 자동 보정된 카드 ---")
        for fix in report["auto_fix_details"]:
            print(f"  {fix['id']}: {', '.join(fix['fixes'])}")

    if report["invalid_details"]:
        print(f"\n--- 무효 카드 ---")
        for inv in report["invalid_details"]:
            print(f"  {inv['id']}:")
            for err in inv["errors"]:
                print(f"    {err[:200]}")

    # 유효 카드 통계
    if valid_cards:
        by_sev = {}
        by_type = {}
        sec_count = 0
        for c in valid_cards:
            s = c["severity"]
            t = c["vulnerability_type"]
            by_sev[s] = by_sev.get(s, 0) + 1
            by_type[t] = by_type.get(t, 0) + 1
            if c["is_security_relevant"]:
                sec_count += 1

        print(f"\n--- 통계 ---")
        print(f"보안 관련: {sec_count}개")
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if s in by_sev:
                print(f"  {s}: {by_sev[s]}개")

    # 보정된 파일 저장 옵션
    if report["auto_fixed"] > 0 and valid_cards:
        out_path = filepath.parent / f"{filepath.stem}_validated{filepath.suffix}"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(valid_cards, f, indent=2, ensure_ascii=False)
        print(f"\n보정된 파일 저장: {out_path}")


if __name__ == "__main__":
    main()
