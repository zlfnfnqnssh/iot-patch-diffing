"""Stage 2 Phase 1 Drafter 오케스트레이터.

두 가지 명령:
  prepare <session_id> [--limit N]  : Drafter 입력 JSON 생성
  apply   <drafter_output.json>     : Drafter 출력을 DB에 INSERT + Auto-merge

Drafter 호출(LLM) 자체는 이 스크립트가 하지 않는다. Agent tool 또는
Anthropic SDK로 외부에서 돌리고, 결과 JSON 파일을 apply에 넘긴다.

실행 예:
  python src/stage2/drafter_run.py prepare 8 --limit 15 --out tmp/stage2/in_s8.json
  # ... Agent가 drafter 프롬프트로 처리 후 결과를 tmp/stage2/out_s8.json에 저장 ...
  python src/stage2/drafter_run.py apply tmp/stage2/out_s8.json
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

DEFAULT_DB = Path(__file__).resolve().parents[2] / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"


# =============================================================================
# prepare
# =============================================================================

def cmd_prepare(args: argparse.Namespace) -> int:
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    rows = c.execute(
        """
        SELECT
            cf.id AS changed_function_id,
            cf.binary_name,
            cf.function_name,
            cf.old_address,
            cf.new_address,
            cf.similarity,
            cf.decompiled_old,
            cf.decompiled_new,
            fo.vendor AS vendor,
            fo.model  AS model,
            fo.version AS old_version,
            fn.version AS new_version
        FROM changed_functions cf
        JOIN bindiff_results br ON cf.bindiff_result_id = br.id
        JOIN changed_files chf   ON br.changed_file_id  = chf.id
        JOIN diff_sessions ds    ON chf.diff_session_id = ds.id
        JOIN firmware_versions fo ON ds.old_version_id = fo.id
        JOIN firmware_versions fn ON ds.new_version_id = fn.id
        WHERE ds.id = ?
          AND cf.stage2_status = 'prefiltered_in'
        ORDER BY cf.similarity ASC, cf.id ASC
        LIMIT ?
        """,
        (args.session_id, args.limit),
    ).fetchall()

    if not rows:
        print(f"[prepare] no prefiltered_in functions in session {args.session_id}", file=sys.stderr)
        return 1

    meta = rows[0]
    payload: dict[str, Any] = {
        "session": {
            "session_id": args.session_id,
            "vendor": meta["vendor"],
            "model": meta["model"],
            "old_version": meta["old_version"],
            "new_version": meta["new_version"],
        },
        "analyst_id": args.analyst_id,
        "functions": [],
    }
    for r in rows:
        payload["functions"].append({
            "changed_function_id": r["changed_function_id"],
            "binary_name": r["binary_name"],
            "function_name": r["function_name"],
            "old_address": r["old_address"],
            "new_address": r["new_address"],
            "similarity": r["similarity"],
            "decompiled_old": r["decompiled_old"],
            "decompiled_new": r["decompiled_new"],
        })

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[prepare] wrote {len(payload['functions'])} functions -> {out_path}")

    # stage2_status를 drafting_a1/a2로 전이
    ids = [r["changed_function_id"] for r in rows]
    new_status = f"drafting_{args.analyst_id.lower()}"
    placeholders = ",".join("?" * len(ids))
    conn.execute(
        f"UPDATE changed_functions SET stage2_status = ? WHERE id IN ({placeholders})",
        [new_status, *ids],
    )
    conn.commit()
    conn.close()
    print(f"[prepare] marked {len(ids)} rows as stage2_status='{new_status}'")
    return 0


# =============================================================================
# apply
# =============================================================================

def _ensure_card_and_merge(
    conn: sqlite3.Connection,
    card: dict[str, Any],
    security_patch_id: int,
    snippet_origin: str,
    batch_tag: str | None = None,
) -> int:
    """Auto-merge 규칙 적용.

    같은 (source_type, sink_type, missing_check) 공식의 active 카드가 있으면:
      - 새 카드 생성 안 함
      - pattern_card_members에 행만 추가
      - 기존 카드의 스니펫이 비어 있거나 새 것이 더 짧으면 version++ + 스니펫 교체 (선택)

    없으면 새 카드 INSERT + tokens/negative_tokens/grep_patterns INSERT.

    Returns card_id (pattern_cards.id).
    """
    c = conn.cursor()
    existing = c.execute(
        """
        SELECT id, version, vulnerable_snippet, fixed_snippet
        FROM pattern_cards
        WHERE source_type = ? AND sink_type = ? AND missing_check = ?
          AND status = 'active'
        """,
        (card["source_type"], card["sink_type"], card["missing_check"]),
    ).fetchone()

    if existing:
        card_pk = existing[0]
        # 이미 있는 카드 - 멤버만 추가
        try:
            c.execute(
                """INSERT INTO pattern_card_members (card_id, security_patch_id, is_representative, note)
                VALUES (?, ?, 0, ?)""",
                (card_pk, security_patch_id, "auto-merged by Drafter"),
            )
        except sqlite3.IntegrityError:
            pass  # UNIQUE(card_id, security_patch_id) - 이미 연결됨

        # 추가 토큰/negative_tokens merge (UNIQUE로 중복 INSERT 자동 차단)
        for t in card.get("tokens", []):
            try:
                c.execute(
                    """INSERT INTO pattern_card_tokens (card_id, token, kind, weight)
                    VALUES (?, ?, ?, ?)""",
                    (card_pk, t["token"], t["kind"], t.get("weight", 1.0)),
                )
            except sqlite3.IntegrityError:
                pass
        for nt in card.get("negative_tokens", []):
            try:
                c.execute(
                    """INSERT INTO pattern_card_negative_tokens (card_id, token, vendor_scope, note)
                    VALUES (?, ?, ?, ?)""",
                    (card_pk, nt["token"], nt.get("vendor_scope"), nt.get("note")),
                )
            except sqlite3.IntegrityError:
                pass
        return card_pk

    # 새 카드 생성
    # card_id 다음 번호 생성
    max_num = c.execute(
        "SELECT MAX(CAST(SUBSTR(card_id, 3) AS INTEGER)) FROM pattern_cards WHERE card_id LIKE 'P-%'"
    ).fetchone()[0] or 0
    new_card_id = f"P-{max_num + 1:03d}"

    c.execute(
        """
        INSERT INTO pattern_cards (
            card_id, source_type, source_detail, sink_type, sink_detail, missing_check,
            summary, vulnerable_snippet, fixed_snippet, snippet_origin, snippet_language,
            long_description, attack_scenario, fix_detail,
            severity_hint, cve_similar, advisory, status, version, created_in_batch
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1, ?)
        """,
        (
            new_card_id,
            card["source_type"], card.get("source_detail"),
            card["sink_type"], card.get("sink_detail"),
            card["missing_check"],
            card["summary"],
            card["vulnerable_snippet"], card["fixed_snippet"],
            snippet_origin, card.get("snippet_language", "decompiled_c"),
            card.get("long_description"), card.get("attack_scenario"), card.get("fix_detail"),
            card.get("severity_hint"), card.get("cve_similar"), card.get("advisory"),
            batch_tag,
        ),
    )
    card_pk = c.lastrowid

    # 대표 멤버
    c.execute(
        """INSERT INTO pattern_card_members (card_id, security_patch_id, is_representative, note)
        VALUES (?, ?, 1, ?)""",
        (card_pk, security_patch_id, "original representative"),
    )

    # 토큰
    for t in card.get("tokens", []):
        c.execute(
            """INSERT INTO pattern_card_tokens (card_id, token, kind, weight)
            VALUES (?, ?, ?, ?)""",
            (card_pk, t["token"], t["kind"], t.get("weight", 1.0)),
        )
    for nt in card.get("negative_tokens", []):
        c.execute(
            """INSERT INTO pattern_card_negative_tokens (card_id, token, vendor_scope, note)
            VALUES (?, ?, ?, ?)""",
            (card_pk, nt["token"], nt.get("vendor_scope"), nt.get("note")),
        )
    for gp in card.get("grep_patterns", []):
        if isinstance(gp, str):
            c.execute(
                """INSERT INTO pattern_card_grep_patterns (card_id, pattern, pattern_flavor)
                VALUES (?, ?, 'python_re')""",
                (card_pk, gp),
            )
        else:
            c.execute(
                """INSERT INTO pattern_card_grep_patterns (card_id, pattern, pattern_flavor)
                VALUES (?, ?, ?)""",
                (card_pk, gp["pattern"], gp.get("pattern_flavor", "python_re")),
            )

    c.execute(
        "INSERT INTO pattern_card_stats (card_id, matches_total, true_positives, false_positives) VALUES (?, 0, 0, 0)",
        (card_pk,),
    )
    return card_pk


def cmd_apply(args: argparse.Namespace) -> int:
    # 여러 파일을 받을 수 있음. 병렬 Agent가 각자 out 파일을 쓰면 한 번에 merge apply.
    sources: list[str] = args.output_jsons
    payload: list[dict[str, Any]] = []
    for p in sources:
        raw = Path(p).read_text(encoding="utf-8")
        part = json.loads(raw)
        if not isinstance(part, list):
            print(f"[apply] {p}: top-level JSON array 아님 -- 스킵", file=sys.stderr)
            continue
        payload.extend(part)
        print(f"[apply] loaded {len(part)} items from {Path(p).name}")
    if not payload:
        print("[apply] 아무 항목도 없음.", file=sys.stderr)
        return 1

    conn = sqlite3.connect(args.db)
    c = conn.cursor()
    # 컬럼 존재 확인 후 needs_human_review 지원
    cols = {r[1] for r in c.execute("PRAGMA table_info(security_patches)")}
    has_nhr = "needs_human_review" in cols

    inserted_patches = 0
    new_cards = 0
    merged_cards = 0
    nonsec = 0
    errors: list[str] = []

    for item in payload:
        try:
            cf_id = item["changed_function_id"]
            analyst_id = item.get("analyst_id", "A1")
            is_sec = bool(item["is_security_patch"])
            conf = item["confidence"]
            patch = item.get("patch_record") or {}
            # v4: needs_human_review 플래그. Drafter가 명시하지 않으면 confidence 구간으로 자동 판단.
            nhr_explicit = item.get("needs_human_review")
            if nhr_explicit is None:
                needs_review = is_sec and conf is not None and 0.50 <= conf < 0.70
            else:
                needs_review = bool(nhr_explicit)

            if has_nhr:
                c.execute(
                    """
                    INSERT INTO security_patches (
                        changed_function_id, is_security_patch, confidence, vuln_type, cwe,
                        severity, root_cause, fix_description, fix_category,
                        attack_vector, requires_auth, attack_surface,
                        source_desc, sink_desc, missing_check,
                        known_cve, llm_model, llm_prompt_ver, analyst_id, analysis_raw,
                        needs_human_review
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cf_id, 1 if is_sec else 0, conf,
                        patch.get("vuln_type"), patch.get("cwe"),
                        patch.get("severity"),
                        patch.get("root_cause"), patch.get("fix_description"), patch.get("fix_category"),
                        patch.get("attack_vector"),
                        1 if patch.get("requires_auth") else (0 if "requires_auth" in patch else None),
                        patch.get("attack_surface"),
                        patch.get("source_desc"), patch.get("sink_desc"), patch.get("missing_check"),
                        patch.get("known_cve"),
                        "claude-opus-4-6[1m]", "stage2-drafter-v4", analyst_id,
                        json.dumps(item, ensure_ascii=False),
                        1 if needs_review else 0,
                    ),
                )
            else:
                c.execute(
                    """
                    INSERT INTO security_patches (
                        changed_function_id, is_security_patch, confidence, vuln_type, cwe,
                        severity, root_cause, fix_description, fix_category,
                        attack_vector, requires_auth, attack_surface,
                        source_desc, sink_desc, missing_check,
                        known_cve, llm_model, llm_prompt_ver, analyst_id, analysis_raw
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cf_id, 1 if is_sec else 0, conf,
                        patch.get("vuln_type"), patch.get("cwe"),
                        patch.get("severity"),
                        patch.get("root_cause"), patch.get("fix_description"), patch.get("fix_category"),
                        patch.get("attack_vector"),
                        1 if patch.get("requires_auth") else (0 if "requires_auth" in patch else None),
                        patch.get("attack_surface"),
                        patch.get("source_desc"), patch.get("sink_desc"), patch.get("missing_check"),
                        patch.get("known_cve"),
                        "claude-opus-4-6[1m]", "stage2-drafter-v4", analyst_id,
                        json.dumps(item, ensure_ascii=False),
                    ),
                )
            sp_id = c.lastrowid
            inserted_patches += 1

            if is_sec and item.get("card_draft"):
                card = item["card_draft"]
                # 필수 필드 검증
                for required in ("source_type", "sink_type", "missing_check",
                                 "summary", "vulnerable_snippet", "fixed_snippet"):
                    if not card.get(required):
                        raise ValueError(f"card_draft missing '{required}'")
                snippet_origin = card.get("snippet_origin") or f"{item.get('binary_name','?')}/{item.get('function_name','?')}"

                existing_before = c.execute(
                    """SELECT id FROM pattern_cards
                       WHERE source_type = ? AND sink_type = ? AND missing_check = ?
                         AND status = 'active'""",
                    (card["source_type"], card["sink_type"], card["missing_check"]),
                ).fetchone()

                card_pk = _ensure_card_and_merge(conn, card, sp_id, snippet_origin, batch_tag=getattr(args, "batch", None))
                if existing_before:
                    merged_cards += 1
                else:
                    new_cards += 1

                c.execute(
                    "UPDATE security_patches SET pattern_card_id = ? WHERE id = ?",
                    (card_pk, sp_id),
                )
                c.execute(
                    "UPDATE changed_functions SET stage2_status = 'drafted_sec' WHERE id = ?",
                    (cf_id,),
                )
            else:
                nonsec += 1
                c.execute(
                    "UPDATE changed_functions SET stage2_status = 'drafted_nonsec' WHERE id = ?",
                    (cf_id,),
                )
        except Exception as e:  # noqa: BLE001
            errors.append(f"cf_id={item.get('changed_function_id')} err={e}")

    conn.commit()
    conn.close()

    print(f"[apply] security_patches inserted: {inserted_patches}")
    print(f"[apply]   - new cards:    {new_cards}")
    print(f"[apply]   - auto-merged:  {merged_cards}")
    print(f"[apply]   - non-security: {nonsec}")
    if errors:
        print(f"[apply] ERRORS ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")
        return 2

    # === v4: 성공하면 tmp 입출력 JSON 자동 삭제 (용량 관리) ===
    if not args.keep_tmp:
        removed = 0
        for out_path in sources:
            op = Path(out_path)
            if op.exists():
                op.unlink()
                removed += 1
            # 대응 input 추정: out_s11_a1.json -> in_s11_a1.json
            name = op.name
            if name.startswith("out_"):
                in_candidate = op.parent / ("in_" + name[4:])
                if in_candidate.exists():
                    in_candidate.unlink()
                    removed += 1
            # 대응 통합 input도 삭제: in_s11.json (a1/a2 prefix 없는 것)
            # 샤드 이름에서 _aN 떼서 base 도출
            import re as _re
            m = _re.match(r"out_(.*?)_a\d+\.json$", name)
            if m:
                base_input = op.parent / f"in_{m.group(1)}.json"
                if base_input.exists():
                    base_input.unlink()
                    removed += 1
        if removed:
            print(f"[apply] cleaned {removed} tmp json(s). (--keep-tmp to preserve)")
    return 0


# =============================================================================
# main
# =============================================================================

def cmd_reset(args: argparse.Namespace) -> int:
    """Stage 2 전체 리셋: security_patches + pattern_cards + 부속 테이블 전부 삭제,
    changed_functions.stage2_status의 drafted_*/drafting_* → prefiltered_in로 복구.
    Phase 0 상태(skipped_oss/prefiltered_out)는 유지.
    """
    if not args.yes:
        print("[reset] --yes 필요. 안전장치.", file=sys.stderr)
        return 1
    conn = sqlite3.connect(args.db)
    c = conn.cursor()

    sp_n = c.execute("SELECT COUNT(*) FROM security_patches").fetchone()[0]
    pc_n = c.execute("SELECT COUNT(*) FROM pattern_cards").fetchone()[0]
    hf_n = c.execute("SELECT COUNT(*) FROM hunt_findings").fetchone()[0]
    print(f"[reset] before: security_patches={sp_n}, pattern_cards={pc_n}, hunt_findings={hf_n}")

    # 부속 테이블은 ON DELETE CASCADE가 있으므로 pattern_cards만 비우면 자동 따라옴.
    # 하지만 명시적으로도 정리 — 안전하게.
    c.execute("DELETE FROM hunt_findings")
    c.execute("DELETE FROM pattern_card_stats")
    c.execute("DELETE FROM pattern_card_members")
    c.execute("DELETE FROM pattern_card_grep_patterns")
    c.execute("DELETE FROM pattern_card_negative_tokens")
    c.execute("DELETE FROM pattern_card_tokens")
    c.execute("DELETE FROM pattern_cards")
    c.execute("DELETE FROM security_patches")

    # stage2_status 복구: drafted_*/drafting_*/error → prefiltered_in
    c.execute(
        """
        UPDATE changed_functions
        SET stage2_status = 'prefiltered_in'
        WHERE stage2_status IN ('drafting_a1','drafting_a2','drafting_a3','drafting_a4',
                                 'drafted_sec','drafted_nonsec','error')
        """
    )

    # sqlite_sequence 리셋 (AUTOINCREMENT 카운터 — card_id P-001부터 다시 시작하려면)
    c.execute("DELETE FROM sqlite_sequence WHERE name IN ('pattern_cards', 'security_patches', 'hunt_findings', 'pattern_card_tokens', 'pattern_card_negative_tokens', 'pattern_card_grep_patterns', 'pattern_card_members', 'pattern_card_stats')")

    conn.commit()

    print("[reset] done.")
    print("[reset] after:")
    for tbl in ("security_patches", "pattern_cards", "hunt_findings"):
        n = c.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        print(f"  {tbl}: {n}")
    print("[reset] stage2_status 분포:")
    for s, n in c.execute("SELECT stage2_status, COUNT(*) FROM changed_functions GROUP BY stage2_status ORDER BY 2 DESC"):
        print(f"  {s}: {n:,}")
    conn.close()
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    """중단된 세션 복구. drafting_a1/a2 상태인데 security_patches에 없는 레코드를
    prefiltered_in으로 되돌려 다음 배치에서 다시 잡히게 한다.
    현재 진행 상황 + 남은 세션 요약도 출력.
    """
    conn = sqlite3.connect(args.db)
    c = conn.cursor()

    stale = c.execute(
        """
        SELECT cf.id FROM changed_functions cf
        LEFT JOIN security_patches sp ON sp.changed_function_id = cf.id
        WHERE cf.stage2_status IN ('drafting_a1', 'drafting_a2')
          AND sp.id IS NULL
        """
    ).fetchall()

    if stale:
        ids = [r[0] for r in stale]
        print(f"[resume] reverting {len(ids)} stale drafting_* rows -> prefiltered_in")
        for i in range(0, len(ids), 500):
            chunk = ids[i : i + 500]
            placeholders = ",".join("?" * len(chunk))
            conn.execute(
                f"UPDATE changed_functions SET stage2_status='prefiltered_in' WHERE id IN ({placeholders})",
                chunk,
            )
        conn.commit()
    else:
        print("[resume] no stale drafting_* rows.")

    print("\n=== stage2 distribution ===")
    for s, n in c.execute(
        "SELECT stage2_status, COUNT(*) AS cnt FROM changed_functions GROUP BY stage2_status ORDER BY cnt DESC"
    ):
        print(f"  {s}: {n:,}")

    print("\n=== cards / patches ===")
    total_cards = c.execute("SELECT COUNT(*) FROM pattern_cards WHERE status='active'").fetchone()[0]
    total_patches = c.execute("SELECT COUNT(*) FROM security_patches").fetchone()[0]
    sec_patches = c.execute("SELECT COUNT(*) FROM security_patches WHERE is_security_patch=1").fetchone()[0]
    print(f"  pattern_cards(active): {total_cards}")
    print(f"  security_patches: {total_patches} (security={sec_patches})")

    print("\n=== top 10 sessions with remaining prefiltered_in ===")
    for r in c.execute(
        """
        SELECT ds.id, fo.vendor, fo.model, fo.version, fn.version, COUNT(cf.id) AS n
        FROM diff_sessions ds
        JOIN firmware_versions fo ON ds.old_version_id = fo.id
        JOIN firmware_versions fn ON ds.new_version_id = fn.id
        JOIN changed_files chf ON chf.diff_session_id = ds.id
        JOIN bindiff_results br ON br.changed_file_id = chf.id
        JOIN changed_functions cf ON cf.bindiff_result_id = br.id
        WHERE cf.stage2_status = 'prefiltered_in'
        GROUP BY ds.id ORDER BY n DESC LIMIT 10
        """
    ):
        print(f"  session {r[0]:>3} | {r[1]:<10} {r[2]:<30} v{r[3]:>8} -> v{r[4]:<8} {r[5]:>5} funcs")

    conn.close()
    return 0


def cmd_split(args: argparse.Namespace) -> int:
    """prepare 산출물을 N 샤드로 쪼개서 병렬 Agent에 배분.

    샤딩 전략: 바이너리(binary_name) 단위 유지 (도메인 학습 이점).
    LPT(Longest Processing Time) — 큰 binary부터 가장 작은 shard에 배정.
    바이너리가 너무 크면 해당 shard가 불가피하게 커질 수 있음.
    """
    from collections import defaultdict

    src = Path(args.input)
    data = json.loads(src.read_text(encoding="utf-8"))
    funcs = data["functions"]
    shards = max(1, args.shards)

    by_binary: dict[str, list[dict]] = defaultdict(list)
    for f in funcs:
        by_binary[f["binary_name"]].append(f)

    shard_lists: list[list[dict]] = [[] for _ in range(shards)]
    shard_sizes = [0] * shards
    for binary, fs in sorted(by_binary.items(), key=lambda x: -len(x[1])):
        idx = shard_sizes.index(min(shard_sizes))
        shard_lists[idx].extend(fs)
        shard_sizes[idx] += len(fs)

    base = src.stem  # 'in_s78'
    out_dir = src.parent
    out_paths: list[Path] = []
    for i, shard in enumerate(shard_lists, start=1):
        if not shard:
            continue
        p = out_dir / f"{base}_a{i}.json"
        payload = {
            "session": data["session"],
            "analyst_id": f"A{i}",
            "functions": shard,
        }
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        bins = sorted({f["binary_name"] for f in shard})
        print(f"  [A{i}] {p.name}: {len(shard)} funcs, binaries={bins}")
        out_paths.append(p)

    # Agent에게 안내할 expected output 경로
    print("\nexpected Drafter outputs (write these paths):")
    stem_after_in = base[3:] if base.startswith("in_") else base
    for i in range(1, len(out_paths) + 1):
        print(f"  tmp/stage2/out_{stem_after_in}_a{i}.json")

    return 0


def cmd_next_batch_info(args: argparse.Namespace) -> int:
    """다음 배치에 가장 좋은 세션 1개 + 함수 수 출력 (JSON).
    사용 예: `next_batch_info --prefer-session 14` 로 특정 세션 우선.
    """
    conn = sqlite3.connect(args.db)
    c = conn.cursor()
    if args.prefer_session:
        r = c.execute(
            """
            SELECT ds.id, fo.vendor, fo.model, fo.version, fn.version, COUNT(cf.id) AS n
            FROM diff_sessions ds
            JOIN firmware_versions fo ON ds.old_version_id = fo.id
            JOIN firmware_versions fn ON ds.new_version_id = fn.id
            JOIN changed_files chf ON chf.diff_session_id = ds.id
            JOIN bindiff_results br ON br.changed_file_id = chf.id
            JOIN changed_functions cf ON cf.bindiff_result_id = br.id
            WHERE cf.stage2_status='prefiltered_in' AND ds.id = ?
            GROUP BY ds.id
            """,
            (args.prefer_session,),
        ).fetchone()
    else:
        r = c.execute(
            """
            SELECT ds.id, fo.vendor, fo.model, fo.version, fn.version, COUNT(cf.id) AS n
            FROM diff_sessions ds
            JOIN firmware_versions fo ON ds.old_version_id = fo.id
            JOIN firmware_versions fn ON ds.new_version_id = fn.id
            JOIN changed_files chf ON chf.diff_session_id = ds.id
            JOIN bindiff_results br ON br.changed_file_id = chf.id
            JOIN changed_functions cf ON cf.bindiff_result_id = br.id
            WHERE cf.stage2_status='prefiltered_in'
            GROUP BY ds.id ORDER BY n DESC LIMIT 1
            """
        ).fetchone()
    if not r:
        print(json.dumps({"session_id": None}))
        return 0
    print(json.dumps({
        "session_id": r[0], "vendor": r[1], "model": r[2],
        "old_version": r[3], "new_version": r[4], "remaining": r[5],
    }))
    conn.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("prepare", help="Drafter 입력 JSON 생성")
    p1.add_argument("session_id", type=int)
    p1.add_argument("--limit", type=int, default=15)
    p1.add_argument("--analyst-id", default="A1")
    p1.add_argument("--out", required=True)

    p2 = sub.add_parser("apply", help="Drafter 출력 DB 반영 (1개 또는 여러 파일)")
    p2.add_argument("output_jsons", nargs="+", help="out_*.json 파일 1개 이상")
    p2.add_argument("--keep-tmp", action="store_true", help="apply 후 tmp in_*/out_* 자동 삭제 끄기")
    p2.add_argument("--batch", default=None, help="새로 생성되는 pattern_cards 에 기록할 batch 태그 (예: 'v2', 'v3', 'batch-04-29'). delta hunt 에서 이 태그로 필터링.")

    p6 = sub.add_parser("reset", help="Stage 2 전체 리셋 (security_patches + pattern_cards 등 삭제)")
    p6.add_argument("--yes", action="store_true", help="안전장치 — 실제 삭제하려면 --yes 필수")

    p5 = sub.add_parser("split", help="prepare 산출물을 N 샤드로 쪼개서 병렬 Agent 배분")
    p5.add_argument("input", help="prepare로 만든 in_*.json")
    p5.add_argument("--shards", type=int, default=4)

    p3 = sub.add_parser("resume", help="중단된 drafting_* 상태 복구 + 현재 진행 요약")

    p4 = sub.add_parser("next-batch-info", help="다음 배치 대상 세션 1개 JSON 출력")
    p4.add_argument("--prefer-session", type=int, default=None)

    args = ap.parse_args()
    if args.cmd == "prepare":
        return cmd_prepare(args)
    elif args.cmd == "apply":
        return cmd_apply(args)
    elif args.cmd == "resume":
        return cmd_resume(args)
    elif args.cmd == "next-batch-info":
        return cmd_next_batch_info(args)
    elif args.cmd == "split":
        return cmd_split(args)
    elif args.cmd == "reset":
        return cmd_reset(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
