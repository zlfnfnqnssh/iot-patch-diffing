"""Merge team leader's pattern_cards.jsonl into our DB.

Strategy (decided 2026-04-19):
  1. Backup DB.
  2. Shift our existing 74 cards: P-001..P-074 -> P-033..P-106.
     Team keeps original P-001..P-032 numbering.
  3. Insert team's 32 cards with original card_ids (P-001..P-032) + tokens +
     negative_tokens + grep_patterns.
  4. Handle formula collisions via idx_pc_formula_active:
     - if a team card's (source, sink, missing) matches an already-active card
       in our DB, we mark the team card status='superseded_by_ours' and set
       superseded_by = our card pk.
     - else active.
  5. Skip importing team card `members` list (their security_patch_ids point to
     THEIR DB, not ours — leave empty here; notes are preserved in the JSONL).

Team file source: git show team/main:data/handoff/pattern_cards.jsonl > tmp/team_pc.jsonl

Usage:
    python src/stage2/merge_team_cards.py --team-jsonl tmp/team_pc.jsonl --apply
    python src/stage2/merge_team_cards.py --team-jsonl tmp/team_pc.jsonl          # dry run
"""
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"
SHIFT_BASE = 32  # our P-001 -> P-033


def format_cid(n: int) -> str:
    return f"P-{n:03d}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--team-jsonl", type=Path, required=True)
    ap.add_argument("--apply", action="store_true",
                    help="actually modify DB (default = dry run)")
    args = ap.parse_args()

    team_lines = [json.loads(l) for l in args.team_jsonl.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"[merge] team cards: {len(team_lines)} ({team_lines[0]['card_id']}..{team_lines[-1]['card_id']})")

    if args.apply:
        bak = args.db.with_suffix(args.db.suffix + f".bak.premerge-team-{int(time.time())}")
        shutil.copy2(args.db, bak)
        print(f"[merge] DB backup -> {bak}")

    conn = sqlite3.connect(str(args.db))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # ── Step 1: shift ours ────────────────────────────────────────────────
    ours = c.execute("SELECT id, card_id FROM pattern_cards ORDER BY id").fetchall()
    print(f"[merge] our current cards: {len(ours)} ({ours[0]['card_id']}..{ours[-1]['card_id']})")

    shift_map: dict[str, str] = {}
    for row in ours:
        old_cid = row["card_id"]
        if not old_cid.startswith("P-"):
            print(f"[merge] WARN: unexpected card_id format {old_cid!r}, skip shift")
            continue
        try:
            n = int(old_cid.split("-")[1])
        except ValueError:
            print(f"[merge] WARN: non-numeric card_id {old_cid!r}, skip")
            continue
        new_cid = format_cid(n + SHIFT_BASE)
        shift_map[old_cid] = new_cid

    # We must avoid UNIQUE collision during the shift itself. Do a two-step:
    #   Phase A: rename all ours P-001..P-074 -> TMP-001..TMP-074
    #   Phase B: rename TMP-NNN -> P-(NNN+32)
    print(f"[merge] shift plan: P-001 -> {format_cid(1+SHIFT_BASE)}, ..., P-{len(ours):03d} -> {format_cid(len(ours)+SHIFT_BASE)}")

    if args.apply:
        # Phase A
        for row in ours:
            old_cid = row["card_id"]
            tmp_cid = "TMP-" + old_cid.split("-")[1]
            c.execute("UPDATE pattern_cards SET card_id = ? WHERE id = ?", (tmp_cid, row["id"]))
        # Phase B
        for row in ours:
            old_cid = row["card_id"]  # still stale in python dict; row was captured before
            new_cid = shift_map[old_cid]
            tmp_cid = "TMP-" + old_cid.split("-")[1]
            c.execute("UPDATE pattern_cards SET card_id = ? WHERE id = ?", (new_cid, row["id"]))
        conn.commit()
        print(f"[merge] shifted {len(ours)} cards")

    # ── Step 2: insert team cards ─────────────────────────────────────────
    imported = 0
    superseded = 0
    skipped = 0

    # Existing formulas after shift — they're the same set as before, just renumbered
    existing_formula_to_pk: dict[tuple, int] = {}
    for r in c.execute("SELECT id, source_type, sink_type, missing_check FROM pattern_cards WHERE status='active'"):
        existing_formula_to_pk[(r[1], r[2], r[3])] = r[0]

    for tc in team_lines:
        cid = tc["card_id"]
        formula = (tc["source_type"], tc["sink_type"], tc["missing_check"])

        # Check collision with our shifted cards
        same_formula_pk = existing_formula_to_pk.get(formula)

        status = "active"
        superseded_by = None
        if same_formula_pk is not None:
            status = "superseded_by_ours"
            superseded_by = same_formula_pk
            superseded += 1

        if not args.apply:
            print(f"[DRY] import {cid} formula={formula} status={status} supersedes_pk={superseded_by}")
            imported += 1
            continue

        try:
            c.execute("""
                INSERT INTO pattern_cards (card_id, source_type, source_detail, sink_type, sink_detail,
                    missing_check, summary, vulnerable_snippet, fixed_snippet, snippet_origin,
                    snippet_language, long_description, attack_scenario, fix_detail, severity_hint,
                    cve_similar, advisory, status, version, superseded_by, shared_with_team,
                    shared_batch_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cid,
                tc.get("source_type"), tc.get("source_detail"),
                tc.get("sink_type"), tc.get("sink_detail"),
                tc.get("missing_check"),
                tc.get("summary") or "",
                tc.get("vulnerable_snippet") or "",
                tc.get("fixed_snippet") or "",
                tc.get("snippet_origin"),
                tc.get("snippet_language") or "decompiled_c",
                tc.get("long_description"),
                tc.get("attack_scenario"),
                tc.get("fix_detail"),
                tc.get("severity_hint"),
                tc.get("cve_similar"),
                tc.get("advisory"),
                status,
                tc.get("version") or 1,
                superseded_by,
                1,                              # shared_with_team = True (from team)
                tc.get("shared_batch_id"),
                tc.get("created_at") or None,
                tc.get("updated_at") or None,
            ))
        except sqlite3.IntegrityError as e:
            print(f"[merge] SKIP {cid} due to integrity: {e}")
            skipped += 1
            continue

        new_pk = c.lastrowid

        # tokens
        for tok in tc.get("tokens") or []:
            c.execute("INSERT INTO pattern_card_tokens (card_id, token, kind, weight) VALUES (?, ?, ?, ?)",
                      (new_pk, tok.get("token"), tok.get("kind"), tok.get("weight") or 1.0))

        # negative_tokens
        for nt in tc.get("negative_tokens") or []:
            note = nt.get("note")
            c.execute("INSERT INTO pattern_card_negative_tokens (card_id, token, vendor_scope, note) VALUES (?, ?, ?, ?)",
                      (new_pk, nt.get("token"), nt.get("vendor_scope"), note))

        # grep_patterns (best-effort; schema may vary)
        for gp in tc.get("grep_patterns") or []:
            pattern = gp.get("pattern") if isinstance(gp, dict) else gp
            note = gp.get("note") if isinstance(gp, dict) else None
            try:
                c.execute("INSERT INTO pattern_card_grep_patterns (card_id, pattern, note) VALUES (?, ?, ?)",
                          (new_pk, pattern, note))
            except sqlite3.OperationalError:
                try:
                    c.execute("INSERT INTO pattern_card_grep_patterns (card_id, pattern) VALUES (?, ?)",
                              (new_pk, pattern))
                except sqlite3.OperationalError:
                    pass

        imported += 1

    if args.apply:
        conn.commit()

    print(f"\n[merge] done. imported={imported}, superseded_by_ours={superseded}, skipped={skipped}")
    print(f"[merge] total active formulas in DB now = {len(existing_formula_to_pk)} (team's same-formula entries got status='superseded_by_ours')")

    if args.apply:
        total = c.execute("SELECT COUNT(*) FROM pattern_cards").fetchone()[0]
        active = c.execute("SELECT COUNT(*) FROM pattern_cards WHERE status='active'").fetchone()[0]
        print(f"[merge] DB now: total={total}, active={active}")

    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
