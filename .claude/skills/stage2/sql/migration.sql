-- Stage 2 v3 마이그레이션 (Reviewer 제거 + 공식 기반 패턴카드)
-- 2026-04-17 확정
-- 실행 전 DB 백업:
--   cp Patch-Learner-main/src/db/patch_learner.db \
--      Patch-Learner-main/src/db/patch_learner.db.bak.pre-stage2-v3

BEGIN TRANSACTION;

-- =====================================================================
-- 1. changed_functions — Drafter 상태 (Reviewer 없음)
-- =====================================================================
ALTER TABLE changed_functions ADD COLUMN stage2_status TEXT DEFAULT 'pending';
-- 값: pending / skipped_oss / prefiltered_out / prefiltered_in /
--     drafting_a1 / drafting_a2 / drafted_sec / drafted_nonsec / error
CREATE INDEX IF NOT EXISTS idx_cf_stage2_status ON changed_functions(stage2_status);

-- =====================================================================
-- 2. security_patches — Drafter 판정 메타
-- =====================================================================
ALTER TABLE security_patches ADD COLUMN analyst_id TEXT;      -- 'A1' | 'A2'
-- 참고: review_status / reopen_count / reviewer_note / reopen_reason 컬럼은
-- v3에서 제거됨. Reviewer 단계가 없음.

-- 카드 연결 (Drafter가 바로 카드 만들 때 저장)
ALTER TABLE security_patches ADD COLUMN pattern_card_id INTEGER REFERENCES pattern_cards(id);
CREATE INDEX IF NOT EXISTS idx_sp_pattern_card ON security_patches(pattern_card_id);

-- =====================================================================
-- 3. pattern_cards (v2 스키마) — 기존 테이블 교체
-- =====================================================================
-- 기존 pattern_cards는 0건이므로 DROP + CREATE가 안전.
-- 사전 확인: SELECT COUNT(*) FROM pattern_cards; → 0 이어야 함.

DROP TABLE IF EXISTS pattern_cards;

CREATE TABLE pattern_cards (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id             TEXT NOT NULL UNIQUE,           -- 'P-001' 단순 번호

    -- === 구조적 taint 공식 (핵심, 전처리 매칭 키) ===
    source_type         TEXT NOT NULL,                  -- enum: http_header/http_body/rpc_arg/...
    source_detail       TEXT,                           -- 'Host', 'Cseq' 등 구체화
    sink_type           TEXT NOT NULL,                  -- enum: stack_buffer_copy/shell_exec/...
    sink_detail         TEXT,                           -- 'sprintf(fixed_stack_buf)'
    missing_check       TEXT NOT NULL,                  -- enum: length_bound/metachar_filter/...

    -- === Hunter LLM 직접 입력 (토큰 예산 관리) ===
    summary             TEXT NOT NULL,                  -- 200자 이내
    vulnerable_snippet  TEXT NOT NULL,                  -- OLD 핵심 5~15줄, 300자 이내
    fixed_snippet       TEXT NOT NULL,                  -- NEW 핵심 5~15줄, 300자 이내
    snippet_origin      TEXT,                           -- 'central_server/sub_F150'
    snippet_language    TEXT DEFAULT 'decompiled_c',    -- 'c' / 'decompiled_c' / 'cpp'

    -- === 인간 전용 상세 (LLM 입력에서 제외) ===
    long_description    TEXT,
    attack_scenario     TEXT,
    fix_detail          TEXT,

    -- === 참고 라벨 (본체 아님, 검색 편의용) ===
    severity_hint       TEXT,                           -- 'critical'/'high'/'medium'/'low'
    cve_similar         TEXT,                           -- 하드 규칙 §5 허용 리스트만
    advisory            TEXT,

    -- === 수명주기 (Drafter가 생성 시 바로 active, draft 단계 없음) ===
    status              TEXT DEFAULT 'active',          -- active / retired / superseded
    version             INTEGER DEFAULT 1,
    superseded_by       INTEGER REFERENCES pattern_cards(id),

    -- === 팀 공유 ===
    shared_with_team    BOOLEAN DEFAULT 0,
    shared_batch_id     INTEGER,

    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 핵심 인덱스: (source, sink, missing_check) 3원소로 Auto-merge 및 Hunter 전처리
CREATE UNIQUE INDEX idx_pc_formula_active
    ON pattern_cards(source_type, sink_type, missing_check)
    WHERE status = 'active';
-- ↑ active 상태에서 같은 공식은 1개만 존재 → Auto-merge 자동 보장
CREATE INDEX idx_pc_status      ON pattern_cards(status);
CREATE INDEX idx_pc_severity    ON pattern_cards(severity_hint);
CREATE INDEX idx_pc_shared      ON pattern_cards(shared_with_team, shared_batch_id);

-- =====================================================================
-- 4. pattern_card_tokens — grep/prefilter 인덱스
-- =====================================================================
CREATE TABLE pattern_card_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id     INTEGER NOT NULL REFERENCES pattern_cards(id) ON DELETE CASCADE,
    token       TEXT NOT NULL,
    kind        TEXT NOT NULL,                          -- api/literal/error_msg/const/struct_field/symbol
    weight      REAL DEFAULT 1.0,
    UNIQUE(card_id, token, kind)
);
CREATE INDEX idx_pct_token ON pattern_card_tokens(token);
CREATE INDEX idx_pct_card  ON pattern_card_tokens(card_id);

-- =====================================================================
-- 5. pattern_card_negative_tokens — safe wrapper 배제 (벤더 scope)
-- =====================================================================
CREATE TABLE pattern_card_negative_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id         INTEGER NOT NULL REFERENCES pattern_cards(id) ON DELETE CASCADE,
    token           TEXT NOT NULL,
    vendor_scope    TEXT,                               -- 'synology'/'ubiquiti'/NULL
    note            TEXT,
    UNIQUE(card_id, token, vendor_scope)
);
CREATE INDEX idx_pcn_token ON pattern_card_negative_tokens(token);
CREATE INDEX idx_pcn_card  ON pattern_card_negative_tokens(card_id);

-- =====================================================================
-- 6. pattern_card_grep_patterns — regex (선택)
-- =====================================================================
CREATE TABLE pattern_card_grep_patterns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id         INTEGER NOT NULL REFERENCES pattern_cards(id) ON DELETE CASCADE,
    pattern         TEXT NOT NULL,
    pattern_flavor  TEXT DEFAULT 'python_re'
);
CREATE INDEX idx_pcg_card ON pattern_card_grep_patterns(card_id);

-- =====================================================================
-- 7. pattern_card_members — 카드가 어느 security_patches에서 왔는지
--    (Auto-merge 핵심 — 같은 공식 카드에 멤버만 쌓임)
-- =====================================================================
CREATE TABLE pattern_card_members (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id             INTEGER NOT NULL REFERENCES pattern_cards(id) ON DELETE CASCADE,
    security_patch_id   INTEGER NOT NULL REFERENCES security_patches(id),
    is_representative   BOOLEAN DEFAULT 0,              -- 현재 스니펫의 원본 멤버면 1
    note                TEXT,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(card_id, security_patch_id)
);
CREATE INDEX idx_pcm_card  ON pattern_card_members(card_id);
CREATE INDEX idx_pcm_patch ON pattern_card_members(security_patch_id);

-- =====================================================================
-- 8. pattern_card_stats — precision 기반 카드 품질 추적
-- =====================================================================
CREATE TABLE pattern_card_stats (
    card_id         INTEGER PRIMARY KEY REFERENCES pattern_cards(id) ON DELETE CASCADE,
    matches_total   INTEGER DEFAULT 0,
    true_positives  INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    last_used_at    DATETIME
);

-- =====================================================================
-- 9. hunt_findings — Phase 2 Hunter 결과 (기존 테이블 확장)
-- =====================================================================
ALTER TABLE hunt_findings ADD COLUMN pattern_card_id    INTEGER;
ALTER TABLE hunt_findings ADD COLUMN target_function_id INTEGER;
ALTER TABLE hunt_findings ADD COLUMN match_confidence   REAL;
ALTER TABLE hunt_findings ADD COLUMN match_lines        TEXT;     -- JSON array
ALTER TABLE hunt_findings ADD COLUMN matched_formula    TEXT;
ALTER TABLE hunt_findings ADD COLUMN is_true_positive   BOOLEAN;  -- NULL=미검토
ALTER TABLE hunt_findings ADD COLUMN notes              TEXT;

CREATE INDEX IF NOT EXISTS idx_hf_pattern_card ON hunt_findings(pattern_card_id);
CREATE INDEX IF NOT EXISTS idx_hf_is_tp        ON hunt_findings(is_true_positive);

COMMIT;

-- =====================================================================
-- Auto-merge 운영 참고
-- =====================================================================
-- Drafter 출력 처리 시 오케스트레이터가 다음 순서로 실행:
-- (1) 기존 카드 검색:
--     SELECT id, version FROM pattern_cards
--     WHERE source_type = :st AND sink_type = :sk AND missing_check = :mc
--       AND status = 'active';
-- (2a) 기존 있음: 새 카드 생성 안 하고, 해당 card_id에 멤버 행만 추가:
--     INSERT INTO pattern_card_members (card_id, security_patch_id, note)
--     VALUES (:existing_card_id, :new_patch_id, 'auto-merged by Drafter');
--     -- 선택: 스니펫이 더 선명하다 판단되면 version++ + 스니펫 필드 UPDATE
-- (2b) 기존 없음: 새 카드 INSERT + tokens/negative_tokens/grep_patterns/members INSERT.
-- (3) security_patches.pattern_card_id 업데이트.
