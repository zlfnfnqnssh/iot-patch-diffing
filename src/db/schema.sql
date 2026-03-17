-- Patch-Learner SQLite Schema v1.0
-- LLM 에이전트가 보안 패치를 식별하고, 0-day 헌팅에 활용할 데이터를 축적하는 DB

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

---------------------------------------------------------------------
-- 1. 펌웨어 버전 관리
---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS firmware_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor          TEXT NOT NULL,           -- 'synology', 'ubiquiti', 'hanwha'
    model           TEXT NOT NULL,           -- 'BC500', 'AI_Pro'
    version         TEXT NOT NULL,           -- '1.0.6-0294'
    filename        TEXT,                    -- 원본 펌웨어 파일명
    sha256          TEXT,                    -- 원본 펌웨어 해시
    extracted       BOOLEAN DEFAULT 0,       -- binwalk 추출 여부
    extracted_path  TEXT,                    -- 추출된 파일시스템 경로
    notes           TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vendor, model, version)
);

---------------------------------------------------------------------
-- 2. 디핑 세션 (v_old vs v_new)
---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS diff_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    old_version_id  INTEGER NOT NULL REFERENCES firmware_versions(id),
    new_version_id  INTEGER NOT NULL REFERENCES firmware_versions(id),
    advisory        TEXT,                    -- 'SA_23_15' 등 (알면)
    status          TEXT DEFAULT 'pending',  -- pending → hash_diffed → bindiffed → analyzed
    total_changed_binaries  INTEGER DEFAULT 0,
    total_changed_texts     INTEGER DEFAULT 0,
    notes           TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(old_version_id, new_version_id)
);

---------------------------------------------------------------------
-- 3. 해시 디핑 결과: 변경된 파일 목록
---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS changed_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    diff_session_id INTEGER NOT NULL REFERENCES diff_sessions(id),
    file_path       TEXT NOT NULL,           -- 파일시스템 내 상대 경로
    file_type       TEXT NOT NULL,           -- 'binary' or 'text'
    change_type     TEXT NOT NULL,           -- 'modified', 'added', 'deleted'
    old_hash        TEXT,
    new_hash        TEXT,
    old_size        INTEGER,
    new_size        INTEGER,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

---------------------------------------------------------------------
-- 4. BinDiff 결과: 바이너리 단위
---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bindiff_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    changed_file_id INTEGER NOT NULL REFERENCES changed_files(id),
    bindiff_path    TEXT,                    -- .BinDiff 파일 경로
    total_functions     INTEGER,
    matched_functions   INTEGER,
    changed_functions   INTEGER,             -- similarity < 1.0
    added_functions     INTEGER,
    removed_functions   INTEGER,
    overall_similarity  REAL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

---------------------------------------------------------------------
-- 5. 변경된 함수 개별 정보
---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS changed_functions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bindiff_result_id   INTEGER NOT NULL REFERENCES bindiff_results(id),
    binary_name     TEXT NOT NULL,           -- 바이너리 파일명
    function_name   TEXT,                    -- 함수 이름 (있으면)
    old_address     TEXT,                    -- hex
    new_address     TEXT,                    -- hex
    similarity      REAL,                    -- 0.0 ~ 1.0
    confidence      REAL,
    basic_blocks    INTEGER,
    instructions    INTEGER,
    decompiled_old  TEXT,                    -- IDA 디컴파일 결과 (old)
    decompiled_new  TEXT,                    -- IDA 디컴파일 결과 (new)
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

---------------------------------------------------------------------
-- 6. ★ 핵심: LLM이 식별한 보안 패치
--    Claude Code 에이전트가 changed_functions를 보고 판단한 결과
---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_patches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    changed_function_id INTEGER NOT NULL REFERENCES changed_functions(id),

    -- LLM 판단
    is_security_patch   BOOLEAN NOT NULL,
    confidence          REAL,                -- 0.0 ~ 1.0

    -- 취약점 정보
    vuln_type       TEXT,                    -- 'buffer_overflow', 'null_deref', 'cmd_injection', 'format_string', 'path_traversal', 'auth_bypass', 'oob_read', 'input_validation'
    cwe             TEXT,                    -- 'CWE-120'
    severity        TEXT,                    -- 'critical', 'high', 'medium', 'low'

    -- 버그 설명
    root_cause      TEXT,                    -- 무엇이 취약했는지
    fix_description TEXT,                    -- 어떻게 고쳤는지
    fix_category    TEXT,                    -- 'null_check_added', 'bounds_check_added', 'sanitization_added', 'dangerous_func_replaced', 'auth_check_added', 'type_check_added', 'format_specifier_fixed', 'error_handling_added'

    -- 공격 정보
    attack_vector   TEXT,                    -- 'network', 'adjacent', 'local'
    requires_auth   BOOLEAN,
    attack_surface  TEXT,                    -- 'http_cgi', 'onvif', 'rtsp', 'login', 'video', 'config'

    -- 테인트 정보 (0-day 헌팅에 활용)
    source_desc     TEXT,                    -- 오염 데이터 진입점 설명
    sink_desc       TEXT,                    -- 위험 함수/동작 설명
    missing_check   TEXT,                    -- 빠진 검증 설명

    -- 헌팅 전략
    huntable        BOOLEAN DEFAULT 1,       -- 변종 헌팅 가능 여부
    hunt_strategy   TEXT,                    -- LLM이 제안하는 헌팅 방법

    -- 알려진 CVE 매핑 (있으면)
    known_cve       TEXT,                    -- 'CVE-2024-39349' or NULL
    advisory        TEXT,                    -- 'SA_23_15' or NULL

    -- LLM 메타
    llm_model       TEXT,                    -- 분석에 사용된 모델
    llm_prompt_ver  TEXT,                    -- 프롬프트 버전
    analysis_raw    TEXT,                    -- LLM 전체 응답 (디버깅용)

    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

---------------------------------------------------------------------
-- 7. 0-day 헌팅 결과
---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hunt_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    security_patch_id   INTEGER REFERENCES security_patches(id),

    -- 발견 위치
    target_vendor   TEXT,
    target_model    TEXT,
    target_version  TEXT,                    -- 분석 대상 펌웨어 버전
    target_binary   TEXT,
    target_function TEXT,
    target_address  TEXT,

    -- 발견 내용
    description     TEXT,
    confidence      REAL,

    -- 검증
    status          TEXT DEFAULT 'candidate', -- candidate → verified → false_positive → exploitable
    verification_notes  TEXT,

    -- PoC
    poc_path        TEXT,

    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

---------------------------------------------------------------------
-- 인덱스
---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_sp_vuln_type ON security_patches(vuln_type);
CREATE INDEX IF NOT EXISTS idx_sp_huntable ON security_patches(huntable);
CREATE INDEX IF NOT EXISTS idx_sp_severity ON security_patches(severity);
CREATE INDEX IF NOT EXISTS idx_cf_binary ON changed_functions(binary_name);
CREATE INDEX IF NOT EXISTS idx_hf_status ON hunt_findings(status);
CREATE INDEX IF NOT EXISTS idx_ds_status ON diff_sessions(status);
