-- Zero-Day blind-hunt schema
-- Applied idempotently against Patch-Learner-main/src/db/patch_learner.db

CREATE TABLE IF NOT EXISTS zero_day_runs (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  target_binary TEXT NOT NULL,
  target_vendor TEXT,
  target_model TEXT,
  target_version TEXT,
  source_json_path TEXT,
  total_functions INTEGER DEFAULT 0,
  prefiltered_functions INTEGER DEFAULT 0,
  processed_functions INTEGER DEFAULT 0,
  vuln_candidates INTEGER DEFAULT 0,
  status TEXT DEFAULT 'pending',
  started_at DATETIME,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS zero_day_functions (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES zero_day_runs(id) ON DELETE CASCADE,
  addr TEXT NOT NULL,
  name TEXT,
  size INTEGER,
  pseudocode TEXT,
  disasm TEXT,
  calls TEXT,        -- JSON array
  strings TEXT,      -- JSON array
  prefiltered INTEGER DEFAULT 0,   -- 1 = passed prefilter
  stage_status TEXT DEFAULT 'pending',  -- pending / drafting / done / skipped
  UNIQUE(run_id, addr)
);

CREATE INDEX IF NOT EXISTS idx_zdf_run ON zero_day_functions(run_id);
CREATE INDEX IF NOT EXISTS idx_zdf_status ON zero_day_functions(run_id, stage_status);
CREATE INDEX IF NOT EXISTS idx_zdf_prefilter ON zero_day_functions(run_id, prefiltered);

CREATE TABLE IF NOT EXISTS zero_day_verdicts (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES zero_day_runs(id) ON DELETE CASCADE,
  function_id INTEGER REFERENCES zero_day_functions(id),
  function_addr TEXT NOT NULL,
  function_name TEXT,
  is_vulnerable BOOLEAN NOT NULL,
  confidence REAL NOT NULL,
  vuln_type TEXT,
  severity_hint TEXT,
  source_type TEXT,
  sink_type TEXT,
  missing_check TEXT,
  matched_card_pk INTEGER REFERENCES pattern_cards(id),
  matched_score REAL,
  root_cause TEXT,
  attack_scenario TEXT,
  agent_id TEXT,
  raw_reasoning TEXT,
  needs_human_review BOOLEAN DEFAULT 0,
  reviewed BOOLEAN DEFAULT 0,
  human_verdict TEXT,      -- confirmed_vuln / false_positive / needs_more_info
  human_note TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_zdv_run ON zero_day_verdicts(run_id);
CREATE INDEX IF NOT EXISTS idx_zdv_vuln ON zero_day_verdicts(run_id, is_vulnerable, confidence);
CREATE INDEX IF NOT EXISTS idx_zdv_card ON zero_day_verdicts(matched_card_pk);
