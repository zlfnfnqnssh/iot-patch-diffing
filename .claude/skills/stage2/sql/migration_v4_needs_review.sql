-- Stage 2 v4 마이그레이션 (2026-04-18)
-- recall 우선 — 0.50~0.69 confidence 구간도 is_security_patch=true로 받되
-- needs_human_review=1 플래그로 사람 검토 큐에 넣음.

BEGIN TRANSACTION;

ALTER TABLE security_patches ADD COLUMN needs_human_review BOOLEAN DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_sp_needs_review ON security_patches(needs_human_review);

COMMIT;
