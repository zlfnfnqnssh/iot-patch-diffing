-- Batch-versioned card + delta hunt 추적용 마이그레이션 (2026-04-22)
--
-- 설계:
--   * 각 주간 드래프트 배치를 'v1', 'v2', 'v3' 같은 label 로 태그.
--   * 팀원 원본 카드는 'team-v1' 등 별도 네임스페이스.
--   * 카드 생성 시점에 `pattern_cards.created_in_batch` 채움.
--   * 해당 카드가 만든 hunt_findings / zero_day_verdicts 도 `source_batch` 로 역추적 가능.
--   * "이번 주 netnew 카드만" 뽑아 최신 펌웨어에 hunt 하려면
--     `WHERE created_in_batch = 'v2' AND status = 'active'` 필터만 쓰면 됨.

BEGIN;

-- 1) pattern_cards 에 batch 태그
ALTER TABLE pattern_cards ADD COLUMN created_in_batch TEXT;

-- 2) hunt_findings 출처 카드의 batch
ALTER TABLE hunt_findings ADD COLUMN source_batch TEXT;

-- 3) zero_day_verdicts 출처 batch (zero-day Agent 가 어느 카드셋을 context 로 썼는지)
ALTER TABLE zero_day_verdicts ADD COLUMN source_batch TEXT;

-- 4) 인덱스
CREATE INDEX IF NOT EXISTS idx_pc_batch ON pattern_cards(created_in_batch, status);
CREATE INDEX IF NOT EXISTS idx_hf_batch ON hunt_findings(source_batch);
CREATE INDEX IF NOT EXISTS idx_zdv_batch ON zero_day_verdicts(source_batch);

-- 5) 기존 106장 소급 태그
--   P-001..P-032 = 팀원 원본 (2026-04-19 병합)
--   P-033..P-106 = 우리가 Stage 2 Drafter 로 누적 생성 (여러 주차 합산)
--                  주차별 소급은 created_at 로 재분리 가능
UPDATE pattern_cards
   SET created_in_batch = 'team-initial'
 WHERE card_id BETWEEN 'P-001' AND 'P-032';

UPDATE pattern_cards
   SET created_in_batch = 'legacy-pre-batch'
 WHERE card_id BETWEEN 'P-033' AND 'P-106';

COMMIT;
