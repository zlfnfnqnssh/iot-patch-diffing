-- v3에서는 Drafter의 Auto-merge가 1차 dedupe 역할.
-- 이 파일은 사후 점검 + 잔여 중복 병합용 쿼리 모음.

-- === 1. 중복 공식 카드 감지 (Auto-merge 누락분) ===
-- 정상 상태면 0건이어야 함 (UNIQUE INDEX idx_pc_formula_active로 차단).
-- 만약 status 전이나 race condition으로 중복이 생겼다면 여기서 탐지.
SELECT
  source_type, sink_type, missing_check,
  COUNT(*) AS n,
  GROUP_CONCAT(card_id) AS duplicate_cards
FROM pattern_cards
WHERE status = 'active'
GROUP BY source_type, sink_type, missing_check
HAVING COUNT(*) > 1;

-- === 2. 공식 유사 카드 (source/sink 같고 missing_check만 다름) ===
-- 사람 검토로 병합 여부 결정.
SELECT
  pc1.card_id AS card_a, pc1.missing_check AS miss_a,
  pc2.card_id AS card_b, pc2.missing_check AS miss_b,
  pc1.source_type, pc1.sink_type,
  pc1.summary AS summary_a, pc2.summary AS summary_b
FROM pattern_cards pc1
JOIN pattern_cards pc2
  ON pc1.source_type = pc2.source_type
  AND pc1.sink_type  = pc2.sink_type
  AND pc1.id < pc2.id
  AND pc1.status = 'active' AND pc2.status = 'active';

-- === 3. 카드 멤버 분포 (Auto-merge 효과 확인) ===
-- 많을수록 같은 공식이 여러 함수에서 반복 발견 (정상).
SELECT
  pc.card_id,
  pc.source_type || '→' || pc.missing_check || '→' || pc.sink_type AS formula,
  pc.severity_hint,
  COUNT(pcm.id) AS member_count,
  pc.updated_at
FROM pattern_cards pc
LEFT JOIN pattern_card_members pcm ON pc.id = pcm.card_id
WHERE pc.status = 'active'
GROUP BY pc.id
ORDER BY member_count DESC;

-- === 4. 멤버가 0인 카드 (생성됐지만 연결 security_patch 없음 — 비정상) ===
SELECT pc.id, pc.card_id, pc.created_at
FROM pattern_cards pc
LEFT JOIN pattern_card_members pcm ON pc.id = pcm.card_id
WHERE pc.status = 'active'
  AND pcm.id IS NULL;

-- === 5. 같은 security_patch가 여러 카드에 연결됐는지 (1:N 허용) ===
-- 정상: 한 함수가 여러 취약점을 고친 경우.
-- 비정상: Drafter가 공식 분류 실수로 한 패치를 두 카드에 매핑.
SELECT
  sp.id AS patch_id,
  COUNT(DISTINCT pcm.card_id) AS card_count,
  GROUP_CONCAT(pc.card_id) AS cards
FROM security_patches sp
JOIN pattern_card_members pcm ON sp.id = pcm.security_patch_id
JOIN pattern_cards pc ON pcm.card_id = pc.id
GROUP BY sp.id
HAVING card_count > 1;

-- === 6. 카드 retire 후보 ===
-- precision < 0.3 AND 표본 충분 (TP+FP ≥ 10).
SELECT
  pc.card_id,
  pc.summary,
  pcs.matches_total,
  pcs.true_positives  AS tp,
  pcs.false_positives AS fp,
  ROUND(1.0 * pcs.true_positives / NULLIF(pcs.true_positives + pcs.false_positives, 0), 2) AS precision_val
FROM pattern_cards pc
JOIN pattern_card_stats pcs ON pc.id = pcs.card_id
WHERE pc.status = 'active'
  AND (pcs.true_positives + pcs.false_positives) >= 10
  AND 1.0 * pcs.true_positives / (pcs.true_positives + pcs.false_positives) < 0.30
ORDER BY precision_val ASC;
