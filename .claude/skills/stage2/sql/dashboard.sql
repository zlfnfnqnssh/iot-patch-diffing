-- Stage 2 v3 진행 대시보드 (Reviewer 제거 후)

-- === 1. 전체 파이프라인 상태 ===
SELECT 'changed_functions' AS tbl, stage2_status AS state, COUNT(*) AS n
FROM changed_functions GROUP BY stage2_status
UNION ALL
SELECT 'security_patches', CASE WHEN is_security_patch THEN 'sec' ELSE 'nonsec' END, COUNT(*)
FROM security_patches GROUP BY is_security_patch
UNION ALL
SELECT 'pattern_cards', status, COUNT(*)
FROM pattern_cards GROUP BY status
UNION ALL
SELECT 'hunt_findings',
  CASE
    WHEN is_true_positive IS NULL THEN 'pending_review'
    WHEN is_true_positive = 1     THEN 'true_positive'
    ELSE 'false_positive'
  END,
  COUNT(*)
FROM hunt_findings GROUP BY 2;

-- === 2. Drafter 처리량 / 판정 분포 ===
SELECT
  analyst_id,
  COUNT(*) AS total,
  SUM(CASE WHEN is_security_patch THEN 1 ELSE 0 END) AS sec,
  SUM(CASE WHEN NOT is_security_patch THEN 1 ELSE 0 END) AS nonsec,
  ROUND(AVG(confidence), 2) AS avg_conf
FROM security_patches
WHERE analyst_id IS NOT NULL
GROUP BY analyst_id;

-- === 3. Drafter confidence 분포 (자기 검증 품질 게이지) ===
-- 0.50~0.69 구간이 사후 집계용 buffer. 30% 넘으면 프롬프트 튜닝 필요.
SELECT
  CASE
    WHEN confidence >= 0.90 THEN '0.90+'
    WHEN confidence >= 0.70 THEN '0.70-0.89'
    WHEN confidence >= 0.50 THEN '0.50-0.69 (buffer)'
    ELSE '<0.50'
  END AS band,
  COUNT(*) AS n,
  SUM(CASE WHEN is_security_patch THEN 1 ELSE 0 END) AS sec_count
FROM security_patches
GROUP BY 1
ORDER BY 1 DESC;

-- === 4. Auto-merge 효과 ===
-- 카드 1장당 평균 몇 개 멤버가 붙었는지 (같은 공식 반복 발견 정도).
SELECT
  COUNT(DISTINCT pc.id) AS total_cards,
  COUNT(pcm.id)         AS total_members,
  ROUND(1.0 * COUNT(pcm.id) / NULLIF(COUNT(DISTINCT pc.id), 0), 2) AS avg_members_per_card,
  MAX(member_counts.cnt) AS max_members
FROM pattern_cards pc
LEFT JOIN pattern_card_members pcm ON pc.id = pcm.card_id
LEFT JOIN (
  SELECT card_id, COUNT(*) AS cnt FROM pattern_card_members GROUP BY card_id
) member_counts ON pc.id = member_counts.card_id
WHERE pc.status = 'active';

-- === 5. 벤더별 카드 밀도 ===
-- 벤더 라벨은 카드 본체에 없으므로 security_patches → changed_functions → firmware 경유.
SELECT
  fv.vendor,
  COUNT(DISTINCT pc.id) AS cards,
  COUNT(DISTINCT sp.id) AS patches
FROM pattern_cards pc
JOIN pattern_card_members pcm ON pc.id = pcm.card_id
JOIN security_patches sp ON pcm.security_patch_id = sp.id
JOIN changed_functions cf ON sp.changed_function_id = cf.id
JOIN bindiff_results br ON cf.bindiff_result_id = br.id
JOIN changed_files chf ON br.changed_file_id = chf.id
JOIN diff_sessions ds ON chf.diff_session_id = ds.id
JOIN firmware_versions fv ON ds.old_version_id = fv.id
WHERE pc.status = 'active'
GROUP BY fv.vendor
ORDER BY cards DESC;

-- === 6. CRITICAL 대기 건 (즉시 공유 대상) ===
SELECT
  pc.card_id, pc.severity_hint, pc.cve_similar, pc.summary,
  pc.shared_with_team, pc.shared_batch_id
FROM pattern_cards pc
WHERE pc.status = 'active'
  AND pc.severity_hint = 'critical'
  AND pc.shared_with_team = 0
ORDER BY pc.created_at ASC;

-- === 7. 패턴 카드 배치 공유 현황 ===
SELECT
  shared_batch_id,
  COUNT(*) AS n_cards,
  MIN(created_at) AS batch_start,
  MAX(updated_at) AS latest_update
FROM pattern_cards
WHERE shared_with_team = 1
GROUP BY shared_batch_id
ORDER BY shared_batch_id DESC;

-- === 8. Hunter 결과 → 카드 품질 (precision) ===
SELECT
  pc.card_id,
  pc.severity_hint,
  pcs.matches_total AS matches,
  pcs.true_positives AS tp,
  pcs.false_positives AS fp,
  ROUND(1.0 * pcs.true_positives / NULLIF(pcs.true_positives + pcs.false_positives, 0), 2) AS precision_val,
  pcs.last_used_at
FROM pattern_cards pc
JOIN pattern_card_stats pcs ON pc.id = pcs.card_id
WHERE pc.status = 'active'
ORDER BY precision_val ASC NULLS LAST;
