-- Phase 0 사전 필터 — LLM 없이 changed_functions 27K → ~1.5K 감축
-- 키워드 필터는 Python 쪽에서 decompiled_new/old를 LIKE로 돌리는 게 빠름.
-- 여기선 OSS/similarity 기반 컷만 SQL로 처리.

-- 0-1. OSS 바이너리 제외 (UPSTREAM 오픈소스 리빌드)
UPDATE changed_functions
SET stage2_status = 'skipped_oss'
WHERE stage2_status = 'pending'
  AND (
    binary_name LIKE 'libcrypto.so%'
    OR binary_name LIKE 'libssl.so%'
    OR binary_name = 'busybox'
    OR binary_name LIKE 'libav%'
    OR binary_name LIKE 'libjq%'
    OR binary_name IN ('e2fsck', 'mke2fs', 'resize2fs', 'tune2fs', 'dumpe2fs')
    OR binary_name LIKE 'libc-%'
    OR binary_name LIKE 'libc.so%'
    OR binary_name LIKE 'ld-%'
    OR binary_name LIKE 'libstdc++%'
    OR binary_name LIKE 'libpthread%'
    OR binary_name LIKE 'libm-%'
    OR binary_name LIKE 'libgcc%'
    OR binary_name LIKE 'libz.so%'
    OR binary_name LIKE 'libxml%'
    OR binary_name LIKE 'libcurl%'
    OR binary_name LIKE 'libnl%'
    OR binary_name LIKE 'libudev%'
    OR binary_name LIKE 'libdbus%'
  );

-- 0-2. similarity > 0.98 제외 (컴파일러 아티팩트)
UPDATE changed_functions
SET stage2_status = 'prefiltered_out'
WHERE stage2_status = 'pending'
  AND similarity IS NOT NULL
  AND similarity > 0.98;

-- 0-3. similarity < 0.20 제외 (BinDiff 오매칭)
UPDATE changed_functions
SET stage2_status = 'prefiltered_out'
WHERE stage2_status = 'pending'
  AND similarity IS NOT NULL
  AND similarity < 0.20;

-- 0-4. decompiled 본문이 비어 있으면 제외 (추출 실패 / stub)
UPDATE changed_functions
SET stage2_status = 'prefiltered_out'
WHERE stage2_status = 'pending'
  AND (decompiled_old IS NULL OR LENGTH(decompiled_old) < 50)
  AND (decompiled_new IS NULL OR LENGTH(decompiled_new) < 50);

-- === 집계 ===
SELECT stage2_status, COUNT(*) AS n
FROM changed_functions
GROUP BY stage2_status
ORDER BY n DESC;

-- === 다음 단계 (Python에서 돌림) ===
-- 남은 'pending' 중 decompiled_old/new에 위험 키워드 매칭되는 것만 'prefiltered_in'로 표시.
-- 키워드:
--   system, popen, sprintf, strcpy, strcat, gets, memcpy, exec,
--   printf(.*user, chmod, chown, snprintf(크기 변경 체크용), scanf, vsprintf
-- 매칭 안 되는 나머지는 'prefiltered_out'.
