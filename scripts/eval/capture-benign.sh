#!/usr/bin/env bash
#
# 정상 코퍼스 캡처 — 실 eBPF 로 개발 활동을 기록해 eval/corpus/benign/ 에 저장(익명화).
#
#   agent --record 로 캡처하면서, 대표적인 개발 명령(빌드·git·ctest·검색·docker 등)을 버스트로 실행.
#   캡처 후 사용자 경로/이름을 익명화(/home/$USER → /home/user)해서 커밋 가능하게 만든다.
#
#   필요: agent 에 cap_bpf (sudo setcap). 캡처 중에는 이 머신에서 공격 행위를 하지 않는다(전부 benign 라벨).
#   옵션: SECONDS_CAP(기본 90) 캡처 시간, OUT(기본 eval/corpus/benign/dev-session.events)
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
B="$REPO/build"
OUT="${OUT:-$REPO/eval/corpus/benign/dev-session.events}"
DUR="${SECONDS_CAP:-90}"
getcap "$B/agent/agent" 2>/dev/null | grep -q cap_bpf \
  || { echo "agent 에 cap_bpf 필요: sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep $B/agent/agent" >&2; exit 1; }
pause() { read -rt "$1" <> <(:) || :; }

RAW="$(mktemp)"
echo "== [1] 캡처 시작 (${DUR}s, 실 eBPF) → 개발 활동 버스트 =="
"$B/agent/agent" --record "$RAW" 2> "$RAW.log" & AGP=$!
i=0; until [[ -f "$RAW.log" && "$(<"$RAW.log")" == *"가동"* ]]; do (( i++ < 200 )) || { echo "agent 기동 실패"; cat "$RAW.log"; exit 1; }; pause 0.05; done

# 대표적 개발 활동을 반복 (SECONDS 는 bash 내장 경과초)
SECONDS=0
while (( SECONDS < DUR )); do
  ( cd "$REPO" && git status >/dev/null 2>&1; git log --oneline -5 >/dev/null 2>&1 )
  ls -la "$REPO" >/dev/null 2>&1; ls "$REPO/analyzer/src" >/dev/null 2>&1
  find "$REPO/crypto" -name '*.cpp' >/dev/null 2>&1
  grep -r "classify_event" "$REPO/analyzer" >/dev/null 2>&1
  cat "$REPO/README.md" >/dev/null 2>&1; head -20 "$REPO/CMakeLists.txt" >/dev/null 2>&1
  wc -l "$REPO"/crypto/src/*.cpp >/dev/null 2>&1
  cmake --build "$B" --target analyzer_selftest >/dev/null 2>&1 || true
  "$B/analyzer/analyzer_selftest" >/dev/null 2>&1 || true
  command -v docker >/dev/null && docker ps >/dev/null 2>&1 || true
  ss -ltn >/dev/null 2>&1 || true; ps aux >/dev/null 2>&1 || true
  pause 0.5
done
kill -TERM "$AGP" 2>/dev/null || true; wait "$AGP" 2>/dev/null || true

RAWLINES=$(grep -c '^execve\|^connect' "$RAW" || true)
echo "== [2] 익명화 → $OUT ($RAWLINES 이벤트) =="
# 사용자 경로/이름 치환 (커밋 가능하게). 홈 경로, 유저명, 스크래치패드 경로.
mkdir -p "$(dirname "$OUT")"
{
  echo "# 정상 코퍼스 — 이 개발 머신에서 실 eBPF 로 캡처한 개발 세션 (전부 benign)."
  echo "# 캡처: scripts/eval/capture-benign.sh (${DUR}s). 경로/유저명 익명화됨. expect 라벨 없음(전부 정상)."
  sed -e "s#$HOME#/home/user#g" -e "s#/home/$USER#/home/user#g" -e "s#\\b$USER\\b#user#g" \
      -e "s#/tmp/claude-[0-9]*/[^ ]*#/tmp/scratch#g" \
      "$RAW" | grep '^execve\|^connect'
} > "$OUT"
rm -f "$RAW" "$RAW.log"
echo "== [3] 완료: $(grep -c '^execve\|^connect' "$OUT") 이벤트, $(du -h "$OUT" | cut -f1) =="
echo "익명화 확인 (남은 '$USER' 있으면 아래에 출력):"; grep -n "$USER" "$OUT" | head -3 || echo "  (없음)"
