#!/usr/bin/env bash
#
# Week 3 엔드투엔드 데모: agent → PQC 채널 → analyzer → LLM 분류 → alert
#
#   - 신원 프로비저닝(keygen) → analyzer 데몬 기동 → agent 가 이벤트 암호화 전송
#   - 기본은 mock LLM(오프라인). 실 Claude API 로 하려면:
#       USE_REAL_LLM=1 ANTHROPIC_API_KEY=sk-... scripts/demo-week3.sh
#   - agent 는 --synthetic(권한 불필요). 실 eBPF 수집으로 하려면 README 참조.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO/build"
PORT="${PORT:-19443}"

for bin in tools/pqsec_keygen analyzer/analyzer agent/agent; do
  [[ -x "$BUILD/$bin" ]] || { echo "빌드 필요: $BUILD/$bin 없음. cmake --build build 먼저."; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "== [1] 신원 프로비저닝 (ML-DSA) =="
"$BUILD/tools/pqsec_keygen" agent
"$BUILD/tools/pqsec_keygen" analyzer

# LLM 모드 선택
MOCK_FLAG="--mock-llm"
if [[ "${USE_REAL_LLM:-0}" == "1" && -n "${ANTHROPIC_API_KEY:-}" ]]; then
  MOCK_FLAG=""
  echo "== LLM: 실 Claude API =="
else
  echo "== LLM: mock (오프라인) =="
fi

echo "== [2] analyzer 데몬 기동 (port $PORT) =="
"$BUILD/analyzer/analyzer" --id analyzer --peer agent.pub --port "$PORT" $MOCK_FLAG --once \
  > analyzer.jsonl 2> analyzer.log &
APID=$!

# analyzer 가 listen 할 때까지 대기 (foreground sleep 미사용)
i=0; until grep -q "리슨" analyzer.log 2>/dev/null || ! kill -0 "$APID" 2>/dev/null || [ $i -ge 200000 ]; do i=$((i+1)); done

echo "== [3] agent --forward --synthetic (이벤트 암호화 전송) =="
"$BUILD/agent/agent" --forward --synthetic --id agent --peer analyzer.pub --port "$PORT" 2> agent.log || true

wait "$APID" 2>/dev/null || true

echo
echo "== agent 로그 =="; cat agent.log
echo "== analyzer 처리 로그(stderr) =="; cat analyzer.log
echo "== analyzer 구조화 alert (stdout, JSON Lines) =="; cat analyzer.jsonl
echo
echo "[demo] 완료 — 소켓에는 암호문만, analyzer 는 복호 후 분류·alert."
