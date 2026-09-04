#!/usr/bin/env bash
#
# 시나리오 2 — 비정상 아웃바운드 커넥션 (C2 비콘)
#
#   python3 implant 흉내: 같은 공인 목적지(198.51.100.7:4444) 비표준 포트로 0.7초 간격 5회 접속 시도.
#
#   execve python3                        → LLM 의심(mock) → Sonnet 심층 → alert
#   connect 1~2회                          → rule Medium (공인 비표준 포트)
#   connect 3회째부터                       → rule+beacon High (같은 목적지 반복 = 비콘 주기성)
#
# 무해: 198.51.100.7 은 문서용 예약 대역(TEST-NET-2)이라 실제 호스트가 없고, 0.3초 타임아웃.
#
# 실행:  scripts/scenario-2-c2-beacon.sh            # agent 에 cap_bpf 있으면 실 eBPF, 아니면 재생
#        MODE=replay scripts/scenario-2-c2-beacon.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/demo-common.sh
source "$REPO/scripts/lib/demo-common.sh"

demo_init "scenario-2-c2-beacon"
demo_start_analyzer

if [[ "$AGENT_MODE" == "ebpf" ]]; then
  demo_start_agent_ebpf
  echo "== [4] 비콘 실행 (python3 implant 흉내 — 무해) =="
  if command -v python3 > /dev/null; then
    python3 - <<'PY'
import socket, time
DST = ("198.51.100.7", 4444)  # TEST-NET-2: 실제 호스트 없음
for i in range(5):
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect(DST)
    except OSError:
        pass
    s.close()
    print(f"[implant] beacon {i + 1}/5 -> {DST[0]}:{DST[1]}", flush=True)
    time.sleep(0.7)
PY
  else
    for i in 1 2 3 4 5; do  # python3 없으면 bash /dev/tcp 로 대체
      timeout 0.3 bash -c 'exec 3<>/dev/tcp/198.51.100.7/4444' 2>/dev/null || true
      echo "[implant] beacon $i/5"; pause 0.7
    done
  fi
  demo_stop_agent
else
  demo_run_replay "$REPO/scenarios/c2-beacon.events"
fi

demo_finish
