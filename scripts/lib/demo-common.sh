# scripts/lib/demo-common.sh — 위협 시나리오 데모 공통 루틴 (scenario-*.sh 가 source)
#
# 흐름: 빌드 확인 → 신원 프로비저닝 → analyzer 데몬 → agent(실 eBPF | replay) → 리포트
#
# 환경변수
#   MODE=auto|ebpf|replay   auto(기본): agent 바이너리에 cap_bpf 가 있으면 ebpf, 없으면 replay
#   USE_REAL_LLM=1          (+ANTHROPIC_API_KEY) 실 Claude API. 기본은 mock(오프라인).
#   PORT=19443              analyzer 포트
#   KEEP_LOGS=1             작업 디렉토리(로그·데모용 키)를 지우지 않고 경로 출력
#
# eBPF 모드에서는 이 스크립트가 실행하는 외부 명령도 전부 이벤트가 된다. 그래서 대기·매칭은
# bash 내장(read -t, [[ ]], $(<file))만 써서 수집 중에 노이즈를 만들지 않는다.

# .env 가 있으면 로드 (ANTHROPIC_API_KEY 등). 실 LLM 은 USE_REAL_LLM=1 일 때만 쓰므로 자동 과금은 없다.
if [[ -z "${ANTHROPIC_API_KEY:-}" && -f "$REPO/.env" ]]; then set -a; . "$REPO/.env"; set +a; fi

# sleep(1) 대체 — 외부 프로세스를 띄우지 않는다
pause() { read -rt "$1" <> <(:) || :; }

# 파일에 패턴이 나타날 때까지 대기. 프로세스가 죽거나 타임아웃이면 실패.
wait_for() { # $1=pattern $2=file $3=pid $4=timeout_sec
  local i=0 max=$(( ${4:-10} * 20 ))
  while (( i < max )); do
    [[ -f "$2" && "$(<"$2")" == *"$1"* ]] && return 0
    kill -0 "$3" 2>/dev/null || return 1
    pause 0.05; i=$((i+1))
  done
  return 1
}

demo_init() { # $1 = 시나리오 이름
  SCENARIO="$1"
  BUILD="$REPO/build"
  PORT="${PORT:-19443}"
  for bin in tools/pqsec_keygen analyzer/analyzer agent/agent; do
    [[ -x "$BUILD/$bin" ]] || { echo "빌드 필요: $BUILD/$bin 없음. cmake --build build 먼저." >&2; exit 1; }
  done
  case "${MODE:-auto}" in
    ebpf|replay) AGENT_MODE="$MODE" ;;
    auto) if getcap "$BUILD/agent/agent" 2>/dev/null | grep -q cap_bpf; then AGENT_MODE=ebpf
          else AGENT_MODE=replay; fi ;;
    *) echo "MODE 는 auto|ebpf|replay 중 하나" >&2; exit 1 ;;
  esac

  WORK="$(mktemp -d -t "pqsec-$SCENARIO.XXXXXX")"
  if [[ "${KEEP_LOGS:-0}" == "1" ]]; then
    trap 'echo "[demo] 로그 보존: $WORK"' EXIT
  else
    trap 'cd "$REPO" && rm -rf "$WORK"' EXIT
  fi
  cd "$WORK"

  echo "== [$SCENARIO] agent 모드: $AGENT_MODE =="
  echo "== [1] 신원 프로비저닝 (ML-DSA) =="
  "$BUILD/tools/pqsec_keygen" agent
  "$BUILD/tools/pqsec_keygen" analyzer
}

demo_start_analyzer() {
  local mock="--mock-llm" llm="mock (오프라인)"
  if [[ "${USE_REAL_LLM:-0}" == "1" && -n "${ANTHROPIC_API_KEY:-}" ]]; then
    mock=""; llm="실 Claude API (Haiku→Sonnet)"
  fi
  echo "== [2] analyzer 데몬 기동 (port $PORT, LLM: $llm) =="
  "$BUILD/analyzer/analyzer" --id analyzer --peer agent.pub --port "$PORT" $mock --once \
    > analyzer.jsonl 2> analyzer.log &
  APID=$!
  wait_for "리슨" analyzer.log "$APID" 10 \
    || { echo "analyzer 기동 실패:" >&2; cat analyzer.log >&2; exit 1; }
}

demo_start_agent_ebpf() {
  echo "== [3] agent 기동: 실 eBPF 수집 → PQC 채널 전송 =="
  "$BUILD/agent/agent" --forward --id agent --peer analyzer.pub --port "$PORT" 2> agent.log &
  AGPID=$!
  wait_for "collector 가동" agent.log "$AGPID" 10 \
    || { echo "agent 기동 실패:" >&2; cat agent.log >&2; exit 1; }
}

demo_stop_agent() {
  pause 1 # ring buffer 폴링(100ms)이 남은 이벤트를 비울 시간
  kill -TERM "$AGPID" 2>/dev/null || true
  wait "$AGPID" 2>/dev/null || true
}

demo_run_replay() { # $1 = events 파일
  echo "== [3] agent 재생: $(basename "$1") → PQC 채널 전송 =="
  "$BUILD/agent/agent" --forward --replay "$1" --id agent --peer analyzer.pub --port "$PORT" \
    2> agent.log || true
}

demo_finish() {
  wait "$APID" 2>/dev/null || true
  echo
  echo "== agent 로그 =="; cat agent.log
  echo "== analyzer 처리 로그 (stderr) =="
  local lines; lines=$(wc -l < analyzer.log)
  if (( lines > 80 )); then
    echo "(총 $lines 줄 — eBPF 모드는 시스템 전체 이벤트를 받으므로 ALERT/시스템 메시지만 표시. 전체는 KEEP_LOGS=1)"
    grep -E "ALERT|^\[analyzer\]" analyzer.log
    echo "  ... drop/normal $(grep -c -E '\[drop\]|normal\]' analyzer.log) 건 생략"
  else
    cat analyzer.log
  fi
  echo "== 구조화 alert (stdout, JSON Lines) =="; cat analyzer.jsonl
  echo
  echo "[$SCENARIO] 완료 — alert $(wc -l < analyzer.jsonl) 건." \
       "와이어에는 암호문만 흘렀고, analyzer 가 복호 후 룰·코릴레이션·LLM 으로 분류."
}
