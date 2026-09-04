#!/usr/bin/env bash
#
# Week 4 — analyzer 를 Docker 컨테이너로, agent 는 호스트에서 PQC 채널로 접속.
#
#   [호스트] agent --forward ──PQC mTLS──▶ 127.0.0.1:9443 ──포트 매핑──▶ [컨테이너] analyzer
#
#   1) 이미지 빌드 (멀티스테이지; 첫 빌드는 liboqs 포함 수 분, 이후 캐시)
#   2) 신원 프로비저닝: build/docker-keys/ 에 ML-DSA 키쌍 2개 → 컨테이너 /keys 로 읽기전용 마운트
#   3) 컨테이너 기동 (비루트, 127.0.0.1 에만 포트 공개, 키는 이미지에 굽지 않음)
#   4) 호스트 agent 가 시나리오 2개를 재생(연결 2회 — 코릴레이션 상태는 데몬 수명 동안 유지)
#      → 컨테이너 로그에서 alert 확인
#
# 환경변수
#   USE_REAL_LLM=1 (+ANTHROPIC_API_KEY)  실 Claude API — 키는 env 로만 컨테이너에 전달. 기본 mock.
#   MODE=ebpf                            재생 대신 실 eBPF agent 를 EBPF_SECONDS(기본 15)초 붙여 둠 (setcap 필요)
#   PORT=9443                            호스트 쪽 공개 포트
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO/build"
# .env 가 있으면 로드 (ANTHROPIC_API_KEY 등). 실 LLM 은 USE_REAL_LLM=1 일 때만 쓰므로 자동 과금은 없다.
if [[ -z "${ANTHROPIC_API_KEY:-}" && -f "$REPO/.env" ]]; then set -a; . "$REPO/.env"; set +a; fi
IMAGE="${IMAGE:-pqc-edr-analyzer}"
NAME="pqc-edr-analyzer-demo"
PORT="${PORT:-9443}"
KEYS="$BUILD/docker-keys"

pause() { read -rt "$1" <> <(:) || :; }
for bin in tools/pqsec_keygen agent/agent; do
  [[ -x "$BUILD/$bin" ]] || { echo "빌드 필요: $BUILD/$bin 없음. cmake --build build 먼저." >&2; exit 1; }
done
command -v docker >/dev/null || { echo "docker 가 필요합니다." >&2; exit 1; }

echo "== [1] 이미지 빌드: $IMAGE =="
docker build -q -f "$REPO/docker/Dockerfile.analyzer" -t "$IMAGE" "$REPO"

echo "== [2] 신원 프로비저닝 (ML-DSA) → $KEYS =="
rm -rf "$KEYS"; mkdir -p "$KEYS"
( cd "$KEYS" && "$BUILD/tools/pqsec_keygen" agent && "$BUILD/tools/pqsec_keygen" analyzer )

echo "== [3] 컨테이너 기동 ($NAME, 127.0.0.1:$PORT → 9443) =="
docker rm -f "$NAME" >/dev/null 2>&1 || true
LLM_ARGS=(--mock-llm); ENV_ARGS=()
if [[ "${USE_REAL_LLM:-0}" == "1" && -n "${ANTHROPIC_API_KEY:-}" ]]; then
  LLM_ARGS=(); ENV_ARGS=(-e ANTHROPIC_API_KEY); echo "   LLM: 실 Claude API"
else
  echo "   LLM: mock (오프라인)"
fi
# --user: 키 파일이 0600 이라 컨테이너 프로세스를 호스트 uid 로 실행 (이미지 기본은 비루트 10001)
docker run -d --name "$NAME" --user "$(id -u):$(id -g)" \
  -p "127.0.0.1:$PORT:9443" -v "$KEYS:/keys:ro" "${ENV_ARGS[@]}" \
  "$IMAGE" "${LLM_ARGS[@]}" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

i=0; until docker logs "$NAME" 2>&1 | grep -q "리슨"; do
  (( i++ < 100 )) || { echo "컨테이너 기동 실패:" >&2; docker logs "$NAME" >&2; exit 1; }
  pause 0.1
done
docker ps --filter "name=$NAME" --format '   컨테이너 {{.Names}} {{.Status}} ports={{.Ports}}'

echo "== [4] 호스트 agent → 컨테이너 analyzer (PQC 채널) =="
cd "$KEYS"
if [[ "${MODE:-replay}" == "ebpf" ]]; then
  "$BUILD/agent/agent" --forward --id agent --peer analyzer.pub --host 127.0.0.1 --port "$PORT" &
  AGPID=$!
  echo "   실 eBPF 수집 ${EBPF_SECONDS:-15}초 — 다른 셸에서 명령을 실행해 보세요"
  pause "${EBPF_SECONDS:-15}"; kill -TERM "$AGPID" 2>/dev/null || true; wait "$AGPID" 2>/dev/null || true
else
  for f in exec-chain c2-beacon; do
    "$BUILD/agent/agent" --forward --replay "$REPO/scenarios/$f.events" \
      --id agent --peer analyzer.pub --host 127.0.0.1 --port "$PORT" 2>&1 | grep -v "이벤트 암호화 전송"
  done
fi
pause 0.5

echo
echo "== 컨테이너 로그 (analyzer) =="
docker logs "$NAME" 2>&1
echo
echo "[demo-docker] 완료 — 호스트 agent ↔ 컨테이너 analyzer 가 PQC 채널로 통신, 분류·alert 는 컨테이너 안에서."
