#!/usr/bin/env bash
#
# scripts/bench-ebpf-overhead.sh — eBPF collector 의 실행 오버헤드 측정 (면접 Q4 근거)
#
#   execve : /bin/true 를 N회 실행하는 루프 (fork+exec 비용 안에서 훅 비용을 본다)
#   connect: 127.0.0.1:1 로 N회 connect (닫힌 포트 → 즉시 RST, 커널 경로만)
#   fileopen: 파일 N회 open+read (security_file_open 은 시스템 전체 open 마다 실행되므로,
#             "흥미롭지 않은" open 의 커널 내 필터 비용 = 항상 켜진 훅의 상시 오버헤드)
#   agent 없이 vs agent(실 eBPF, stdout→/dev/null) 붙인 채로 각 R회 반복해 median 비교.
#
# 필요: agent 바이너리에 cap_bpf (sudo setcap). 대기는 bash 내장만 사용.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO/build"
N="${N:-3000}"
R="${R:-5}"

pause() { read -rt "$1" <> <(:) || :; }
getcap "$BUILD/agent/agent" 2>/dev/null | grep -q cap_bpf \
  || { echo "agent 에 cap_bpf 필요: sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep $BUILD/agent/agent" >&2; exit 1; }

# 한 번의 측정: ms 출력
run_exec() {
  local t0=$EPOCHREALTIME i
  for ((i = 0; i < N; i++)); do /bin/true; done
  local t1=$EPOCHREALTIME
  awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f\n", (b - a) * 1000 }'
}
run_connect() {
  python3 - "$N" <<'PY'
import socket, sys, time
n = int(sys.argv[1]); t0 = time.perf_counter()
for _ in range(n):
    s = socket.socket()
    try: s.connect(("127.0.0.1", 1))
    except OSError: pass
    s.close()
print(f"{(time.perf_counter() - t0) * 1000:.1f}")
PY
}
run_fileopen() {
  python3 - "$N" <<'PY'
import os, sys, time
n = int(sys.argv[1]); paths = ["/etc/hostname", "/etc/os-release", "/proc/self/stat"]
t0 = time.perf_counter()
for i in range(n):
    try:
        fd = os.open(paths[i % len(paths)], os.O_RDONLY); os.read(fd, 64); os.close(fd)
    except OSError: pass
print(f"{(time.perf_counter() - t0) * 1000:.1f}")
PY
}
median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }
measure() { # $1 = run_exec|run_connect → R회 median (ms)
  local i; for ((i = 0; i < R; i++)); do "$1"; done | median
}

echo "# eBPF collector 오버헤드 (N=$N 회, R=$R 회 median)"
echo
echo "## baseline (agent 없음)"
base_exec=$(measure run_exec);    echo "- execve  루프: ${base_exec} ms"
base_conn=$(measure run_connect); echo "- connect 루프: ${base_conn} ms"
base_fopen=$(measure run_fileopen); echo "- fileopen 루프: ${base_fopen} ms"

echo
echo "## agent 가동 (실 eBPF: ksyscall/execve + fentry/tcp_v4_connect, ring buffer → stdout /dev/null)"
: > "$BUILD/bench-agent.log" # 백그라운드 agent 가 열기 전에 읽는 레이스 방지
"$BUILD/agent/agent" > /dev/null 2> "$BUILD/bench-agent.log" &
AGPID=$!
i=0; until [[ "$(<"$BUILD/bench-agent.log")" == *"collector 가동"* ]]; do
  (( i++ < 100 )) || { echo "agent 기동 실패" >&2; cat "$BUILD/bench-agent.log" >&2; exit 1; }
  pause 0.05
done
with_exec=$(measure run_exec);    echo "- execve  루프: ${with_exec} ms"
with_conn=$(measure run_connect); echo "- connect 루프: ${with_conn} ms"
with_fopen=$(measure run_fileopen); echo "- fileopen 루프: ${with_fopen} ms"
kill -TERM "$AGPID" 2>/dev/null || true; wait "$AGPID" 2>/dev/null || true

echo
echo "| 경로 | 없음 (ms) | 있음 (ms) | 차이 | 이벤트당 추가 (µs) |"
echo "|---|---:|---:|---:|---:|"
awk -v n="$N" -v a="$base_exec" -v b="$with_exec" \
  'BEGIN { printf "| execve (fork+exec /bin/true) | %.1f | %.1f | %+.1f%% | %.1f |\n", a, b, (b/a-1)*100, (b-a)*1000/n }'
awk -v n="$N" -v a="$base_conn" -v b="$with_conn" \
  'BEGIN { printf "| connect (loopback RST) | %.1f | %.1f | %+.1f%% | %.1f |\n", a, b, (b/a-1)*100, (b-a)*1000/n }'
awk -v n="$N" -v a="$base_fopen" -v b="$with_fopen" \
  'BEGIN { printf "| fileopen (open+read, 커널필터로 버려짐) | %.1f | %.1f | %+.1f%% | %.1f |\n", a, b, (b/a-1)*100, (b-a)*1000/n }' 
echo
echo "(µs/이벤트 = 훅 실행 + ring buffer reserve/commit + 유저스페이스 소비. 노이즈 있음 — 방향성 지표.)"
