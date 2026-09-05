#!/usr/bin/env bash
#
# README 용 데모 GIF 녹화 — asciinema 로 터미널 세션을 녹화(docs/demo.cast)하고 agg 로 GIF(docs/demo.gif) 변환.
#
#   내용: 시나리오 1(다운로드→실행 체인) → 시나리오 2(C2 비콘). agent 에 cap_bpf 가 있으면 실 eBPF, 없으면 재생.
#   필요: asciinema (apt), agg (없으면 build/agg 로 자동 다운로드 — asciinema 공식 릴리스 바이너리, sudo 불필요)
#   옵션: COLS/ROWS(기본 110x34), IDLE(유휴 압축 초, 기본 1.5), MODE(시나리오에 그대로 전달)
#
# 재현: scripts/record-demo.sh && git add docs/demo.gif
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLS="${COLS:-110}"; ROWS="${ROWS:-34}"; IDLE="${IDLE:-1.5}"
CAST="$REPO/docs/demo.cast"; GIF="$REPO/docs/demo.gif"

command -v asciinema >/dev/null || { echo "asciinema 필요: sudo apt install asciinema" >&2; exit 1; }
AGG="$(command -v agg || true)"
if [[ -z "$AGG" ]]; then
  AGG="$REPO/build/agg"
  if [[ ! -x "$AGG" ]]; then
    echo "[record] agg 다운로드 → $AGG"
    curl -fsSL -o "$AGG" https://github.com/asciinema/agg/releases/latest/download/agg-x86_64-unknown-linux-gnu
    chmod +x "$AGG"
  fi
fi
echo "[record] asciinema $(asciinema --version | awk '{print $2}'), $("$AGG" --version)"

# 한글 출력이 있으므로 한글 글리프 폰트를 폴백으로 붙인다 (없으면 □ 로 렌더됨)
FONTS="DejaVu Sans Mono,Liberation Mono"
for f in "Noto Sans CJK KR" "Noto Sans Mono CJK KR" "NanumGothicCoding" "NanumGothic" "D2Coding" "UnDotum"; do
  fc-list "$f" 2>/dev/null | grep -q . && FONTS="$FONTS,$f"
done

# 녹화 안에서 돌릴 대본: 가짜 프롬프트를 찍고 잠깐 멈춘 뒤 실행 (사람이 치는 것처럼)
INNER="$(mktemp)"
cat > "$INNER" <<'INNER_EOF'
pause() { read -rt "$1" <> <(:) || :; }
run() { printf '\033[1;32m$\033[0m %s\n' "$*"; pause 1.2; "$@"; pause 2; }
printf '\033[1m# pqc-edr — eBPF → PQC 하이브리드 mTLS 채널 → 룰·코릴레이션·LLM 분류\033[0m\n'
pause 1.5
run scripts/scenario-1-exec-chain.sh
run scripts/scenario-2-c2-beacon.sh
INNER_EOF

cd "$REPO"
echo "[record] 녹화 시작 (${COLS}x${ROWS}, idle limit ${IDLE}s)"
asciinema rec --overwrite -q -i "$IDLE" --cols "$COLS" --rows "$ROWS" -c "bash $INNER" "$CAST" </dev/null
rm -f "$INNER"
echo "[record] 변환 → $GIF (fonts: $FONTS)"
"$AGG" --font-family "$FONTS" --font-size 14 --theme monokai --speed 1.0 "$CAST" "$GIF"
ls -la "$CAST" "$GIF"
echo "[record] 완료. README 는 docs/demo.gif 를 참조한다."
