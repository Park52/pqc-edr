#!/usr/bin/env bash
#
# 탐지 평가 실행 → docs/EVAL.md 갱신.
#   기본: mock. REAL=1 이면 실 Claude API 도 돌려 나란히 기록(.env 자동 로드, 비용 소액).
#
#   MAX_LLM_CALLS(기본 400) 실 API 상한. 정상 코퍼스가 크면 상한으로 비용을 막는다.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
B="$REPO/build"; EVAL="$B/analyzer/analyzer_eval"
BENIGN="$REPO/eval/corpus/benign"; ATTACK="$REPO/eval/corpus/attack"
DOC="$REPO/docs/EVAL.md"
CAP="${MAX_LLM_CALLS:-400}"
[[ -x "$EVAL" ]] || { echo "빌드 필요: $EVAL"; exit 1; }
[[ -z "${ANTHROPIC_API_KEY:-}" && -f "$REPO/.env" ]] && { set -a; . "$REPO/.env"; set +a; }

BEN_ARGS=(); [[ -d "$BENIGN" && -n "$(ls "$BENIGN"/*.events 2>/dev/null)" ]] && BEN_ARGS=(--benign "$BENIGN")

TMPM="$(mktemp)"; "$EVAL" "${BEN_ARGS[@]}" --attack "$ATTACK" --llm mock \
  --json "$B/eval-mock.json" > "$TMPM"
if [[ "${REAL:-0}" == "1" && -n "${ANTHROPIC_API_KEY:-}" ]]; then
  TMPR="$(mktemp)"; "$EVAL" "${BEN_ARGS[@]}" --attack "$ATTACK" --llm real --max-llm-calls "$CAP" \
    --json "$B/eval-real.json" > "$TMPR"
fi

{
  echo "# 탐지 평가 (EVAL)"
  echo
  echo "> 라벨된 이벤트 코퍼스를 데몬과 **같은 분류 코드**(\`classify_event\`)에 소켓 없이 흘려, 룰·코릴레이션·LLM"
  echo "> 각 층의 오탐·탐지·비용을 잰다. 하네스 \`analyzer/src/eval.cpp\`, 코퍼스 \`eval/corpus/\`. 재현: \`REAL=1 scripts/eval/run-eval.sh\`."
  echo "> 게이트: \`ctest\` 의 \`analyzer.eval_gate\` 가 known-miss 아닌 시나리오의 ≥High 미탐 시 실패한다."
  echo
  echo "생성: $(date -Iseconds) · 코퍼스: benign $(cat "$BENIGN"/*.events 2>/dev/null | grep -c '^execve\|^connect' || echo 0) 이벤트 / attack $(ls "$ATTACK"/*.events | wc -l) 시나리오"
  echo
  echo "## mock 분류기 (오프라인, 결정론)"
  echo
  cat "$TMPM"
  if [[ "${REAL:-0}" == "1" && -f "${TMPR:-/nonexistent}" ]]; then
    echo
    echo "## 실 Claude API (Haiku→Sonnet)"
    echo
    cat "$TMPR"
    echo
    echo "> **두 분류기의 오탐 성향이 다르다.** mock 은 curl/wget/python 등 키워드만 의심하는 휴리스틱이라"
    echo "> 정상 개발 세션(키워드 없음)엔 오탐이 없지만 공격 코퍼스의 다운로더 줄(expect:drop)을 과탐하고, 키워드 없는 신종은 놓친다."
    echo "> 실 모델은 다운로더 문맥은 잘 구분(공격 코퍼스 오탐 mock 4 → real 1)하지만, 낯선 빌드·시스템 도구를 의심해"
    echo "> 정상 코퍼스에 자체 오탐이 생긴다. **결론: 실 모델조차 오탐이 있으므로 LLM 을 판정 앵커로 두지 않는다** —"
    echo "> 룰·코릴레이션이 앵커, LLM 은 설명자. 화이트리스트는 이 평가의 오탐 분석으로 튜닝한다(예: gmake·ss 추가)."
  fi
  echo
  echo "## 튜닝 로그"
  echo "- **2026-09-06 #1**: 초기 실 API 에서 정상 오탐률 5.62% (전량 \`gmake\`·\`ss\`) — 화이트리스트에 없어 LLM 까지"
  echo "  올라감. 두 도구(+ldconfig/ctest/dirname)를 \`prefilter.cpp\` 화이트리스트에 추가 → 그 코퍼스에서 0.00%."
  echo "- **2026-09-06 #2 (파일훅·계보 추가 후)**: 정상 코퍼스를 재캡처(docker·make 활동 포함)하니 LLM 오탐이"
  echo "  \`gmake→/bin/sh\`(make 가 레시피마다 셸 실행)와 \`docker\` 에 집중. **전부 LLM-only — 룰 단독 FPR 은 0%.**"
  echo "  \`sh\`/\`bash\` 는 리버스셸의 핵심이라 화이트리스트에 넣으면 센서가 눈먼다 → **의도적으로 튜닝하지 않고 기록.**"
  echo "  교훈: 이 오탐은 값싸게 못 없앤다. 그래서 LLM 은 앵커가 아니라 triage 이고(룰·코릴레이션이 판정),"
  echo "  프로덕션이라면 escalate 대상을 좁히거나 LLM 의심을 코릴레이션으로 교차검증해야 한다."
  echo
  echo "## 읽는 법"
  echo "- **오탐률(FPR)**: 정상 코퍼스에서 alert 난 비율. source 별로 어느 층이 오탐을 냈는지 분해."
  echo "- **시나리오 탐지(≥High)**: EDR 의 실질 지표 — 시나리오당 High 이상 alert 이 하나라도 있으면 탐지."
  echo "- **known-miss**: 설계상 못 잡는 것을 정직하게 표기하고 게이트에서 제외 (예: 인자 미관측 → \`cat /etc/shadow\`)."
  echo "- **결정 층**: rule(즉시) / rule+correlation / correlation+sonnet(룰이 못 잡고 시퀀스로) / sonnet(Haiku 의심 후 심층)."
} > "$DOC"
rm -f "$TMPM" "${TMPR:-}"
echo "[eval] → $DOC ($(wc -l < "$DOC") 줄)"
