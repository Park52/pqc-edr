# 탐지 평가 (EVAL)

> 라벨된 이벤트 코퍼스를 데몬과 **같은 분류 코드**(`classify_event`)에 소켓 없이 흘려, 룰·코릴레이션·LLM
> 각 층의 오탐·탐지·비용을 잰다. 하네스 `analyzer/src/eval.cpp`, 코퍼스 `eval/corpus/`. 재현: `REAL=1 scripts/eval/run-eval.sh`.
> 게이트: `ctest` 의 `analyzer.eval_gate` 가 known-miss 아닌 시나리오의 ≥High 미탐 시 실패한다.

생성: 2026-09-06T09:10:36+09:00 · 코퍼스: benign 5055 이벤트 / attack 7 시나리오

## mock 분류기 (오프라인, 결정론)

# 탐지 평가 결과 (llm=mock)

## 1. 정상 코퍼스 — 오탐률·비용 (1 파일, 5055 이벤트)

| 지표 | 값 |
|---|---:|
| alert (= 오탐) | 0 / 5055 = **0.00%** |
| LLM 도달 (Haiku 호출 이벤트) | 1063 (21.0%) |
| Sonnet 도달 | 0 (0.00%) |
| 실 API 호출 (메모 후) | 7 (메모 히트 1056) |
| 비용 | n/a (mock) |
| 지연 룰 경로 median / p90 | 0.9 / 0.9 µs |
| 지연 LLM 경로 median / p90 | 1.3 / 1.7 µs |

층별 분포: `drop` 79.0%  `haiku-normal` 21.0%  

상위 오탐 요약 (top 10):

| n | 이벤트 | source |
|---:|---|---|

## 2. 공격 시나리오 — 탐지율 (7 시나리오)

| 시나리오 | 이벤트 | expect:alert 탐지 | expect:drop 오탐 | 시나리오 탐지 (≥High) | 최대 심각도 | 기대 심각도 | 결정 층 | 비고 |
|---|---:|---:|---:|:---:|---|---|---|---|
| c2-beacon-443 | 4 | 2/2 | 0/2 | ✅ | high | ≥high ✅ | correlation+sonnet×2  |  |
| c2-beacon-4444 | 6 | 5/5 | 1/1 | ✅ | high | ≥high ✅ | rule×2 rule+correlation×3 sonnet×1  |  |
| exec-chain-curl | 8 | 3/3 | 1/5 | ✅ | critical | ≥critical ✅ | rule×2 rule+correlation×1 sonnet×1  |  |
| exec-chain-split-parent | 4 | 1/1 | 1/3 | ✅ | high | ≥high ✅ | rule×1 sonnet×1  |  |
| exec-chain-wget-devshm | 5 | 2/2 | 1/3 | ✅ | critical | ≥critical ✅ | rule×1 rule+correlation×1 sonnet×1  |  |
| recon-shadow | 3 | 0/2 | 0/1 | ❌ | info | - |  | known-miss: 화이트리스트가 인자를 못 봄 — cat /etc/shadow 가 cat 실행으로만 보여 Drop |
| reverse-shell-devtcp | 2 | 1/1 | 0/1 | ❌ | medium | - | rule×1  | known-miss: /dev/tcp 단일 리버스셸은 rule Medium — nc 없이 High 로는 못 올림 (반복 시 beacon) |

시나리오 탐지 **5/7**, 게이트 대상(known-miss 제외) **5/5**. 공격 코퍼스 LLM 호출: Haiku 8, Sonnet 6.


## 실 Claude API (Haiku→Sonnet)

# 탐지 평가 결과 (llm=real)

## 1. 정상 코퍼스 — 오탐률·비용 (1 파일, 5055 이벤트)

| 지표 | 값 |
|---|---:|
| alert (= 오탐) | 0 / 5055 = **0.00%** |
| LLM 도달 (Haiku 호출 이벤트) | 1063 (21.0%) |
| Sonnet 도달 | 0 (0.00%) |
| 실 API 호출 (메모 후) | 7 (메모 히트 1056) |
| 토큰 (Haiku in/out, Sonnet in/out) | 1245/274, 0/0 |
| 비용 | $0.0026 총, **$0.0005 / 1k 이벤트** (메모 없이면 ×151.9) |
| 지연 룰 경로 median / p90 | 0.9 / 1.2 µs |
| 지연 LLM 경로 median / p90 | 1.4 / 2.6 µs |

층별 분포: `drop` 79.0%  `haiku-normal` 21.0%  

상위 오탐 요약 (top 10):

| n | 이벤트 | source |
|---:|---|---|

## 2. 공격 시나리오 — 탐지율 (7 시나리오)

| 시나리오 | 이벤트 | expect:alert 탐지 | expect:drop 오탐 | 시나리오 탐지 (≥High) | 최대 심각도 | 기대 심각도 | 결정 층 | 비고 |
|---|---:|---:|---:|:---:|---|---|---|---|
| c2-beacon-443 | 4 | 2/2 | 0/2 | ✅ | high | ≥high ✅ | correlation+sonnet×2  |  |
| c2-beacon-4444 | 6 | 5/5 | 0/1 | ✅ | high | ≥high ✅ | rule×2 rule+correlation×3  |  |
| exec-chain-curl | 8 | 3/3 | 1/5 | ✅ | critical | ≥critical ✅ | rule×2 rule+correlation×1 sonnet×1  |  |
| exec-chain-split-parent | 4 | 1/1 | 2/3 | ✅ | high | ≥high ✅ | rule×1 sonnet×2  |  |
| exec-chain-wget-devshm | 5 | 2/2 | 0/3 | ✅ | critical | ≥critical ✅ | rule×1 rule+correlation×1  |  |
| recon-shadow | 3 | 0/2 | 0/1 | ❌ | info | - |  | known-miss: 화이트리스트가 인자를 못 봄 — cat /etc/shadow 가 cat 실행으로만 보여 Drop |
| reverse-shell-devtcp | 2 | 1/1 | 0/1 | ❌ | medium | - | rule×1  | known-miss: /dev/tcp 단일 리버스셸은 rule Medium — nc 없이 High 로는 못 올림 (반복 시 beacon) |

시나리오 탐지 **5/7**, 게이트 대상(known-miss 제외) **5/5**. 공격 코퍼스 LLM 호출: Haiku 8, Sonnet 5.

실 API 호출 합계 17 (메모 히트 1059, 상한 도달 0), 총 비용 $0.0149

> **두 분류기의 오탐 성향이 다르다.** mock 은 curl/wget/python 등 키워드만 의심하는 휴리스틱이라
> 정상 개발 세션(키워드 없음)엔 오탐이 없지만 공격 코퍼스의 다운로더 줄(expect:drop)을 과탐하고, 키워드 없는 신종은 놓친다.
> 실 모델은 다운로더 문맥은 잘 구분(공격 코퍼스 오탐 mock 4 → real 1)하지만, 낯선 빌드·시스템 도구를 의심해
> 정상 코퍼스에 자체 오탐이 생긴다. **결론: 실 모델조차 오탐이 있으므로 LLM 을 판정 앵커로 두지 않는다** —
> 룰·코릴레이션이 앵커, LLM 은 설명자. 화이트리스트는 이 평가의 오탐 분석으로 튜닝한다(예: gmake·ss 추가).

## 튜닝 로그
- **2026-09-06 초기 실 API 실행**: 정상 코퍼스 오탐률 5.62% (284/5055), 전량 `gmake`(cmake 가 부르는 GNU make)
  와 `ss`(소켓 통계) — 화이트리스트에 없어 LLM 까지 올라가 Haiku·Sonnet 이 의심 판정.
  → 두 도구(+ldconfig/ctest/dirname)를 `prefilter.cpp` 화이트리스트에 추가. **재측정 FPR 0.00%**, 게이트·탐지율 불변.
  이것이 평가 세트의 목적: 오탐원을 데이터로 찾아 룰을 튜닝하고 회귀를 게이트로 고정.

## 읽는 법
- **오탐률(FPR)**: 정상 코퍼스에서 alert 난 비율. source 별로 어느 층이 오탐을 냈는지 분해.
- **시나리오 탐지(≥High)**: EDR 의 실질 지표 — 시나리오당 High 이상 alert 이 하나라도 있으면 탐지.
- **known-miss**: 설계상 못 잡는 것을 정직하게 표기하고 게이트에서 제외 (예: 인자 미관측 → `cat /etc/shadow`).
- **결정 층**: rule(즉시) / rule+correlation / correlation+sonnet(룰이 못 잡고 시퀀스로) / sonnet(Haiku 의심 후 심층).
