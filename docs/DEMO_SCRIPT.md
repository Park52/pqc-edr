# 5분 시연 대본 (면접용)

> 목표: "세 축(eBPF · PQC · LLM)이 하나로 관통한다"를 5분 안에 눈으로 보여주고, 각 단계에서 설계 결정을 한 문장씩 말한다.
> 원칙: **실행 전에 무엇이 나올지 먼저 말하고, 나온 줄을 손가락으로 가리킨다.**

## 전날 준비 체크리스트

```bash
bash scripts/build-liboqs.sh && cmake -S . -B build && cmake --build build -j   # 빌드
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep build/agent/agent            # 실 eBPF (리빌드마다)
ctest --test-dir build                                                        # 전부 초록인지
docker build -f docker/Dockerfile.analyzer -t pqc-edr-analyzer .              # 이미지 미리 (첫 빌드 수 분)
cat .env | wc -c                                                              # ANTHROPIC_API_KEY (실 LLM 단계용, 선택)
```
- 터미널 2개(왼쪽 명령, 오른쪽 README/BENCHMARK), 글꼴 크게, `PORT` 충돌 없는지(`ss -ltn | grep 9443`).
- 인터넷이 없어도 4단계까지는 된다. 5단계(실 LLM)만 네트워크·키 필요.

## 흐름

| 시각 | 단계 | 명령 | 가리킬 출력 | 한 줄 멘트 |
|---|---|---|---|---|
| 0:00 | 아키텍처 | README 다이어그램 | agent → 채널 → analyzer 3칸 | "호스트 eBPF 가 잡은 이벤트를 양자내성 채널로 컨테이너에 보내고, 룰·코릴레이션·LLM 이 분류합니다. 오늘 이 화살표를 실제로 흘려 보겠습니다." |
| 0:30 | 크립토 | `./build/crypto/hybrid_demo` | `세션키 일치`, `MITM ... 거부` | "X25519 와 ML-KEM 공유비밀을 HKDF 로 합칩니다. 둘 중 하나만 안전해도 세션키가 안전합니다. 마지막 줄은 중간자가 공개값을 바꾸면 ML-DSA 서명 검증에서 걸리는 겁니다." |
| 1:00 | 시나리오 1 (실 eBPF) | `scripts/scenario-1-exec-chain.sh` | `[ALERT] ... sev=critical src=rule+download-exec-chain` | "지금 이 셸이 실제로 curl 로 받아 /tmp 에서 실행했고 eBPF 가 잡았습니다. `curl` 하나는 룰이 못 잡지만, 같은 부모에서 직후 임시경로 실행 — 이 시퀀스를 코릴레이터가 Critical 로 올립니다. 와이어엔 암호문만 흘렀습니다." |
| 2:30 | Docker | `scripts/demo-docker.sh` | `컨테이너 ... Up`, 컨테이너 로그의 `[ALERT]` | "analyzer 는 컨테이너(비루트, 142MB)이고 agent 는 호스트입니다. 신원 키는 이미지에 없고 마운트했습니다. 두 번 연결했는데 코릴레이션 상태가 데몬에 유지됩니다." |
| 3:30 | 실 LLM | `USE_REAL_LLM=1 MODE=replay scripts/scenario-2-c2-beacon.sh` | `[llm:claude-haiku-4-5 normal]` 다음의 `src=rule+beacon` | "Haiku 는 단독 이벤트를 보수적으로 정상이라 하고, 3회째 반복 접속에서 비콘 룰이 High 로 올립니다. LLM 이 아니라 결정론적 계층이 판정의 앵커입니다. LLM 은 설명을 씁니다." |
| 4:30 | 숫자 | `docs/BENCHMARK.md` 표 | 0.48ms / 9KB(×47) / CPU 동급 / eBPF 13µs | "하이브리드 비용은 CPU 로는 고전과 같고 바이트가 47배, 세션당 1회입니다. eBPF 훅은 이벤트당 13µs 입니다." |

시간이 남으면: `./build/analyzer/llm_probe "execve comm=bash file=/usr/bin/python3 | 직후 connect ... 4444 반복"` → Sonnet 의 MITRE 매핑 설명.

## 예상 질문 → 답 위치

| 질문 | 답 |
|---|---|
| 왜 순수 PQC 가 아니라 하이브리드? | `INTERVIEW_NOTES.md` Q1 — 검증 기간, SIKE 전례, HNDL, CPU 비용 0 |
| ML-KEM 말고 HQC/BIKE 는? | Q2 — 격자 vs 부호, 크기·속도·성숙도, 격자 리스크는 X25519 로 헤지 |
| LLM 오탐·할루시네이션은? | Q3 — 룰이 앵커, 코릴레이션은 결정론, LLM 은 설명자, fail-safe, 실측 사례 |
| eBPF 가 시스템을 느리게 안 하나? | Q4 — 이벤트당 13µs, execve +2%, verifier, 최소권한 |
| 프로덕션에 올리면 뭐가 부족? | Q5 — PKI/회전 없음, 백프레셔 없음, 훅 2개, 형식 검증 없음 |
| 서명이 정확히 뭘 덮나? | Week 2 Q — 트랜스크립트 해시(공개값·랜덤·스위트) |
| 프롬프트 인젝션은? | `analyzer/src/llm_client_claude.cpp` `sanitize_context`/`wrap_event` — 완화이지 완전 방어 아님, 그래서 앵커가 룰 |
| 왜 CI 에 agent 가 없나? | 러너 커널 BTF·bpftool 의존 → 로컬 setcap 으로 검증, CI 는 채널·analyzer·Docker |

## 실패 시 폴백

| 증상 | 대처 |
|---|---|
| `BPF 로드 실패` / attach 실패 | `MODE=replay scripts/scenario-1-exec-chain.sh` — 같은 순서를 재생. "권한 폴백을 설계해 뒀습니다"로 넘어감 |
| 시나리오 로그에 노이즈가 너무 많음 | 정상. "실 eBPF 는 시스템 전체를 봅니다 — 화이트리스트·Haiku-normal 로 걸러지는 걸 보세요"로 뒤집기 |
| Docker 데몬 안 뜸 / 이미지 없음 | `scripts/demo-week3.sh` 로 로컬 analyzer 시연 + `docker/Dockerfile.analyzer` 를 열어 멀티스테이지 설명 |
| API 키·네트워크 실패 | 기본 mock 으로 진행하고 README 의 실 API 트랜스크립트를 보여줌. fail-safe 로 `unknown` 이 뜨면 "이게 조용히 넘기지 않는 설계"라고 설명 |
| 포트 충돌 | `PORT=19443 scripts/...` |
| setcap 이 풀림(리빌드 후) | `sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep build/agent/agent` |
