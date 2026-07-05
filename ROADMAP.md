# PQSec-Pipeline — 4주 로드맵

> PQC로 보호되는 채널 위에 eBPF 보안 이벤트를 실어 나르고, LLM이 이상행위를 분류·설명하는 통합 엔드포인트 보안 파이프라인.
> 타겟: 42dot Software Engineer (Security System)

---

## 프로젝트 한 줄 요약

**Agent(eBPF collector) → PQC-secured mTLS channel → Analyzer(LLM) → Alert**

공고 요구사항 매핑:
- 보안 모듈/시스템 구현 → eBPF collector + analyzer daemon
- 보안 프로토콜 분석·설계·구현 → mTLS 핸드셰이크 + 하이브리드 키교환 직접 설계
- C/C++ 능통 → 전 구간 C++
- 클라우드 서비스 이해 → analyzer를 컨테이너로, 채널은 네트워크 경유
- (우대) PQC 구현 → liboqs 기반 X25519 + ML-KEM 하이브리드 KEM
- (우대) LLM 보안 솔루션 → Claude API로 이벤트 분류/설명

---

## 아키텍처

```
┌─────────────────────┐         PQC-hybrid mTLS          ┌──────────────────────┐
│   Agent (host)      │  ────────────────────────────▶   │  Analyzer (container)│
│  ┌───────────────┐  │   X25519 + ML-KEM key exchange   │  ┌────────────────┐  │
│  │ eBPF programs │  │   AES-256-GCM record layer       │  │ event decoder  │  │
│  │ execve / conn │──┼──▶ serialize events ──▶ send ────┼─▶│ LLM classifier │  │
│  └───────────────┘  │                                  │  │ (Claude API)   │  │
│  ring buffer → user │                                  │  └────────┬───────┘  │
└─────────────────────┘                                  │           ▼          │
                                                          │       alert / log    │
                                                          └──────────────────────┘
```

---

## Week 1 — eBPF Collector (기존 강점 재활용, 워밍업)

이미 익숙한 영역이라 빠르게 통과하며 프로젝트 뼈대를 세우는 주.

- [ ] 프로젝트 구조 확정, CMake 빌드 세팅, libbpf + CO-RE 스캐폴딩
- [ ] execve / tcp_connect 두 개 eBPF 프로그램 작성 (ring buffer로 유저스페이스 전달)
- [ ] 이벤트 공통 스키마 정의 (`SecurityEvent` 직렬화 포맷 — flatbuffers 또는 단순 POD + length-prefix)
- [ ] collector가 이벤트를 stdout/파일로 뱉는 것까지 완성 (아직 네트워크 없음)

**핵심 개념 (핵심만):** ring buffer vs perf buffer 차이, CO-RE가 왜 필요한지 한 문단.

---

## Week 2 — PQC 하이브리드 키교환 (새로 배우는 핵심 칸)

프로젝트의 차별화 포인트. 여기에 시간을 제일 많이 투자.

- [ ] liboqs 빌드·링크, ML-KEM(Kyber) KEM API 최소 예제 돌리기
- [ ] 하이브리드 키교환 설계: X25519 공유비밀 ∥ ML-KEM 공유비밀 → HKDF로 세션키 유도
- [ ] 핸드셰이크 메시지 포맷 직접 설계 (ClientHello / ServerHello 축약판, 왜 이 필드가 필요한지 근거 남기기)
- [ ] AES-256-GCM record layer (nonce 관리, 재전송/순서 처리 최소 구현)
- [ ] 로컬 소켓으로 agent↔analyzer 암호화 채널 완성

**핵심 개념 (핵심만):** KEM이 뭐고 왜 PQC는 서명이 아니라 KEM부터인지, "하이브리드"를 왜 쓰는지(고전 알고리즘 깨져도 안전, 반대도 성립), HKDF의 역할. → 면접 설명용으로 이 3개만 확실히.

---

## Week 3 — LLM Analyzer + 통합

- [ ] analyzer daemon: 채널에서 이벤트 수신 → 디코드 → 배치
- [ ] Claude API 연동: 이벤트 시퀀스를 넣어 normal/suspicious 분류 + 사유 설명
  - 프롬프트에 룰 기반 1차 필터를 코드로 먼저 태워 토큰 절약 (InvestmentAgent에서 쓰던 패턴 재활용)
  - Haiku로 1차 분류, 의심스러운 것만 Sonnet으로 심층 분석 (모델 분리)
- [ ] alert 출력 (구조화 로그 + 콘솔)
- [ ] agent → PQC 채널 → analyzer → LLM → alert 엔드투엔드 데모 성공

**핵심 개념 (핵심만):** 왜 룰 필터를 LLM 앞단에 두는지(비용·오탐), 이벤트를 어떻게 컨텍스트로 만들지.

---

## Week 4 — 클라우드화 + 마무리 + 문서

- [ ] analyzer를 Docker 컨테이너로, agent는 호스트에서 채널로 접속 (클라우드 서비스 이해 어필)
- [ ] 위협 시나리오 데모 2개 (예: 의심스러운 execve 체인, 비정상 아웃바운드 커넥션) 재현 스크립트
- [ ] README: 아키텍처 다이어그램 + 위협모델 + PQC 설계 근거 + 데모 GIF
- [ ] 면접 대비 Q&A 노트 (아래 항목 각각 3문장 이내로 답 준비)
- [ ] (여유 시) 벤치마크: 핸드셰이크 지연, 하이브리드 vs 고전 키교환 오버헤드

**면접 대비 Q&A 필수 항목:**
1. 왜 하이브리드 KEM인가? 순수 PQC가 아니라?
2. ML-KEM을 골랐는데 다른 후보(BIKE, HQC 등) 대비 트레이드오프는?
3. LLM 이상탐지의 오탐/할루시네이션 리스크를 어떻게 통제했나?
4. eBPF collector가 성능/보안에 주는 영향은?
5. 이 시스템을 실제 프로덕션에 올린다면 뭐가 부족한가? (솔직하게)

---

## 범위 가드레일 (난이도 관리)

넣지 **않는다**:
- 완전한 TLS 1.3 재구현 (핸드셰이크는 축약판으로)
- 인증서 체인/PKI 전체 (self-signed + 사전공유 신뢰로 대체)
- 프로덕션급 eBPF 커버리지 (2~3개 프로그램이면 충분)

"깊이는 데모 + 면접 설명으로, 폭은 통합 파이프라인으로." 각 요소가 완벽할 필요 없고, 세 축이 하나로 연결되어 돌아가는 게 핵심 가치.
