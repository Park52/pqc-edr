# pqc-edr

> **eBPF telemetry over a post-quantum (X25519 + ML-KEM) mTLS channel, triaged by an LLM.**
> A learning-grade PoC exploring PQC-secured endpoint security — **not** a production EDR.

호스트에서 eBPF로 보안 이벤트(프로세스 실행·아웃바운드 접속)를 수집해, **양자내성 하이브리드
암호로 보호되는 상호인증 채널**로 전송하고, LLM이 이상행위를 분류·설명하는 통합 파이프라인.

> ⚠️ **범위**: 학습·포트폴리오용 PoC. 완전한 TLS/PKI 재구현이나 프로덕션급 커버리지가 아니라,
> **세 축(eBPF · PQC · LLM)이 하나로 관통하는 통합**이 핵심 가치. 한계는 [아래](#범위와-한계)에 명시.

---

## 아키텍처

```
  [호스트]                         PQC 하이브리드 mTLS                  [서버/컨테이너]
  agent                     X25519 + ML-KEM 키교환                     analyzer
  ┌──────────────┐          ML-DSA 상호인증                            ┌──────────────┐
  │ eBPF programs│          AES-256-GCM record layer                  │ event decoder│
  │ execve/connect│──┐                                                │ LLM triage   │
  └──────────────┘  │ ring buffer                                     │ (Claude API) │
  ┌──────────────┐  ▼                                                 └──────┬───────┘
  │ userspace     │ 직렬화 → 암호화 ─────────── TCP ───────────────────────┘
  │ collector     │                                                    alert / log
  └──────────────┘
       Week 1                        Week 2                            Week 3 (진행 예정)
```

## 구현 현황

| | 컴포넌트 | 상태 |
|---|---|---|
| **Week 1** | eBPF collector (execve + tcp_connect, CO-RE, ring buffer) | ✅ |
| **Week 2** | PQC 하이브리드 mTLS 채널 (핸드셰이크 + record layer) | ✅ |
| **Week 3** | analyzer 데몬 + Claude API 이상탐지 + 엔드투엔드 통합 | ✅ |
| **Week 4** | 컨테이너화 + 위협 시나리오 데모 + 문서 | ⏳ |

## 핵심 보안 설계

- **하이브리드 KEM** — `X25519 ∥ ML-KEM-768` 공유비밀을 HKDF로 결합. 고전이 양자로 깨져도,
  PQC에 미래 결함이 나와도, **둘 중 하나만 안전하면 세션키가 안전**. (TLS 1.3 하이브리드와 동일 발상)
- **PQC 상호인증** — `ML-DSA-65` 서명으로 트랜스크립트에 상호서명. 서명이 KEM 공개값을 덮어
  **MITM·다운그레이드를 검증 단계에서 차단**. 신뢰모델은 사전공유 신원키(PKI 대체).
- **AES-256-GCM record layer** — TLS 1.3식 nonce(`iv_base ⊕ seq`)로 nonce 재사용 원천 차단,
  변조·재정렬·재전송을 모두 거부.
- **Fail-closed 전반** — 크립토·파싱 실패는 조용히 넘기지 않고 즉시 예외/거부.
- **최소권한 eBPF** — `ksyscall`(kprobe PMU) attach로 root 없이 `CAP_BPF`/`CAP_PERFMON`만으로 동작.
- **LLM 이상탐지 비용·오탐 통제** — 룰 프리필터로 명백 정상/악성을 앞단에서 걸러 LLM 호출을
  줄이고, `claude-haiku-4-5` 1차 분류 → 의심만 `claude-sonnet-5` 심층. LLM 호출 실패는
  fail-safe(미분류로 surface, 데몬 중단 X). 오프라인/CI용 mock 분류기 내장.

암호 스위트: **ML-KEM-768 + X25519 + ML-DSA-65 + HKDF-SHA256 + AES-256-GCM** (PQC는 NIST level 3).
검증된 라이브러리(liboqs, OpenSSL)의 primitive를 **조합만** 하며, 직접 구현한 암호는 없다.

## 빌드 & 데모

**요구사항** (Ubuntu 24.04 / kernel 6.17 기준): `clang`, `libbpf-dev`, `cmake`, `pkg-config`,
`libssl-dev`, `bpftool`.

```bash
# 1) liboqs 로컬 빌드 (ML-KEM-768 + ML-DSA-65, sudo 불필요)
bash scripts/build-liboqs.sh

# 2) 전체 빌드
cmake -S . -B build && cmake --build build
```

**Week 2 — 엔드투엔드 암호화 채널 데모** (실제 TCP 소켓, 두 프로세스):
```bash
./build/crypto/channel_e2e_demo
# 핸드셰이크(상호인증) → 이벤트 암호화 전송 → analyzer 복호·디코드
# 와이어에는 암호문만 흐름을 hex 로 확인
```

**크립토 검증 스위트:**
```bash
./build/crypto/hybrid_demo       # 하이브리드 키합의 + ML-DSA 상호인증 + MITM 거부
./build/crypto/record_demo       # AES-256-GCM 왕복 + 변조/재정렬/재전송 거부
./build/crypto/channel_selftest  # KEM/서명/와이어 포맷 셀프테스트
```

**Week 3 — 엔드투엔드 이상탐지 데모** (agent → PQC 채널 → analyzer → LLM → alert):
```bash
scripts/demo-week3.sh                       # mock LLM (오프라인, 권한 불필요)
USE_REAL_LLM=1 ANTHROPIC_API_KEY=sk-... scripts/demo-week3.sh   # 실 Claude API

# 실 eBPF 수집을 채널로 흘려보내기 (합성 대신):
./build/tools/pqsec_keygen agent && ./build/tools/pqsec_keygen analyzer  # 신원 프로비저닝
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./build/agent/agent
./build/analyzer/analyzer --id analyzer --peer agent.pub --mock-llm &    # 데몬
./build/agent/agent --forward --id agent --peer analyzer.pub             # 실 수집 전송
```

**Week 1 — eBPF collector** (커널 이벤트 수집, 권한 필요):
```bash
# 리빌드마다 file capability 재부여 필요 (capability 는 inode 귀속)
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./build/agent/agent
./build/agent/agent   # 다른 셸에서 명령 실행/접속하면 이벤트가 흐름
```

## 저장소 구조

```
agent/          Week 1 — eBPF collector (bpf/ 커널 프로그램, src/ 유저스페이스 로더)
common/         공유 이벤트 스키마 (security_event)
crypto/         Week 2 — PQC 보안 채널 라이브러리 + 데모
  include/pqsec/  공개 헤더 (pqc, x25519, kdf, session, record, wire, handshake, socket)
  src/            구현
  examples/       데모·셀프테스트
analyzer/       Week 3 — LLM analyzer (예정)
cmake/          eBPF 빌드 파이프라인 헬퍼
scripts/        liboqs 로컬 빌드
docs/           설계·학습 문서
```

## 문서

- [`docs/handshake-design.md`](docs/handshake-design.md) — 핸드셰이크 상세 설계·근거·한계
- [`docs/STUDY_GUIDE.md`](docs/STUDY_GUIDE.md) — eBPF·암호학 제로베이스 학습 가이드
- [`INTERVIEW_NOTES.md`](INTERVIEW_NOTES.md) — 설계 결정 Q&A
- [`ROADMAP.md`](ROADMAP.md) — 4주 계획과 범위 가드레일

## 범위와 한계

의도적으로 **넣지 않은 것** (PoC 스코프 유지):
- 완전한 TLS 1.3 재구현 (핸드셰이크는 축약판)
- 인증서 체인/PKI (self-signed + 사전공유 신뢰로 대체)
- 프로덕션급 eBPF 커버리지 (2개 프로그램)
- 세션 재개·키 갱신·신원 은닉, 사이드채널 방어(라이브러리에 위임)

## 기술 스택
C++17 · CMake · libbpf + CO-RE · liboqs (ML-KEM/ML-DSA) · OpenSSL (X25519/HKDF/AES-GCM) ·
Claude API (Haiku→Sonnet, libcurl + nlohmann/json)
