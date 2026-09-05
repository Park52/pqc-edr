# 벤치마크 — PQC 하이브리드 채널 비용과 eBPF collector 오버헤드

> 질문: "양자내성 하이브리드로 가면 얼마나 비싸지나?" / "eBPF 훅이 시스템을 얼마나 느리게 하나?"
> 답: **CPU 는 고전과 동급, 진짜 비용은 와이어 바이트(×47, 세션당 1회). eBPF 는 이벤트당 ~13µs.**

## 환경

| | |
|---|---|
| CPU | Intel Core i7-9700K @ 3.60GHz (데스크톱, 4 코어 가시) |
| OS / 커널 | Ubuntu 24.04 / Linux 6.17 |
| 빌드 | Release (`-O3`), GCC, liboqs 0.15.0 (`OQS_USE_OPENSSL=OFF`), OpenSSL 3.0 |
| 도구 | `build/release/crypto/bench_handshake`, `scripts/bench-ebpf-overhead.sh` |

재현:
```bash
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release -DBUILD_AGENT=OFF
cmake --build build/release --target bench_handshake && ./build/release/crypto/bench_handshake
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep build/agent/agent && scripts/bench-ebpf-overhead.sh
```

## 1. 프리미티브 지연 (µs, N=300, median / p90)

| 연산 | median | p90 | 크기 |
|---|---:|---:|---|
| X25519 keygen | 37.5 | 40.5 | pub 32B |
| X25519 shared | 32.2 | 40.4 | ss 32B |
| **ML-KEM-768 keygen** | **9.9** | 10.4 | pub 1184B |
| **ML-KEM-768 encaps** | **10.1** | 10.2 | ct 1088B |
| **ML-KEM-768 decaps** | **12.3** | 12.4 | ss 32B |
| Ed25519 keygen | 38.9 | 42.9 | pub 32B |
| Ed25519 sign | 37.2 | 40.6 | sig 64B |
| Ed25519 verify | 95.0 | 109.1 | |
| ML-DSA-65 keygen | 35.3 | 37.1 | pub 1952B |
| **ML-DSA-65 sign** | **76.6** | **157.0** | sig 3309B |
| **ML-DSA-65 verify** | **33.4** | 35.8 | |
| AES-256-GCM seal (168B 이벤트) | 1.0 | 1.0 | +2B 헤더 +16B 태그 |
| AES-256-GCM seal+open 왕복 | 1.9 | 1.9 | |

관찰:
- **ML-KEM-768 이 X25519 보다 3배 빠르다.** 격자 연산(NTT 다항식 곱)이 타원곡선 스칼라곱보다 싸다. "PQC = 느리다"는 KEM 에는 해당하지 않는다.
- **ML-DSA-65 verify 는 Ed25519 verify 보다 빠르고, sign 은 2배 느리며 p90 이 median 의 2배.** ML-DSA 서명은 거부 샘플링(rejection sampling)으로 조건을 만족할 때까지 재시도하므로 지연 분산이 크다. 지연에 민감한 경로에선 이 꼬리(tail)를 봐야 한다.
- 레코드 암호화(AES-GCM)는 이벤트당 1µs — 핸드셰이크 이후 비용은 고전 채널과 완전히 동일하다.

## 2. 전체 핸드셰이크 실측 (인메모리 transport, 2 스레드, N=100)

| 항목 | 값 |
|---|---:|
| 클라이언트 관점 지연 median | **0.48 ms** |
| 클라이언트 관점 지연 p90 | 1.14 ms |
| 와이어 바이트 agent→analyzer | 4565 B |
| 와이어 바이트 analyzer→agent | 4469 B |
| **와이어 바이트 합계** | **9034 B** |

네트워크 RTT 제외. 실제 링크에선 4-메시지 흐름이라 **2-RTT** 가 더해진다.
프리미티브 합산(§3, 0.39ms)과의 차이 ~0.1ms 가 직렬화·HKDF·트랜스크립트 해시·스레드 전환 비용.

## 3. 고전 전용 vs 하이브리드 (양측 CPU 합산, median)

| | 고전 전용 (X25519 + Ed25519) *추정* | 하이브리드 (X25519‖ML-KEM-768 + ML-DSA-65) | 배수 |
|---|---:|---:|---:|
| 키교환 CPU | 139.5 µs | 171.8 µs | ×1.2 |
| 인증 CPU (서명 2 + 검증 2) | 264.4 µs | 220.1 µs | ×0.8 |
| **핸드셰이크 CPU 합계** | 403.9 µs | 391.9 µs | **×1.0** |
| 키교환 바이트 | 64 B | 2336 B | ×36.5 |
| 인증 바이트 (서명 2개) | 128 B | 6618 B | ×51.7 |
| **핸드셰이크 바이트 합계 (페이로드)** | 192 B | 8954 B | **×46.6** |

> 정직성 주의: 고전 전용 핸드셰이크는 구현하지 않았다(범위 밖). 그 열은 같은 4-메시지 흐름을
> 가정하고 프리미티브 실측치를 합산한 추정이다. 하이브리드 열도 같은 방식의 합산이며,
> 실측 전체 핸드셰이크는 §2 다.

해석:
- **CPU 로는 공짜에 가깝다.** ML-KEM 이 빠르고 ML-DSA verify 가 빨라서 합계가 고전과 같다.
- **진짜 비용은 바이트다.** 192B → ~9KB. 공개키·암호문·서명이 각각 1~3KB 라서다.
  - 데스크톱/서버 링크에선 무시 가능.
  - 저대역·고지연 링크(차량 텔레매틱스 LTE, IoT)에선 9KB × 2-RTT 가 체감된다 → 세션을 길게 유지하고
    키 갱신으로 대체하는 설계가 필요(현재 미구현, [INTERVIEW_NOTES Q5](../INTERVIEW_NOTES.md)).
  - 서명 6.6KB 가 KEM 2.3KB 보다 크다. 인증 바이트를 줄이려면 ML-DSA-44(서명 2420B)나
    인증서 대신 사전공유 키 핀닝(이미 채택)이 레버다.
- 이 비용은 **세션당 1회**다. 이벤트 168B 는 고전이든 하이브리드든 186B 레코드로 나간다.

## 4. eBPF collector 오버헤드 (N=3000 회 루프, R=5 회 median)

| 경로 | agent 없음 | agent 있음 | 차이 | **이벤트당 추가** |
|---|---:|---:|---:|---:|
| execve (fork+exec `/bin/true`) | 1883.8 ms | 1926.4 ms | +2.3% | **14.2 µs** |
| connect (loopback, 즉시 RST) | 127.2 ms | 166.3 ms | +30.7% | **13.0 µs** |

훅: `ksyscall/execve`(kprobe) + `fentry/tcp_v4_connect`. 이벤트당 비용 = 훅 실행 + `BPF_CORE_READ` +
ring buffer reserve/commit + 유저스페이스 소비(stdout→/dev/null).

해석:
- **절대치는 이벤트당 ~13–14µs 로 두 훅이 비슷하다.** 상대 비율이 다른 건 baseline 차이 —
  fork+exec 은 원래 ~630µs 라 +2%, loopback connect 는 ~42µs 라 +31% 로 보인다.
- 실 워크로드(초당 수백 이벤트)에선 CPU 1% 미만. 초당 수만 execve 를 하는 빌드 서버라면 수 % 까지 갈 수 있다.
- 채널 전송 모드에선 여기에 AES-GCM 1µs + 소켓 send 가 더해진다. analyzer 가 느리면(LLM 호출 수백 ms) TCP
  백프레셔가 걸리는데, agent 는 ring buffer 콜백을 막지 않고 **유한 큐(기본 4096)에서 드롭을 세어 통지**한다.
  스트레스(analyzer SIGSTOP 1.5초, 20만 이벤트): 178,563 드롭 / 21,438 전송, analyzer 복호 21,438 (정합).
  디스크 큐·재연결은 없다 — 유실을 "보이게" 할 뿐 막지는 못한다.
- 노이즈 있는 단일 머신 측정이다. 방향성 지표로만 볼 것.

## 한계

- 데스크톱 x86 1대. 임베디드/차량 ECU(ARM Cortex-A/R) 에선 ML-DSA sign 이 수 ms 가 될 수 있어 다시 재야 한다.
- liboqs 는 이 CPU 의 AVX2 최적화 구현을 쓴다. 범용 C 구현은 수 배 느리다.
- 네트워크 RTT·패킷 손실은 측정하지 않았다(인메모리 transport).
