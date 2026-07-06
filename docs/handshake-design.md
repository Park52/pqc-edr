# PQSec 핸드셰이크 설계

> 축약 mTLS 핸드셰이크. TLS 1.3 상호인증 구조를 PQC로 옮긴 것.
> **KEM(하이브리드) = 기밀성, ML-DSA 서명 = 인증.**
> 범위 밖(ROADMAP): 전체 TLS 1.3 재구현, CA/PKI. → self-signed + 사전공유 신뢰로 대체.

## 1. 신뢰 모델

각 엔드포인트(agent, analyzer)는:
- **자신의 장기 ML-DSA 키쌍** 보유 (장치 신원)
- **상대의 장기 ML-DSA 공개키**를 아웃오브밴드로 사전 배포받아 보관

CA 체인 검증 대신 "이미 아는 상대 공개키와 일치하는가"로 신원을 확인한다. 이는 SSH의
`known_hosts`, TLS의 인증서 고정(pinning)과 같은 신뢰 모델이다.

## 2. 암호 스위트

| 용도 | 알고리즘 | NIST level | 비고 |
|---|---|---|---|
| 기밀성 (PQC KEM) | ML-KEM-768 | 3 | pub 1184B / ct 1088B / ss 32B |
| 기밀성 (고전 KEM) | X25519 | — | 하이브리드 상대축, pub 32B / ss 32B |
| 인증 (PQC 서명) | ML-DSA-65 | 3 | pub 1952B / sig ~3309B |
| 키유도 | HKDF-SHA256 | — | extract-then-expand |
| record layer | AES-256-GCM | — | 방향별 키 분리 |
| 트랜스크립트 해시 | SHA-256 | — | |

ML-KEM/ML-DSA 모두 NIST level 3으로 맞춰 보안강도를 정렬.

## 3. 메시지 흐름

```
agent(client)                                     analyzer(server)
  |                                                     |
  |  1. ClientHello                                     |
  |   client_random(32) ‖ x25519_c_pub(32)              |
  |   ‖ mlkem_c_pub(1184)                               |
  |---------------------------------------------------->|
  |                                                     |  (하이브리드 세션키 유도 가능)
  |  2. ServerHello                                     |
  |   server_random(32) ‖ x25519_s_pub(32)              |
  |   ‖ mlkem_ct(1088)                                  |
  |<----------------------------------------------------|
  |  (하이브리드 세션키 유도 가능)                        |
  |  3. ServerAuth                                      |
  |   ml_dsa_sig( H(CH ‖ SH) )                          |
  |<----------------------------------------------------|
  |  (사전보유 서버 공개키로 검증 → 서버 인증)             |
  |  4. ClientAuth                                      |
  |   ml_dsa_sig( H(CH ‖ SH ‖ ServerAuth) )             |
  |---------------------------------------------------->|
  |                                                     |  (사전보유 클라 공개키로 검증 → 클라 인증)
  |  ===== record layer (AES-256-GCM) 전환 =====         |
```

**서버가 먼저 인증**(TLS 1.3와 동일). 서명 실패 = fail-closed 즉시 종료.

## 4. 역할 배정 근거 (왜 이 필드가 여기 있나)

- **X25519**는 DH라 대칭적: 양쪽이 임시 공개키를 서로 보낸다 → `ClientHello.x25519_c_pub`,
  `ServerHello.x25519_s_pub`.
- **ML-KEM**은 KEM이라 비대칭적:
  - 클라이언트가 KEM **수신자** → `ClientHello.mlkem_c_pub`(공개키)를 보냄
  - 서버가 KEM **송신자** → 그 공개키로 encaps 한 `ServerHello.mlkem_ct`(ciphertext)를 보냄
  - 클라이언트는 자기 ML-KEM 개인키로 ct 를 decaps → 공유비밀
- `*_random`: 세션 신선도(replay 방지) + HKDF salt + 트랜스크립트 바인딩.
- **서명 대상 = 트랜스크립트 해시**: 서명이 앞선 모든 핸드셰이크 바이트(=KEM 공개키·ct 포함)를
  덮으므로, 중간자가 KEM 공유값을 바꾸면 서명 검증에서 걸린다. 이게 MITM·다운그레이드 방어의 핵심.

## 5. 키 스케줄

```
ss_classical = X25519(내 임시개인키, 상대 임시공개키)     # 32B
ss_pq        = ML-KEM 공유비밀                            # 32B
                (서버: encaps 결과 / 클라: decaps 결과)

IKM  = ss_classical ‖ ss_pq                               # 하이브리드 결합
salt = client_random ‖ server_random
PRK  = HKDF-Extract(salt, IKM)

th   = SHA-256(ClientHello ‖ ServerHello)
c2s_key = HKDF-Expand(PRK, "pqsec c2s key" ‖ th, 32)      # agent → analyzer
s2c_key = HKDF-Expand(PRK, "pqsec s2c key" ‖ th, 32)      # analyzer → agent
# GCM nonce/IV base 파생은 record layer 에서 (예: "pqsec c2s iv")
```

**하이브리드 안전성:** IKM 이 두 공유비밀의 연접이므로, X25519 가 양자컴퓨터로 깨져도 ss_pq 가,
ML-KEM 에 미래 결함이 나와도 ss_classical 이 IKM 의 예측불가능성을 지킨다. **둘 중 하나만
안전하면 세션키가 안전.**

**HKDF 역할:** KEM/DH 의 raw 공유비밀은 균일 분포가 아니므로 직접 키로 쓰면 안 된다.
extract 로 균일한 PRK 를 만들고 expand 로 방향별·용도별 키를 분리 파생한다. `th` 를 info 에
묶어 핸드셰이크가 변조되면 파생키가 달라지게 한다.

## 6. 키 확인 (key confirmation)

별도 Finished 메시지 없이, **record layer 첫 GCM 레코드 복호 성공**으로 양쪽이 같은 세션키를
얻었는지 암묵 확인한다(KEM 왕복이 정상이었는지). 서명은 트랜스크립트 바이트를 덮지만 decaps
결과의 일치까지 보장하진 않으므로, 이 암묵 확인이 KEM 불일치를 잡는다. 필요 시 명시적
Finished(HMAC(finished_key, transcript))를 추가할 수 있다.

## 7. 와이어 프레이밍

모든 핸드셰이크 메시지 공통 헤더:
```
[u8 msg_type][u8 version][u16 payload_len][payload ...]
```
- `msg_type`: 1=ClientHello, 2=ServerHello, 3=ServerAuth, 4=ClientAuth
- `version`: 프로토콜 버전(현재 1). 다운그레이드 협상은 없음(고정).
- `payload_len`: payload 바이트 수(big-endian). 수신측은 길이를 검증하고 초과/부족 시 fail-closed.

## 8. 비용 (면접 트레이드오프)

핸드셰이크 총량 ≈ Hello 2개(~2.3KB + ~1.2KB) + 서명 2개(~6.6KB) ≈ **10KB 안팎**.
고전 TLS(수백 B) 대비 크다 — PQC(특히 ML-DSA 서명 ~3.3KB)의 대역폭 비용. 엔드포인트 보안
채널은 연결 수립 빈도가 낮아 감내 가능하지만, 고빈도 단명 연결에는 부담. 이 트레이드오프를
"왜 그래도 PQC 상호인증을 쓰나"(harvest-now-decrypt-later + 미래 위조 방어)로 정당화.

## 9. 범위 밖 / 알려진 한계

- 신원 은닉 없음: TLS 1.3 은 서명 메시지를 암호화해 신원을 숨기나, 여기선 신원 공개키가
  어차피 사전공유라 평문 전송(범위 축소).
- 세션 재개(0-RTT/PSK resumption), 키 갱신(rekey), 인증서 폐기 없음.
- 사이드채널(상수시간) 방어는 라이브러리(liboqs/OpenSSL) 구현에 위임.
