// crypto/include/pqsec/handshake.h
//
// 축약 mTLS 핸드셰이크 상태머신 (docs/handshake-design.md).
// 프리미티브(X25519/ML-KEM/ML-DSA/HKDF/wire)를 엮어 세션을 확립한다.
// 전송 계층은 Transport 로 추상화 → 소켓/인메모리 모두 테스트 가능.

#ifndef PQSEC_HANDSHAKE_H
#define PQSEC_HANDSHAKE_H

#include "pqsec/pqc.h"    // Bytes
#include "pqsec/record.h" // RecordSender/Receiver

#include <functional>
#include <stdexcept>

namespace pqsec {

class HandshakeError : public std::runtime_error {
public:
    explicit HandshakeError(const std::string &what) : std::runtime_error(what) {}
};

// 장기 신원 + 사전보유 상대 공개키 (self-signed + pinning 신뢰모델)
struct Identity {
    Bytes sig_public;      // 내 ML-DSA 공개키
    Bytes sig_secret;      // 내 ML-DSA 개인키
    Bytes peer_sig_public; // 상대의 ML-DSA 공개키 (사전 배포로 보유)
};

// 프레임 단위 송수신 추상화. 한 호출 = 완전한 한 프레임.
struct Transport {
    std::function<void(const Bytes &)> send_frame;
    std::function<Bytes()> recv_frame;
};

// 확립된 방향별 암호 채널
struct Channel {
    RecordSender sender;   // 내가 상대에게 보낼 때
    RecordReceiver receiver; // 상대가 나에게 보낸 것
};

// agent(클라이언트) 역할 핸드셰이크 실행. 실패 시 HandshakeError.
Channel client_handshake(const Identity &id, Transport &t);

// analyzer(서버) 역할 핸드셰이크 실행. 실패 시 HandshakeError.
Channel server_handshake(const Identity &id, Transport &t);

} // namespace pqsec

#endif // PQSEC_HANDSHAKE_H
