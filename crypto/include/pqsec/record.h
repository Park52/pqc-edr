// crypto/include/pqsec/record.h
//
// AES-256-GCM record layer. 하이브리드 핸드셰이크로 유도한 방향별 세션키/IV 를 받아
// 애플리케이션 메시지를 암호화·인증한다.
//
// nonce 구성(TLS 1.3 방식): nonce = iv_base(12B) XOR left_pad(seq64).
//   - seq 는 레코드마다 단조 증가 → 같은 키로 nonce 재사용 없음 (GCM 필수 조건).
//   - 송신/수신이 각자 seq 를 세므로 순서가 어긋나면 복호 실패(fail-closed).
//
// 레코드 프레임: [u16 len(be)][ciphertext ...][tag(16)]   (len = ciphertext+tag 길이)
//   len 필드는 AAD 로 인증한다.

#ifndef PQSEC_RECORD_H
#define PQSEC_RECORD_H

#include "pqsec/pqc.h" // Bytes

#include <cstdint>
#include <stdexcept>

namespace pqsec {

class RecordError : public std::runtime_error {
public:
    explicit RecordError(const std::string &what) : std::runtime_error(what) {}
};

constexpr size_t kGcmTagLen = 16;
constexpr size_t kIvLen = 12;
constexpr size_t kAesKeyLen = 32;

// 한 방향 송신기: plaintext → 프레임된 암호 레코드
class RecordSender {
public:
    RecordSender(Bytes key, Bytes iv_base);
    Bytes seal(const Bytes &plaintext); // 전체 레코드 프레임 반환

private:
    Bytes key_;
    Bytes iv_base_;
    uint64_t seq_ = 0;
};

// 한 방향 수신기: 프레임된 암호 레코드 → plaintext (태그 검증 실패 시 RecordError)
class RecordReceiver {
public:
    RecordReceiver(Bytes key, Bytes iv_base);
    Bytes open(const Bytes &record);

private:
    Bytes key_;
    Bytes iv_base_;
    uint64_t seq_ = 0;
};

} // namespace pqsec

#endif // PQSEC_RECORD_H
