// crypto/include/pqsec/wire.h
//
// 핸드셰이크 메시지 와이어 포맷. docs/handshake-design.md §7 참조.
// 공통 프레임: [u8 msg_type][u8 version][u16 payload_len(be)][payload...]
//
// 파싱은 fail-closed: 길이 불일치·잘린 입력·잘못된 타입/버전은 예외(WireError).

#ifndef PQSEC_WIRE_H
#define PQSEC_WIRE_H

#include "pqsec/pqc.h" // Bytes

#include <cstdint>
#include <stdexcept>

namespace pqsec::wire {

class WireError : public std::runtime_error {
public:
    explicit WireError(const std::string &what) : std::runtime_error(what) {}
};

enum class MsgType : uint8_t {
    ClientHello = 1,
    ServerHello = 2,
    ServerAuth  = 3,
    ClientAuth  = 4,
};

constexpr uint8_t kVersion    = 1;
constexpr size_t  kRandomLen  = 32;
constexpr size_t  kX25519Len  = 32;
constexpr size_t  kHeaderLen  = 4; // type + version + u16 len

// --- 메시지 구조체 ---------------------------------------------------------
struct ClientHello {
    Bytes client_random; // 32
    Bytes x25519_pub;    // 32
    Bytes mlkem_pub;     // ML-KEM-768 공개키
};

struct ServerHello {
    Bytes server_random; // 32
    Bytes x25519_pub;    // 32
    Bytes mlkem_ct;      // ML-KEM-768 ciphertext
};

struct ServerAuth {
    Bytes signature; // ML-DSA sig over H(CH ‖ SH)
};

struct ClientAuth {
    Bytes signature; // ML-DSA sig over H(CH ‖ SH ‖ ServerAuth)
};

// --- 직렬화 (전체 프레임 반환) ---------------------------------------------
Bytes serialize(const ClientHello &m);
Bytes serialize(const ServerHello &m);
Bytes serialize(const ServerAuth &m);
Bytes serialize(const ClientAuth &m);

// --- 파싱 (전체 프레임 입력, 실패 시 WireError) -----------------------------
ClientHello parse_client_hello(const Bytes &frame);
ServerHello parse_server_hello(const Bytes &frame);
ServerAuth  parse_server_auth(const Bytes &frame);
ClientAuth  parse_client_auth(const Bytes &frame);

// 프레임 헤더에서 메시지 타입만 미리 확인 (디스패치용)
MsgType peek_type(const Bytes &frame);

} // namespace pqsec::wire

#endif // PQSEC_WIRE_H
