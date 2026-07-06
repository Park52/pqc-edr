// crypto/src/wire.cpp — 핸드셰이크 메시지 직렬화/파싱

#include "pqsec/wire.h"

#include <string>

namespace pqsec::wire {

namespace {

// 경계검사 append. u16 은 big-endian.
class Writer {
public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void u16(uint16_t v) {
        buf_.push_back(static_cast<uint8_t>(v >> 8));
        buf_.push_back(static_cast<uint8_t>(v & 0xff));
    }
    void bytes(const Bytes &b) { buf_.insert(buf_.end(), b.begin(), b.end()); }
    Bytes take() { return std::move(buf_); }

private:
    Bytes buf_;
};

// 경계검사 read. 부족하면 WireError.
class Reader {
public:
    Reader(const Bytes &b, size_t off) : buf_(b), pos_(off) {}

    uint8_t u8() {
        need(1);
        return buf_[pos_++];
    }
    uint16_t u16() {
        need(2);
        uint16_t v = static_cast<uint16_t>(buf_[pos_] << 8 | buf_[pos_ + 1]);
        pos_ += 2;
        return v;
    }
    Bytes bytes(size_t n) {
        need(n);
        Bytes out(buf_.begin() + pos_, buf_.begin() + pos_ + n);
        pos_ += n;
        return out;
    }
    size_t remaining() const { return buf_.size() - pos_; }

private:
    void need(size_t n) const {
        if (pos_ + n > buf_.size())
            throw WireError("프레임이 잘림 (경계 초과)");
    }
    const Bytes &buf_;
    size_t pos_;
};

// 공통 프레임 헤더를 쓰고 payload 를 붙인다.
Bytes frame(MsgType type, const Bytes &payload) {
    if (payload.size() > 0xffff)
        throw WireError("payload 가 u16 길이 한도 초과");
    Writer w;
    w.u8(static_cast<uint8_t>(type));
    w.u8(kVersion);
    w.u16(static_cast<uint16_t>(payload.size()));
    w.bytes(payload);
    return w.take();
}

// 헤더를 검증하고 payload 를 Reader 로 반환한다.
Reader open_frame(const Bytes &f, MsgType expected) {
    Reader r(f, 0);
    uint8_t type = r.u8();
    uint8_t version = r.u8();
    uint16_t len = r.u16();
    if (type != static_cast<uint8_t>(expected))
        throw WireError("예상과 다른 메시지 타입");
    if (version != kVersion)
        throw WireError("지원하지 않는 프로토콜 버전");
    if (r.remaining() != len)
        throw WireError("payload_len 과 실제 길이 불일치");
    return r;
}

} // namespace

MsgType peek_type(const Bytes &f) {
    if (f.size() < kHeaderLen)
        throw WireError("프레임이 헤더보다 짧음");
    return static_cast<MsgType>(f[0]);
}

// --- ClientHello ---
Bytes serialize(const ClientHello &m) {
    if (m.client_random.size() != kRandomLen || m.x25519_pub.size() != kX25519Len)
        throw WireError("ClientHello 고정 필드 길이 오류");
    Writer w;
    w.bytes(m.client_random);
    w.bytes(m.x25519_pub);
    w.bytes(m.mlkem_pub); // 나머지 = ML-KEM 공개키
    return frame(MsgType::ClientHello, w.take());
}

ClientHello parse_client_hello(const Bytes &f) {
    Reader r = open_frame(f, MsgType::ClientHello);
    ClientHello m;
    m.client_random = r.bytes(kRandomLen);
    m.x25519_pub = r.bytes(kX25519Len);
    m.mlkem_pub = r.bytes(r.remaining());
    if (m.mlkem_pub.empty())
        throw WireError("ClientHello: ML-KEM 공개키 없음");
    return m;
}

// --- ServerHello ---
Bytes serialize(const ServerHello &m) {
    if (m.server_random.size() != kRandomLen || m.x25519_pub.size() != kX25519Len)
        throw WireError("ServerHello 고정 필드 길이 오류");
    Writer w;
    w.bytes(m.server_random);
    w.bytes(m.x25519_pub);
    w.bytes(m.mlkem_ct);
    return frame(MsgType::ServerHello, w.take());
}

ServerHello parse_server_hello(const Bytes &f) {
    Reader r = open_frame(f, MsgType::ServerHello);
    ServerHello m;
    m.server_random = r.bytes(kRandomLen);
    m.x25519_pub = r.bytes(kX25519Len);
    m.mlkem_ct = r.bytes(r.remaining());
    if (m.mlkem_ct.empty())
        throw WireError("ServerHello: ML-KEM ciphertext 없음");
    return m;
}

// --- ServerAuth / ClientAuth (payload = 서명 전체) ---
Bytes serialize(const ServerAuth &m) { return frame(MsgType::ServerAuth, m.signature); }
Bytes serialize(const ClientAuth &m) { return frame(MsgType::ClientAuth, m.signature); }

ServerAuth parse_server_auth(const Bytes &f) {
    Reader r = open_frame(f, MsgType::ServerAuth);
    ServerAuth m;
    m.signature = r.bytes(r.remaining());
    if (m.signature.empty())
        throw WireError("ServerAuth: 서명 없음");
    return m;
}

ClientAuth parse_client_auth(const Bytes &f) {
    Reader r = open_frame(f, MsgType::ClientAuth);
    ClientAuth m;
    m.signature = r.bytes(r.remaining());
    if (m.signature.empty())
        throw WireError("ClientAuth: 서명 없음");
    return m;
}

} // namespace pqsec::wire
