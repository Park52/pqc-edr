// crypto/include/pqsec/x25519.h
//
// X25519 임시(ephemeral) 키교환 (OpenSSL EVP). 하이브리드의 고전 축.
// 생성자에서 임시 키쌍을 만들고, 상대 공개키로 ECDH 공유비밀을 계산한다.

#ifndef PQSEC_X25519_H
#define PQSEC_X25519_H

#include "pqsec/pqc.h" // Bytes

namespace pqsec {

class X25519 {
public:
    X25519(); // 임시 키쌍 생성
    ~X25519();
    X25519(const X25519 &) = delete;
    X25519 &operator=(const X25519 &) = delete;

    static constexpr size_t kKeyLen = 32;

    Bytes public_key() const;                            // raw 32B
    Bytes compute_shared(const Bytes &peer_public) const; // ECDH → 32B

private:
    void *pkey_; // EVP_PKEY*
};

} // namespace pqsec

#endif // PQSEC_X25519_H
