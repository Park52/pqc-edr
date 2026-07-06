// crypto/include/pqsec/pqc.h
//
// liboqs ML-KEM / ML-DSA 를 감싼 얇은 RAII 래퍼.
// 크립토는 직접 구현하지 않고 liboqs primitive 를 조합만 한다.
// 실패는 조용히 넘기지 않는다(fail-closed): 생성/연산 실패는 예외, 검증 실패는 false.

#ifndef PQSEC_PQC_H
#define PQSEC_PQC_H

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace pqsec {

using Bytes = std::vector<uint8_t>;

struct KeyPair {
    Bytes public_key;
    Bytes secret_key;
};

// ML-KEM-768 (기밀성용 PQC KEM)
class MlKem {
public:
    MlKem();
    ~MlKem();
    MlKem(const MlKem &) = delete;
    MlKem &operator=(const MlKem &) = delete;

    KeyPair keypair() const;

    struct EncapsResult {
        Bytes ciphertext;
        Bytes shared_secret;
    };
    // 송신자: 상대 공개키로 캡슐화
    EncapsResult encaps(const Bytes &peer_public_key) const;
    // 수신자: 자기 개인키로 복호 → 공유비밀
    Bytes decaps(const Bytes &ciphertext, const Bytes &secret_key) const;

    size_t public_key_len() const;
    size_t secret_key_len() const;
    size_t ciphertext_len() const;
    size_t shared_secret_len() const;
    const char *name() const;

private:
    void *kem_; // OQS_KEM*
};

// ML-DSA-65 (인증용 PQC 서명)
class MlDsa {
public:
    MlDsa();
    ~MlDsa();
    MlDsa(const MlDsa &) = delete;
    MlDsa &operator=(const MlDsa &) = delete;

    KeyPair keypair() const;

    // 개인키로 메시지 서명
    Bytes sign(const Bytes &message, const Bytes &secret_key) const;
    // 공개키로 서명 검증. 유효하면 true, 아니면 false (fail-closed: 예외 아님).
    bool verify(const Bytes &message, const Bytes &signature,
                const Bytes &public_key) const;

    size_t public_key_len() const;
    size_t secret_key_len() const;
    size_t max_signature_len() const;
    const char *name() const;

private:
    void *sig_; // OQS_SIG*
};

} // namespace pqsec

#endif // PQSEC_PQC_H
