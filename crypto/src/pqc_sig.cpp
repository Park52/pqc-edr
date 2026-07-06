// crypto/src/pqc_sig.cpp — ML-DSA-65 래퍼 (liboqs)

#include "pqsec/pqc.h"

#include <oqs/oqs.h>

namespace pqsec {

static OQS_SIG *as_sig(void *p) { return static_cast<OQS_SIG *>(p); }

MlDsa::MlDsa() : sig_(OQS_SIG_new(OQS_SIG_alg_ml_dsa_65)) {
    if (sig_ == nullptr)
        throw std::runtime_error("ML-DSA-65 미지원 (liboqs 빌드 확인)");
}

MlDsa::~MlDsa() { OQS_SIG_free(as_sig(sig_)); }

KeyPair MlDsa::keypair() const {
    OQS_SIG *sig = as_sig(sig_);
    KeyPair kp;
    kp.public_key.resize(sig->length_public_key);
    kp.secret_key.resize(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, kp.public_key.data(), kp.secret_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("OQS_SIG_keypair 실패");
    return kp;
}

Bytes MlDsa::sign(const Bytes &message, const Bytes &secret_key) const {
    OQS_SIG *sig = as_sig(sig_);
    if (secret_key.size() != sig->length_secret_key)
        throw std::runtime_error("ML-DSA sign: 개인키 길이 불일치");
    // 서명은 가변 길이 → 최대 버퍼로 잡고 실제 길이로 축소
    Bytes signature(sig->length_signature);
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig, signature.data(), &sig_len, message.data(), message.size(),
                     secret_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("OQS_SIG_sign 실패");
    signature.resize(sig_len);
    return signature;
}

bool MlDsa::verify(const Bytes &message, const Bytes &signature,
                   const Bytes &public_key) const {
    OQS_SIG *sig = as_sig(sig_);
    if (public_key.size() != sig->length_public_key)
        return false; // 잘못된 공개키 길이 → 검증 실패로 취급 (fail-closed)
    return OQS_SIG_verify(sig, message.data(), message.size(), signature.data(),
                          signature.size(), public_key.data()) == OQS_SUCCESS;
}

size_t MlDsa::public_key_len() const { return as_sig(sig_)->length_public_key; }
size_t MlDsa::secret_key_len() const { return as_sig(sig_)->length_secret_key; }
size_t MlDsa::max_signature_len() const { return as_sig(sig_)->length_signature; }
const char *MlDsa::name() const { return as_sig(sig_)->method_name; }

} // namespace pqsec
