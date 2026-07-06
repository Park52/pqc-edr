// crypto/src/pqc_kem.cpp — ML-KEM-768 래퍼 (liboqs)

#include "pqsec/pqc.h"

#include <oqs/oqs.h>

namespace pqsec {

static OQS_KEM *as_kem(void *p) { return static_cast<OQS_KEM *>(p); }

MlKem::MlKem() : kem_(OQS_KEM_new(OQS_KEM_alg_ml_kem_768)) {
    if (kem_ == nullptr)
        throw std::runtime_error("ML-KEM-768 미지원 (liboqs 빌드 확인)");
}

MlKem::~MlKem() { OQS_KEM_free(as_kem(kem_)); }

KeyPair MlKem::keypair() const {
    OQS_KEM *kem = as_kem(kem_);
    KeyPair kp;
    kp.public_key.resize(kem->length_public_key);
    kp.secret_key.resize(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, kp.public_key.data(), kp.secret_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("OQS_KEM_keypair 실패");
    return kp;
}

MlKem::EncapsResult MlKem::encaps(const Bytes &peer_public_key) const {
    OQS_KEM *kem = as_kem(kem_);
    if (peer_public_key.size() != kem->length_public_key)
        throw std::runtime_error("ML-KEM encaps: 공개키 길이 불일치");
    EncapsResult r;
    r.ciphertext.resize(kem->length_ciphertext);
    r.shared_secret.resize(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, r.ciphertext.data(), r.shared_secret.data(),
                       peer_public_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("OQS_KEM_encaps 실패");
    return r;
}

Bytes MlKem::decaps(const Bytes &ciphertext, const Bytes &secret_key) const {
    OQS_KEM *kem = as_kem(kem_);
    if (ciphertext.size() != kem->length_ciphertext)
        throw std::runtime_error("ML-KEM decaps: ciphertext 길이 불일치");
    if (secret_key.size() != kem->length_secret_key)
        throw std::runtime_error("ML-KEM decaps: 개인키 길이 불일치");
    Bytes shared_secret(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(),
                       secret_key.data()) != OQS_SUCCESS)
        throw std::runtime_error("OQS_KEM_decaps 실패");
    return shared_secret;
}

size_t MlKem::public_key_len() const { return as_kem(kem_)->length_public_key; }
size_t MlKem::secret_key_len() const { return as_kem(kem_)->length_secret_key; }
size_t MlKem::ciphertext_len() const { return as_kem(kem_)->length_ciphertext; }
size_t MlKem::shared_secret_len() const { return as_kem(kem_)->length_shared_secret; }
const char *MlKem::name() const { return as_kem(kem_)->method_name; }

} // namespace pqsec
