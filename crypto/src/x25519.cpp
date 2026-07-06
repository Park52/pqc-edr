// crypto/src/x25519.cpp — X25519 임시 키교환 (OpenSSL EVP)

#include "pqsec/x25519.h"

#include <openssl/evp.h>

#include <stdexcept>

namespace pqsec {

namespace {

[[noreturn]] void fail(const char *what) {
    throw std::runtime_error(std::string("x25519: ") + what);
}

EVP_PKEY *as_pkey(void *p) { return static_cast<EVP_PKEY *>(p); }

} // namespace

X25519::X25519() : pkey_(nullptr) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (pctx == nullptr)
        fail("EVP_PKEY_CTX_new_id 실패");
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        fail("X25519 keygen 실패");
    }
    EVP_PKEY_CTX_free(pctx);
    pkey_ = pkey;
}

X25519::~X25519() { EVP_PKEY_free(as_pkey(pkey_)); }

Bytes X25519::public_key() const {
    Bytes pub(kKeyLen);
    size_t len = kKeyLen;
    if (EVP_PKEY_get_raw_public_key(as_pkey(pkey_), pub.data(), &len) != 1 || len != kKeyLen)
        fail("raw 공개키 추출 실패");
    return pub;
}

Bytes X25519::compute_shared(const Bytes &peer_public) const {
    if (peer_public.size() != kKeyLen)
        fail("상대 공개키 길이 오류");

    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                 peer_public.data(), peer_public.size());
    if (peer == nullptr)
        fail("상대 공개키 로드 실패");

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(as_pkey(pkey_), nullptr);
    if (dctx == nullptr) {
        EVP_PKEY_free(peer);
        fail("derive ctx 생성 실패");
    }

    Bytes secret;
    size_t slen = 0;
    if (EVP_PKEY_derive_init(dctx) <= 0 || EVP_PKEY_derive_set_peer(dctx, peer) <= 0 ||
        EVP_PKEY_derive(dctx, nullptr, &slen) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer);
        fail("ECDH derive(길이) 실패");
    }
    secret.resize(slen);
    if (EVP_PKEY_derive(dctx, secret.data(), &slen) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer);
        fail("ECDH derive 실패");
    }
    secret.resize(slen);

    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer);
    return secret;
}

} // namespace pqsec
