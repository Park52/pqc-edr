// crypto/src/kdf.cpp — SHA-256 + HKDF-SHA256 (OpenSSL EVP)

#include "pqsec/kdf.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

#include <stdexcept>

namespace pqsec {

namespace {

[[noreturn]] void fail(const char *what) {
    throw std::runtime_error(std::string("kdf: ") + what);
}

// HKDF 한 단계 실행 (mode 로 extract-only / expand-only 구분)
Bytes hkdf_run(int mode, const Bytes &salt_or_unused, const Bytes &key,
               const Bytes &info, size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr)
        fail("EVP_KDF_fetch(HKDF) 실패");
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == nullptr)
        fail("EVP_KDF_CTX_new 실패");

    char digest[] = "SHA256";
    int m = mode;
    OSSL_PARAM params[5];
    int n = 0;
    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &m);
    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(key.data()), key.size());
    if (mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<uint8_t *>(salt_or_unused.data()),
            salt_or_unused.size());
    } else { // EXPAND_ONLY
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<uint8_t *>(info.data()), info.size());
    }
    params[n] = OSSL_PARAM_construct_end();

    Bytes out(out_len);
    int rc = EVP_KDF_derive(ctx, out.data(), out.size(), params);
    EVP_KDF_CTX_free(ctx);
    if (rc <= 0)
        fail("EVP_KDF_derive 실패");
    return out;
}

} // namespace

Bytes sha256(const Bytes &data) {
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr) != 1)
        fail("EVP_Digest(SHA256) 실패");
    out.resize(len);
    return out;
}

Bytes hkdf_extract(const Bytes &salt, const Bytes &ikm) {
    // extract-only: 출력은 해시 길이(32B). key=IKM, salt=salt.
    return hkdf_run(EVP_KDF_HKDF_MODE_EXTRACT_ONLY, salt, ikm, {}, 32);
}

Bytes hkdf_expand(const Bytes &prk, const Bytes &info, size_t out_len) {
    // expand-only: key=PRK, info=info.
    return hkdf_run(EVP_KDF_HKDF_MODE_EXPAND_ONLY, {}, prk, info, out_len);
}

} // namespace pqsec
