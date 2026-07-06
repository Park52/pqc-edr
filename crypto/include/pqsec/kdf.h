// crypto/include/pqsec/kdf.h
//
// SHA-256 + HKDF-SHA256 (OpenSSL EVP 조합). 직접 구현 아님.
// HKDF 는 extract-then-expand 로 분리 제공 (docs/handshake-design.md §5).

#ifndef PQSEC_KDF_H
#define PQSEC_KDF_H

#include "pqsec/pqc.h" // Bytes

namespace pqsec {

// SHA-256 다이제스트 (32B)
Bytes sha256(const Bytes &data);

// HKDF-Extract: (salt, IKM) → PRK(32B). raw 공유비밀에서 균일한 키재료 추출.
Bytes hkdf_extract(const Bytes &salt, const Bytes &ikm);

// HKDF-Expand: (PRK, info, len) → OKM(len B). 용도별 키 파생.
Bytes hkdf_expand(const Bytes &prk, const Bytes &info, size_t out_len);

} // namespace pqsec

#endif // PQSEC_KDF_H
