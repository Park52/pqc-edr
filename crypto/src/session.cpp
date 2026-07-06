// crypto/src/session.cpp — 하이브리드 키 스케줄

#include "pqsec/session.h"
#include "pqsec/kdf.h"

namespace pqsec {

namespace {

// 라벨 문자열 ‖ transcript_hash 를 HKDF info 로 만든다.
Bytes label_info(const char *label, const Bytes &transcript_hash) {
    Bytes info(label, label + std::char_traits<char>::length(label));
    info.insert(info.end(), transcript_hash.begin(), transcript_hash.end());
    return info;
}

Bytes concat(const Bytes &a, const Bytes &b) {
    Bytes out = a;
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

} // namespace

SessionKeys derive_session_keys(const Bytes &ss_classical, const Bytes &ss_pq,
                                const Bytes &client_random, const Bytes &server_random,
                                const Bytes &transcript_hash) {
    // 하이브리드: 두 공유비밀 연접이 IKM. 둘 중 하나만 안전해도 IKM 예측 불가.
    Bytes ikm = concat(ss_classical, ss_pq);
    Bytes salt = concat(client_random, server_random);

    Bytes prk = hkdf_extract(salt, ikm);

    SessionKeys keys;
    keys.c2s_key = hkdf_expand(prk, label_info("pqsec c2s key", transcript_hash), 32);
    keys.s2c_key = hkdf_expand(prk, label_info("pqsec s2c key", transcript_hash), 32);
    keys.c2s_iv  = hkdf_expand(prk, label_info("pqsec c2s iv", transcript_hash), 12);
    keys.s2c_iv  = hkdf_expand(prk, label_info("pqsec s2c iv", transcript_hash), 12);
    return keys;
}

} // namespace pqsec
