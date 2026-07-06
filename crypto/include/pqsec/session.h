// crypto/include/pqsec/session.h
//
// 하이브리드 키 스케줄 (docs/handshake-design.md §5).
//   IKM  = ss_classical ‖ ss_pq
//   PRK  = HKDF-Extract(client_random ‖ server_random, IKM)
//   c2s_key = HKDF-Expand(PRK, "pqsec c2s key" ‖ transcript_hash, 32)
//   s2c_key = HKDF-Expand(PRK, "pqsec s2c key" ‖ transcript_hash, 32)

#ifndef PQSEC_SESSION_H
#define PQSEC_SESSION_H

#include "pqsec/pqc.h" // Bytes

namespace pqsec {

struct SessionKeys {
    Bytes c2s_key; // agent → analyzer (AES-256 키, 32B)
    Bytes s2c_key; // analyzer → agent (32B)
    Bytes c2s_iv;  // GCM nonce base (12B) — record layer 에서 사용
    Bytes s2c_iv;  // 12B
};

// 하이브리드 세션키 유도. 양쪽이 같은 입력을 넣으면 동일한 키가 나온다.
SessionKeys derive_session_keys(const Bytes &ss_classical, const Bytes &ss_pq,
                                const Bytes &client_random, const Bytes &server_random,
                                const Bytes &transcript_hash);

} // namespace pqsec

#endif // PQSEC_SESSION_H
