// crypto/src/handshake.cpp — 핸드셰이크 상태머신

#include "pqsec/handshake.h"

#include "pqsec/kdf.h"
#include "pqsec/pqc.h"
#include "pqsec/session.h"
#include "pqsec/wire.h"
#include "pqsec/x25519.h"

#include <openssl/rand.h>

namespace pqsec {

namespace {

Bytes random_bytes(size_t n) {
    Bytes b(n);
    if (RAND_bytes(b.data(), static_cast<int>(n)) != 1)
        throw HandshakeError("난수 생성 실패");
    return b;
}

Bytes concat(const Bytes &a, const Bytes &b) {
    Bytes o = a;
    o.insert(o.end(), b.begin(), b.end());
    return o;
}

// 트랜스크립트 해시 = SHA-256(누적 프레임)
Bytes transcript(const Bytes &acc) { return sha256(acc); }

} // namespace

Channel client_handshake(const Identity &id, Transport &t) {
    MlKem kem;
    MlDsa dsa;
    X25519 x_client; // 임시 키

    // --- 1. ClientHello 송신 ---
    KeyPair kem_kp = kem.keypair();
    Bytes client_random = random_bytes(wire::kRandomLen);
    wire::ClientHello ch;
    ch.client_random = client_random;
    ch.x25519_pub = x_client.public_key();
    ch.mlkem_pub = kem_kp.public_key;
    Bytes ch_frame = wire::serialize(ch);
    t.send_frame(ch_frame);

    // --- 2. ServerHello 수신 → 하이브리드 키합의 ---
    Bytes sh_frame = t.recv_frame();
    wire::ServerHello sh = wire::parse_server_hello(sh_frame);
    Bytes ss_classical = x_client.compute_shared(sh.x25519_pub);
    Bytes ss_pq = kem.decaps(sh.mlkem_ct, kem_kp.secret_key);

    Bytes acc = concat(ch_frame, sh_frame);
    Bytes th = transcript(acc);
    SessionKeys keys =
        derive_session_keys(ss_classical, ss_pq, client_random, sh.server_random, th);

    // --- 3. ServerAuth 수신 → 서버 인증 ---
    Bytes sa_frame = t.recv_frame();
    wire::ServerAuth sa = wire::parse_server_auth(sa_frame);
    if (!dsa.verify(th, sa.signature, id.peer_sig_public))
        throw HandshakeError("서버 서명 검증 실패 (인증 실패)");

    // --- 4. ClientAuth 송신 (트랜스크립트에 ServerAuth 까지 포함) ---
    acc = concat(acc, sa_frame);
    Bytes th2 = transcript(acc);
    Bytes client_sig = dsa.sign(th2, id.sig_secret);
    t.send_frame(wire::serialize(wire::ClientAuth{client_sig}));

    // 클라 관점: 보낼 때 c2s, 받을 때 s2c
    return Channel{RecordSender(keys.c2s_key, keys.c2s_iv),
                   RecordReceiver(keys.s2c_key, keys.s2c_iv)};
}

Channel server_handshake(const Identity &id, Transport &t) {
    MlKem kem;
    MlDsa dsa;
    X25519 x_server;

    // --- 1. ClientHello 수신 ---
    Bytes ch_frame = t.recv_frame();
    wire::ClientHello ch = wire::parse_client_hello(ch_frame);

    // --- 2. ServerHello 송신 (encaps) → 하이브리드 키합의 ---
    MlKem::EncapsResult enc = kem.encaps(ch.mlkem_pub);
    Bytes server_random = random_bytes(wire::kRandomLen);
    wire::ServerHello sh;
    sh.server_random = server_random;
    sh.x25519_pub = x_server.public_key();
    sh.mlkem_ct = enc.ciphertext;
    Bytes sh_frame = wire::serialize(sh);
    t.send_frame(sh_frame);

    Bytes ss_classical = x_server.compute_shared(ch.x25519_pub);
    Bytes ss_pq = enc.shared_secret;

    Bytes acc = concat(ch_frame, sh_frame);
    Bytes th = transcript(acc);
    SessionKeys keys =
        derive_session_keys(ss_classical, ss_pq, ch.client_random, server_random, th);

    // --- 3. ServerAuth 송신 (트랜스크립트 서명) ---
    Bytes server_sig = dsa.sign(th, id.sig_secret);
    Bytes sa_frame = wire::serialize(wire::ServerAuth{server_sig});
    t.send_frame(sa_frame);

    // --- 4. ClientAuth 수신 → 클라 인증 ---
    Bytes ca_frame = t.recv_frame();
    wire::ClientAuth ca = wire::parse_client_auth(ca_frame);
    acc = concat(acc, sa_frame);
    Bytes th2 = transcript(acc);
    if (!dsa.verify(th2, ca.signature, id.peer_sig_public))
        throw HandshakeError("클라이언트 서명 검증 실패 (인증 실패)");

    // 서버 관점: 보낼 때 s2c, 받을 때 c2s
    return Channel{RecordSender(keys.s2c_key, keys.s2c_iv),
                   RecordReceiver(keys.c2s_key, keys.c2s_iv)};
}

} // namespace pqsec
