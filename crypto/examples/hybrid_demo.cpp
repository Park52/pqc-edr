// crypto/examples/hybrid_demo.cpp
//
// 하이브리드 핸드셰이크 크립토 전 구간을 한 프로세스 안에서 양측 역할로 시뮬레이션.
// (소켓 전송·record layer 는 이후 태스크. 여기선 키합의 + 상호인증의 정확성 증명.)
//
//   1. ClientHello / ServerHello 로 X25519 ‖ ML-KEM 교환
//   2. 양측이 독립적으로 하이브리드 세션키 유도 → 일치 확인
//   3. ML-DSA 로 트랜스크립트 상호서명 → 사전보유 공개키로 검증 (인증)

#include "pqsec/kdf.h"
#include "pqsec/pqc.h"
#include "pqsec/session.h"
#include "pqsec/wire.h"
#include "pqsec/x25519.h"

#include <oqs/oqs.h>

#include <cstdio>

using namespace pqsec;

static int g_fail = 0;
static void check(bool cond, const char *what) {
    printf("  [%s] %s\n", cond ? "OK" : "FAIL", what);
    if (!cond)
        ++g_fail;
}
static Bytes random_bytes(size_t n) {
    Bytes b(n);
    OQS_randombytes(b.data(), n);
    return b;
}
static Bytes concat(const Bytes &a, const Bytes &b) {
    Bytes o = a;
    o.insert(o.end(), b.begin(), b.end());
    return o;
}

int main() {
    MlKem kem;
    MlDsa dsa;

    // === 사전 프로비저닝: 장기 ML-DSA 신원키 (상대 공개키를 서로 안다) ===
    KeyPair server_id = dsa.keypair();
    KeyPair client_id = dsa.keypair();
    // (실제로는 아웃오브밴드 배포. 여기선 서로의 public_key 를 아는 것으로 간주)

    printf("스위트: %s + X25519 + %s + HKDF-SHA256\n\n", kem.name(), dsa.name());

    // ========== 클라이언트(agent): ClientHello 준비 ==========
    Bytes client_random = random_bytes(wire::kRandomLen);
    X25519 x_client;                          // 임시 X25519
    KeyPair kem_client = kem.keypair();        // 임시 ML-KEM (클라=수신자)

    wire::ClientHello ch;
    ch.client_random = client_random;
    ch.x25519_pub = x_client.public_key();
    ch.mlkem_pub = kem_client.public_key;
    Bytes ch_frame = wire::serialize(ch);

    // ========== 서버(analyzer): ClientHello 수신 → ServerHello ==========
    wire::ClientHello ch_recv = wire::parse_client_hello(ch_frame);
    Bytes server_random = random_bytes(wire::kRandomLen);
    X25519 x_server;
    auto enc = kem.encaps(ch_recv.mlkem_pub);  // 서버=송신자 → ct + ss_pq

    wire::ServerHello sh;
    sh.server_random = server_random;
    sh.x25519_pub = x_server.public_key();
    sh.mlkem_ct = enc.ciphertext;
    Bytes sh_frame = wire::serialize(sh);

    // 서버측 공유비밀 & 세션키
    Bytes ss_classical_srv = x_server.compute_shared(ch_recv.x25519_pub);
    Bytes ss_pq_srv = enc.shared_secret;
    Bytes th = sha256(concat(ch_frame, sh_frame));   // 트랜스크립트 해시
    SessionKeys keys_srv =
        derive_session_keys(ss_classical_srv, ss_pq_srv, client_random, server_random, th);

    // ========== 클라이언트: ServerHello 수신 → 세션키 ==========
    wire::ServerHello sh_recv = wire::parse_server_hello(sh_frame);
    Bytes ss_classical_cli = x_client.compute_shared(sh_recv.x25519_pub);
    Bytes ss_pq_cli = kem.decaps(sh_recv.mlkem_ct, kem_client.secret_key);
    Bytes th_cli = sha256(concat(ch_frame, sh_frame));
    SessionKeys keys_cli =
        derive_session_keys(ss_classical_cli, ss_pq_cli, client_random, server_random, th_cli);

    // === 검증 1: 하이브리드 세션키 일치 ===
    printf("[1] 하이브리드 키합의\n");
    check(ss_classical_cli == ss_classical_srv, "X25519 공유비밀 일치");
    check(ss_pq_cli == ss_pq_srv, "ML-KEM 공유비밀 일치");
    check(keys_cli.c2s_key == keys_srv.c2s_key && keys_cli.s2c_key == keys_srv.s2c_key,
          "방향별 세션키 일치 (c2s/s2c)");
    check(keys_cli.c2s_iv == keys_srv.c2s_iv && keys_cli.s2c_iv == keys_srv.s2c_iv,
          "IV base 일치");
    check(keys_cli.c2s_key != keys_cli.s2c_key, "방향별 키가 서로 다름 (분리)");

    // === 검증 2: ML-DSA 상호인증 (트랜스크립트 서명) ===
    printf("[2] ML-DSA 상호인증\n");
    // 서버가 먼저 인증: H(CH ‖ SH) 에 서명
    Bytes server_sig = dsa.sign(th, server_id.secret_key);
    check(dsa.verify(th, server_sig, server_id.public_key), "클라가 서버 서명 검증(서버 인증)");

    // 클라 인증: H(CH ‖ SH ‖ ServerAuth) 에 서명
    Bytes th2 = sha256(concat(concat(ch_frame, sh_frame),
                              wire::serialize(wire::ServerAuth{server_sig})));
    Bytes client_sig = dsa.sign(th2, client_id.secret_key);
    check(dsa.verify(th2, client_sig, client_id.public_key), "서버가 클라 서명 검증(클라 인증)");

    // MITM 시뮬레이션: 중간자가 서버 X25519 공개키를 바꿔치기 → 트랜스크립트 달라짐 → 서명 검증 실패
    Bytes th_tampered = th;
    th_tampered[5] ^= 0x01;
    check(!dsa.verify(th_tampered, server_sig, server_id.public_key),
          "변조된 트랜스크립트 서명 거부 (MITM 방어)");

    printf("\n핸드셰이크 총 바이트: ClientHello=%zu, ServerHello=%zu, 서명2개=%zu → 합 %zu B\n",
           ch_frame.size(), sh_frame.size(), server_sig.size() + client_sig.size(),
           ch_frame.size() + sh_frame.size() + server_sig.size() + client_sig.size());

    // 정리
    OQS_MEM_cleanse(kem_client.secret_key.data(), kem_client.secret_key.size());
    OQS_MEM_cleanse(server_id.secret_key.data(), server_id.secret_key.size());
    OQS_MEM_cleanse(client_id.secret_key.data(), client_id.secret_key.size());

    printf("\n%s (실패 %d건)\n", g_fail == 0 ? "[PASS] 전체 통과" : "[FAIL]", g_fail);
    return g_fail == 0 ? 0 : 1;
}
