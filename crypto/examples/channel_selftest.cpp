// crypto/examples/channel_selftest.cpp
//
// OpenSSL 없이 되는 부분의 셀프테스트:
//   - ML-KEM 왕복 (공유비밀 일치)
//   - ML-DSA 서명/검증 + 위조/키불일치 거부 (fail-closed)
//   - 와이어 포맷 직렬화↔파싱 왕복 + 잘린 프레임 거부
//
// (X25519·HKDF·GCM 은 libssl-dev 설치 후 하이브리드 KEM 단계에서 결합)

#include "pqsec/pqc.h"
#include "pqsec/wire.h"

#include <oqs/oqs.h>

#include <cstdio>
#include <cstdlib>

using namespace pqsec;

static int g_failures = 0;

static void check(bool cond, const char *what) {
    printf("  [%s] %s\n", cond ? "OK" : "FAIL", what);
    if (!cond)
        ++g_failures;
}

static Bytes random_bytes(size_t n) {
    Bytes b(n);
    OQS_randombytes(b.data(), n);
    return b;
}

int main() {
    MlKem kem;
    MlDsa dsa;
    printf("스위트: %s + %s\n\n", kem.name(), dsa.name());

    // --- 1. ML-KEM 왕복 ---
    printf("[1] ML-KEM 왕복\n");
    KeyPair kem_kp = kem.keypair(); // 클라이언트(수신자)
    auto enc = kem.encaps(kem_kp.public_key); // 서버(송신자)
    Bytes ss_client = kem.decaps(enc.ciphertext, kem_kp.secret_key);
    check(enc.shared_secret == ss_client, "encaps/decaps 공유비밀 일치");

    // --- 2. ML-DSA 상호인증 프리미티브 ---
    printf("[2] ML-DSA 서명/검증\n");
    KeyPair server_id = dsa.keypair(); // 서버 장기 신원키
    KeyPair client_id = dsa.keypair(); // 클라 장기 신원키
    Bytes transcript = random_bytes(200); // 트랜스크립트 스탠드인
    Bytes sig = dsa.sign(transcript, server_id.secret_key);
    check(dsa.verify(transcript, sig, server_id.public_key), "정상 서명 검증 통과");

    Bytes tampered = transcript;
    tampered[0] ^= 0x01; // 한 바이트 변조
    check(!dsa.verify(tampered, sig, server_id.public_key), "변조된 트랜스크립트 거부");
    check(!dsa.verify(transcript, sig, client_id.public_key), "다른 신원키로 검증 거부");

    // --- 3. 와이어 포맷 왕복 ---
    printf("[3] 와이어 직렬화/파싱\n");
    wire::ClientHello ch;
    ch.client_random = random_bytes(wire::kRandomLen);
    ch.x25519_pub = random_bytes(wire::kX25519Len); // 실제 X25519 는 이후 단계
    ch.mlkem_pub = kem_kp.public_key;
    Bytes ch_frame = wire::serialize(ch);
    wire::ClientHello ch2 = wire::parse_client_hello(ch_frame);
    check(ch2.client_random == ch.client_random && ch2.x25519_pub == ch.x25519_pub &&
              ch2.mlkem_pub == ch.mlkem_pub,
          "ClientHello 왕복 일치");

    wire::ServerHello sh;
    sh.server_random = random_bytes(wire::kRandomLen);
    sh.x25519_pub = random_bytes(wire::kX25519Len);
    sh.mlkem_ct = enc.ciphertext;
    Bytes sh_frame = wire::serialize(sh);
    wire::ServerHello sh2 = wire::parse_server_hello(sh_frame);
    check(sh2.server_random == sh.server_random && sh2.mlkem_ct == sh.mlkem_ct,
          "ServerHello 왕복 일치");

    wire::ServerAuth sa{sig};
    wire::ServerAuth sa2 = wire::parse_server_auth(wire::serialize(sa));
    check(sa2.signature == sig, "ServerAuth 왕복 일치");

    check(wire::peek_type(ch_frame) == wire::MsgType::ClientHello, "peek_type 정확");

    // --- 4. 잘린 프레임 거부 (fail-closed) ---
    printf("[4] 잘린 프레임 거부\n");
    Bytes truncated(ch_frame.begin(), ch_frame.begin() + ch_frame.size() / 2);
    bool threw = false;
    try {
        wire::parse_client_hello(truncated);
    } catch (const wire::WireError &) {
        threw = true;
    }
    check(threw, "잘린 ClientHello 파싱 시 예외");

    // 정리
    OQS_MEM_cleanse(kem_kp.secret_key.data(), kem_kp.secret_key.size());
    OQS_MEM_cleanse(server_id.secret_key.data(), server_id.secret_key.size());
    OQS_MEM_cleanse(client_id.secret_key.data(), client_id.secret_key.size());

    printf("\n%s (실패 %d건)\n", g_failures == 0 ? "[PASS] 전체 통과" : "[FAIL]", g_failures);
    return g_failures == 0 ? 0 : 1;
}
