// crypto/examples/mlkem_demo.cpp
//
// ML-KEM(Kyber) KEM API 최소 예제 — Week 2 첫 체크박스.
// KEM 3단계 흐름을 손에 익히는 목적:
//
//   [수신자] keypair()            → (public_key, secret_key)
//   [송신자] encaps(public_key)   → (ciphertext, shared_secret_A)   ← 랜덤 대칭키를 "캡슐화"
//   [수신자] decaps(ciphertext)   → shared_secret_B                 ← 자기 개인키로 "까기"
//
// 성공 = shared_secret_A == shared_secret_B (양쪽이 같은 세션키 비밀을 공유).
// 이 공유비밀은 raw 이므로 실제로는 HKDF 를 태워 세션키로 유도한다(다음 태스크).

#include <oqs/oqs.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

// 16진 앞부분만 짧게 출력 (디버그/확인용)
static void print_hex_prefix(const char *label, const uint8_t *buf, size_t len, size_t show = 8)
{
    printf("  %-16s (%zu bytes) ", label, len);
    for (size_t i = 0; i < show && i < len; ++i)
        printf("%02x", buf[i]);
    printf("...\n");
}

int main()
{
    const char *alg = OQS_KEM_alg_ml_kem_768;

    OQS_KEM *kem = OQS_KEM_new(alg);
    if (kem == nullptr) {
        // fail-closed: 알고리즘 미지원이면 조용히 넘어가지 않고 즉시 실패
        fprintf(stderr, "OQS_KEM_new(%s) 실패 — 이 빌드에 알고리즘이 없음\n", alg);
        return 1;
    }

    printf("KEM: %s\n", kem->method_name);
    printf("  claimed NIST level : %d\n", kem->claimed_nist_level);
    printf("  IND-CCA            : %s\n", kem->ind_cca ? "yes" : "no");
    printf("  public key         : %zu bytes\n", kem->length_public_key);
    printf("  secret key         : %zu bytes\n", kem->length_secret_key);
    printf("  ciphertext         : %zu bytes\n", kem->length_ciphertext);
    printf("  shared secret      : %zu bytes\n\n", kem->length_shared_secret);

    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_enc(kem->length_shared_secret); // 송신자
    std::vector<uint8_t> shared_secret_dec(kem->length_shared_secret); // 수신자

    int rc = 1;

    // ① [수신자] 키쌍 생성
    if (OQS_KEM_keypair(kem, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_KEM_keypair 실패\n");
        goto cleanup;
    }
    // ② [송신자] 공개키로 캡슐화 → ciphertext + 공유비밀
    if (OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_enc.data(),
                       public_key.data()) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_KEM_encaps 실패\n");
        goto cleanup;
    }
    // ③ [수신자] 개인키로 복호화(decapsulate) → 공유비밀
    if (OQS_KEM_decaps(kem, shared_secret_dec.data(), ciphertext.data(),
                       secret_key.data()) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_KEM_decaps 실패\n");
        goto cleanup;
    }

    print_hex_prefix("public_key", public_key.data(), public_key.size());
    print_hex_prefix("ciphertext", ciphertext.data(), ciphertext.size());
    print_hex_prefix("secret(send)", shared_secret_enc.data(), shared_secret_enc.size());
    print_hex_prefix("secret(recv)", shared_secret_dec.data(), shared_secret_dec.size());

    // 두 공유비밀이 일치해야 성공 (상수시간 비교)
    if (memcmp(shared_secret_enc.data(), shared_secret_dec.data(),
               kem->length_shared_secret) == 0) {
        printf("\n[OK] 양쪽 공유비밀 일치 — KEM 왕복 성공\n");
        rc = 0;
    } else {
        printf("\n[FAIL] 공유비밀 불일치\n");
        rc = 1;
    }

cleanup:
    // 비밀 자료는 메모리에서 지운다
    OQS_MEM_cleanse(secret_key.data(), secret_key.size());
    OQS_MEM_cleanse(shared_secret_enc.data(), shared_secret_enc.size());
    OQS_MEM_cleanse(shared_secret_dec.data(), shared_secret_dec.size());
    OQS_KEM_free(kem);
    return rc;
}
