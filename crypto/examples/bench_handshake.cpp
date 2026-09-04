// crypto/examples/bench_handshake.cpp
//
// 벤치마크 — PQC 하이브리드 채널의 비용을 수치로 (docs/BENCHMARK.md 의 근거).
//   1. 프리미티브 단위 지연 (µs; median / p90): X25519, ML-KEM-768, ML-DSA-65,
//      Ed25519(고전 인증 비교용), AES-256-GCM 레코드(168B 이벤트)
//   2. 전체 핸드셰이크: 인메모리 transport + 2 스레드로 client/server 실행, 지연·와이어 바이트 실측
//   3. 비교표: 고전 전용(X25519 + Ed25519) vs 하이브리드(X25519 ‖ ML-KEM-768 + ML-DSA-65)
//
// 정직성 주의: 고전 전용 핸드셰이크는 구현하지 않았다(범위 밖). 그 열은 같은 4-메시지 흐름을
// 가정하고 프리미티브 실측치를 합산한 *추정치*다. 표에 그렇게 표기한다.

#include "pqsec/handshake.h"
#include "pqsec/pqc.h"
#include "pqsec/record.h"
#include "pqsec/x25519.h"

#include <openssl/evp.h>
#include <oqs/oqs.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace pqsec;
using Clock = std::chrono::steady_clock;

// ---- 통계 ------------------------------------------------------------------
struct Stats {
    double median = 0, p90 = 0, mean = 0;
};
static Stats stats(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    Stats s;
    s.median = v[v.size() / 2];
    s.p90 = v[v.size() * 9 / 10];
    for (double x : v) s.mean += x;
    s.mean /= static_cast<double>(v.size());
    return s;
}
template <class F> static Stats bench(int iters, F &&fn) {
    std::vector<double> us;
    us.reserve(static_cast<size_t>(iters));
    for (int i = 0; i < iters; ++i) {
        auto t0 = Clock::now();
        fn();
        auto t1 = Clock::now();
        us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
    }
    return stats(us);
}
static Bytes random_bytes(size_t n) {
    Bytes b(n);
    OQS_randombytes(b.data(), n);
    return b;
}

// ---- Ed25519 (OpenSSL) — 고전 인증 비교용 -----------------------------------
struct Ed25519 {
    EVP_PKEY *pkey = nullptr;
    Ed25519() {
        pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
        if (!pkey) throw std::runtime_error("Ed25519 keygen 실패");
    }
    ~Ed25519() { EVP_PKEY_free(pkey); }
    Bytes sign(const Bytes &msg) const {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        size_t len = 0;
        if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1 ||
            EVP_DigestSign(ctx, nullptr, &len, msg.data(), msg.size()) != 1)
            throw std::runtime_error("Ed25519 sign 실패");
        Bytes sig(len);
        if (EVP_DigestSign(ctx, sig.data(), &len, msg.data(), msg.size()) != 1)
            throw std::runtime_error("Ed25519 sign 실패");
        EVP_MD_CTX_free(ctx);
        sig.resize(len);
        return sig;
    }
    bool verify(const Bytes &msg, const Bytes &sig) const {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
                  EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size()) == 1;
        EVP_MD_CTX_free(ctx);
        return ok;
    }
};

// ---- 인메모리 transport (2 스레드) ------------------------------------------
struct Pipe {
    std::mutex m;
    std::condition_variable cv;
    std::deque<Bytes> q;
    void push(const Bytes &b) {
        { std::lock_guard<std::mutex> lk(m); q.push_back(b); }
        cv.notify_one();
    }
    Bytes pop() {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [&] { return !q.empty(); });
        Bytes b = std::move(q.front());
        q.pop_front();
        return b;
    }
};
struct HandshakeRun {
    double client_us;
    size_t c2s_bytes, s2c_bytes;
};
static HandshakeRun run_handshake(const Identity &cid, const Identity &sid) {
    Pipe c2s, s2c;
    size_t nc = 0, ns = 0;
    Transport tc{[&](const Bytes &f) { nc += f.size(); c2s.push(f); }, [&] { return s2c.pop(); }};
    Transport ts{[&](const Bytes &f) { ns += f.size(); s2c.push(f); }, [&] { return c2s.pop(); }};
    std::thread srv([&] { server_handshake(sid, ts); });
    auto t0 = Clock::now();
    Channel ch = client_handshake(cid, tc);
    auto t1 = Clock::now();
    srv.join();
    (void)ch;
    return {std::chrono::duration<double, std::micro>(t1 - t0).count(), nc, ns};
}

static std::string cpu_model() {
    std::ifstream f("/proc/cpuinfo");
    std::string line;
    while (std::getline(f, line))
        if (line.rfind("model name", 0) == 0) return line.substr(line.find(':') + 2);
    return "unknown";
}

int main() {
    MlKem kem;
    MlDsa dsa;
    const Bytes msg32 = random_bytes(32); // 서명 대상 = 트랜스크립트 해시(32B)

    printf("# PQC 하이브리드 채널 벤치마크\n\n");
    printf("- CPU: %s\n- 빌드: %s\n- 스위트: %s + X25519 + %s + HKDF-SHA256 + AES-256-GCM\n\n",
           cpu_model().c_str(),
#ifdef NDEBUG
           "Release",
#else
           "Debug (최적화 없음 — Release 로 다시 재면 더 빠름)",
#endif
           kem.name(), dsa.name());

    // ===== 1. 프리미티브 =====
    const int N = 300;
    X25519 x_peer;
    const Bytes x_peer_pub = x_peer.public_key();
    Stats x_keygen = bench(N, [&] { X25519 x; (void)x; });
    X25519 x_me;
    Stats x_shared = bench(N, [&] { x_me.compute_shared(x_peer_pub); });

    KeyPair kem_kp = kem.keypair();
    Stats kem_keygen = bench(N, [&] { kem.keypair(); });
    Stats kem_encaps = bench(N, [&] { kem.encaps(kem_kp.public_key); });
    MlKem::EncapsResult enc = kem.encaps(kem_kp.public_key);
    Stats kem_decaps = bench(N, [&] { kem.decaps(enc.ciphertext, kem_kp.secret_key); });

    KeyPair dsa_kp = dsa.keypair();
    Stats dsa_keygen = bench(50, [&] { dsa.keypair(); });
    Stats dsa_sign = bench(N, [&] { dsa.sign(msg32, dsa_kp.secret_key); });
    const Bytes dsa_sig = dsa.sign(msg32, dsa_kp.secret_key);
    Stats dsa_verify = bench(N, [&] { dsa.verify(msg32, dsa_sig, dsa_kp.public_key); });

    Ed25519 ed;
    Stats ed_keygen = bench(N, [&] { Ed25519 e; (void)e; });
    Stats ed_sign = bench(N, [&] { ed.sign(msg32); });
    const Bytes ed_sig = ed.sign(msg32);
    Stats ed_verify = bench(N, [&] { ed.verify(msg32, ed_sig); });

    const Bytes key = random_bytes(kAesKeyLen), iv = random_bytes(kIvLen);
    RecordSender snd(key, iv);
    RecordReceiver rcv(key, iv);
    const Bytes event(168, 0xAB); // sizeof(security_event)
    Stats rec_seal = bench(2000, [&] { snd.seal(event); });
    RecordSender snd2(key, iv);
    Stats rec_open = bench(2000, [&] { rcv.open(snd2.seal(event)); }); // seal+open 왕복

    printf("## 1. 프리미티브 지연 (µs, N=%d)\n\n", N);
    printf("| 연산 | median | p90 | 크기 |\n|---|---:|---:|---|\n");
    auto row = [](const char *name, const Stats &s, const std::string &size) {
        printf("| %s | %.1f | %.1f | %s |\n", name, s.median, s.p90, size.c_str());
    };
    row("X25519 keygen", x_keygen, "pub 32B");
    row("X25519 shared", x_shared, "ss 32B");
    row("ML-KEM-768 keygen", kem_keygen, "pub " + std::to_string(kem.public_key_len()) + "B");
    row("ML-KEM-768 encaps", kem_encaps, "ct " + std::to_string(kem.ciphertext_len()) + "B");
    row("ML-KEM-768 decaps", kem_decaps, "ss 32B");
    row("Ed25519 keygen", ed_keygen, "pub 32B");
    row("Ed25519 sign", ed_sign, "sig " + std::to_string(ed_sig.size()) + "B");
    row("Ed25519 verify", ed_verify, "");
    row("ML-DSA-65 keygen", dsa_keygen, "pub " + std::to_string(dsa.public_key_len()) + "B");
    row("ML-DSA-65 sign", dsa_sign, "sig " + std::to_string(dsa_sig.size()) + "B");
    row("ML-DSA-65 verify", dsa_verify, "");
    row("AES-256-GCM seal (168B 이벤트)", rec_seal, "+2B 헤더 +16B 태그");
    row("AES-256-GCM seal+open 왕복", rec_open, "");

    // ===== 2. 전체 핸드셰이크 =====
    KeyPair cid_kp = dsa.keypair(), sid_kp = dsa.keypair();
    Identity cid{cid_kp.public_key, cid_kp.secret_key, sid_kp.public_key};
    Identity sid{sid_kp.public_key, sid_kp.secret_key, cid_kp.public_key};
    run_handshake(cid, sid); // 워밍업
    const int H = 100;
    std::vector<double> hs;
    size_t c2s = 0, s2c = 0;
    for (int i = 0; i < H; ++i) {
        HandshakeRun r = run_handshake(cid, sid);
        hs.push_back(r.client_us);
        c2s = r.c2s_bytes;
        s2c = r.s2c_bytes;
    }
    Stats hs_stats = stats(hs);
    printf("\n## 2. 전체 핸드셰이크 실측 (인메모리 transport, N=%d)\n\n", H);
    printf("| 항목 | 값 |\n|---|---:|\n");
    printf("| 클라이언트 관점 지연 median | %.2f ms |\n", hs_stats.median / 1000);
    printf("| 클라이언트 관점 지연 p90 | %.2f ms |\n", hs_stats.p90 / 1000);
    printf("| 와이어 바이트 (agent→analyzer) | %zu B |\n", c2s);
    printf("| 와이어 바이트 (analyzer→agent) | %zu B |\n", s2c);
    printf("| 와이어 바이트 합계 | %zu B |\n", c2s + s2c);
    printf("\n(스레드 전환·프레이밍 포함. 네트워크 RTT 제외 — 실제 링크에선 2-RTT 가 더해진다.)\n");

    // ===== 3. 고전 vs 하이브리드 비교 =====
    // 4-메시지 흐름 기준, 양측 CPU 합산. 키교환: keygen×2 + shared×2 (+ ML-KEM keygen/encaps/decaps).
    // 인증: sign×2 + verify×2.
    const double kex_classic = 2 * x_keygen.median + 2 * x_shared.median;
    const double kex_hybrid = kex_classic + kem_keygen.median + kem_encaps.median + kem_decaps.median;
    const double auth_classic = 2 * ed_sign.median + 2 * ed_verify.median;
    const double auth_pq = 2 * dsa_sign.median + 2 * dsa_verify.median;
    const size_t kex_bytes_classic = 32 + 32;
    const size_t kex_bytes_hybrid = 32 + kem.public_key_len() + 32 + kem.ciphertext_len();
    const size_t auth_bytes_classic = 2 * ed_sig.size();
    const size_t auth_bytes_pq = 2 * dsa_sig.size();

    printf("\n## 3. 고전 전용 vs 하이브리드 (양측 CPU 합산, median 기준)\n\n");
    printf("| | 고전 전용 (X25519 + Ed25519) *추정* | 하이브리드 (X25519‖ML-KEM-768 + ML-DSA-65) *실측 프리미티브 합산* | 배수 |\n");
    printf("|---|---:|---:|---:|\n");
    printf("| 키교환 CPU | %.1f µs | %.1f µs | ×%.1f |\n", kex_classic, kex_hybrid, kex_hybrid / kex_classic);
    printf("| 인증 CPU (서명2+검증2) | %.1f µs | %.1f µs | ×%.1f |\n", auth_classic, auth_pq, auth_pq / auth_classic);
    printf("| 핸드셰이크 CPU 합계 | %.1f µs | %.1f µs | ×%.1f |\n", kex_classic + auth_classic,
           kex_hybrid + auth_pq, (kex_hybrid + auth_pq) / (kex_classic + auth_classic));
    printf("| 키교환 바이트 | %zu B | %zu B | ×%.1f |\n", kex_bytes_classic, kex_bytes_hybrid,
           static_cast<double>(kex_bytes_hybrid) / kex_bytes_classic);
    printf("| 인증 바이트 (서명 2개) | %zu B | %zu B | ×%.1f |\n", auth_bytes_classic, auth_bytes_pq,
           static_cast<double>(auth_bytes_pq) / auth_bytes_classic);
    printf("| 핸드셰이크 바이트 합계 (페이로드) | %zu B | %zu B | ×%.1f |\n",
           kex_bytes_classic + auth_bytes_classic, kex_bytes_hybrid + auth_bytes_pq,
           static_cast<double>(kex_bytes_hybrid + auth_bytes_pq) / (kex_bytes_classic + auth_bytes_classic));
    printf("\n*고전 전용 열은 미구현 — 같은 4-메시지 흐름을 가정한 프리미티브 합산 추정. "
           "하이브리드 열도 프리미티브 합산이며, 실측 전체 핸드셰이크(§2)와 비교하면 "
           "직렬화·HKDF·스레드 전환 오버헤드를 볼 수 있다.*\n");
    printf("\n요약: 핸드셰이크 1회당 추가 비용은 CPU 수백 µs·와이어 수 KB 수준으로, "
           "세션당 1회 지불하고 이후 레코드(AES-GCM)는 동일 비용이다.\n");
    return 0;
}
