// crypto/examples/record_demo.cpp
//
// AES-256-GCM record layer 검증:
//   - 정상 왕복 (여러 레코드, 순서대로)
//   - 변조된 레코드 거부 (태그 검증 실패)
//   - 재정렬/재전송 거부 (seq 어긋나면 nonce 불일치 → 실패)

#include "pqsec/record.h"

#include <oqs/oqs.h>

#include <cstdio>
#include <string>

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
static Bytes str_bytes(const std::string &s) { return Bytes(s.begin(), s.end()); }

int main() {
    Bytes key = random_bytes(kAesKeyLen);
    Bytes iv = random_bytes(kIvLen);

    printf("[1] 정상 왕복 (순서대로)\n");
    {
        RecordSender tx(key, iv);
        RecordReceiver rx(key, iv);
        const char *msgs[] = {"first event", "second event", "third — longer payload …"};
        bool all_ok = true;
        for (const char *m : msgs) {
            Bytes pt = str_bytes(m);
            Bytes rec = tx.seal(pt);
            Bytes got = rx.open(rec);
            if (got != pt)
                all_ok = false;
        }
        check(all_ok, "3개 레코드 seal→open 평문 일치");
    }

    printf("[2] 변조 거부\n");
    {
        RecordSender tx(key, iv);
        RecordReceiver rx(key, iv);
        Bytes rec = tx.seal(str_bytes("sensitive"));
        rec[rec.size() - 1] ^= 0x01; // 태그 한 비트 변조
        bool threw = false;
        try {
            rx.open(rec);
        } catch (const RecordError &) {
            threw = true;
        }
        check(threw, "변조된 레코드 open 시 RecordError");
    }

    printf("[3] 재정렬 거부\n");
    {
        RecordSender tx(key, iv);
        RecordReceiver rx(key, iv);
        Bytes r0 = tx.seal(str_bytes("rec0"));
        Bytes r1 = tx.seal(str_bytes("rec1"));
        bool threw = false;
        try {
            rx.open(r1); // 0번을 건너뛰고 1번 먼저 → seq 불일치
        } catch (const RecordError &) {
            threw = true;
        }
        check(threw, "순서 어긋난 레코드 거부");
    }

    printf("[4] 재전송 거부\n");
    {
        RecordSender tx(key, iv);
        RecordReceiver rx(key, iv);
        Bytes r0 = tx.seal(str_bytes("once"));
        rx.open(r0); // 정상 소비 (seq 0)
        bool threw = false;
        try {
            rx.open(r0); // 같은 레코드 재전송 → 수신기 seq 는 1 → nonce 불일치
        } catch (const RecordError &) {
            threw = true;
        }
        check(threw, "재전송된 레코드 거부");
    }

    OQS_MEM_cleanse(key.data(), key.size());
    printf("\n%s (실패 %d건)\n", g_fail == 0 ? "[PASS] 전체 통과" : "[FAIL]", g_fail);
    return g_fail == 0 ? 0 : 1;
}
