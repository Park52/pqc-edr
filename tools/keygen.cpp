// tools/keygen.cpp — ML-DSA 신원 키쌍 생성 (프로비저닝)
//
//   pqsec_keygen <prefix>  →  <prefix>.pub (공개키), <prefix>.key (개인키, 0600)
//
// 사용 예: agent 와 analyzer 신원을 만들고 서로의 .pub 을 배포한다.
//   pqsec_keygen agent
//   pqsec_keygen analyzer
//   # agent    는 agent.key   + analyzer.pub 를 로드
//   # analyzer 는 analyzer.key + agent.pub    를 로드

#include "pqsec/identity.h"

#include <cstdio>
#include <exception>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr,
                "사용법: %s <prefix>\n"
                "  → <prefix>.pub (ML-DSA-65 공개키), <prefix>.key (개인키, 0600)\n",
                argv[0]);
        return 1;
    }
    try {
        pqsec::generate_identity_files(argv[1]);
    } catch (const std::exception &e) {
        fprintf(stderr, "keygen 실패: %s\n", e.what());
        return 1;
    }
    printf("생성 완료: %s.pub, %s.key (ML-DSA-65 신원)\n", argv[1], argv[1]);
    return 0;
}
