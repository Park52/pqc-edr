// analyzer/src/analyzer_selftest.cpp
//
// 분류 파이프라인을 합성 이벤트로 검증 (오프라인, MockLlmClient).
// prefilter Drop/Alert/Escalate 분기와 Haiku→Sonnet 티어링이 의도대로 도는지 확인.

#include "llm_client.h"
#include "pipeline.h"

#include "event.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

using namespace pqsec::analyzer;

static security_event make_execve(const char *comm, const char *file) {
    security_event ev{};
    ev.type = PQSEC_EVT_EXECVE;
    ev.pid = 1234;
    std::strncpy(ev.comm, comm, sizeof(ev.comm) - 1);
    std::strncpy(ev.u.execve.filename, file, sizeof(ev.u.execve.filename) - 1);
    return ev;
}

static security_event make_tcp(const char *comm, const char *ip, uint16_t port) {
    security_event ev{};
    ev.type = PQSEC_EVT_TCP_CONNECT;
    ev.pid = 1234;
    std::strncpy(ev.comm, comm, sizeof(ev.comm) - 1);
    ev.u.tcp.family = 2; // AF_INET
    inet_pton(AF_INET, ip, &ev.u.tcp.daddr);
    ev.u.tcp.dport = port;
    return ev;
}

int main() {
    MockLlmClient llm;

    security_event events[] = {
        make_execve("bash", "/usr/bin/ls"),            // Drop (화이트리스트)
        make_execve("bash", "/tmp/xmrig"),             // Alert (rule: tmp 실행)
        make_execve("bash", "/usr/bin/nc"),            // Alert (rule: 네트워크 툴)
        make_execve("bash", "/usr/bin/curl"),          // Escalate → Haiku 의심 → Sonnet
        make_execve("bash", "/usr/local/bin/myapp"),   // Escalate → Haiku normal
        make_tcp("app", "10.0.0.5", 443),              // Drop (사설)
        make_tcp("curl", "185.220.101.1", 443),        // Escalate → Haiku(=curl 없음)→normal
        make_tcp("beacon", "45.9.148.99", 4444),       // Alert (rule: 비표준 포트)
    };

    printf("=== 분류 파이프라인 셀프테스트 (mock LLM) ===\n");
    printf("(JSON 로그=stdout, 사람요약=stderr)\n\n");
    for (const security_event &ev : events)
        process_event(ev, llm);

    printf("\n[done] 위 이벤트들을 prefilter→Haiku→Sonnet 로 처리 완료.\n");
    return 0;
}
