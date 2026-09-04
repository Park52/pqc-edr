// analyzer/src/analyzer_selftest.cpp
//
// 분류 파이프라인을 합성 이벤트로 검증 (오프라인, MockLlmClient).
// prefilter Drop/Alert/Escalate 분기, Haiku→Sonnet 티어링, 시퀀스 코릴레이션(체인·비콘)이
// 의도대로 도는지 확인.

#include "correlator.h"
#include "llm_client.h"
#include "pipeline.h"

#include "event.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

using namespace pqsec::analyzer;

static security_event make_execve(const char *comm, const char *file, uint32_t pid = 1234,
                                  uint32_t ppid = 1000) {
    security_event ev{};
    ev.type = PQSEC_EVT_EXECVE;
    ev.pid = pid;
    ev.ppid = ppid;
    std::strncpy(ev.comm, comm, sizeof(ev.comm) - 1);
    std::strncpy(ev.u.execve.filename, file, sizeof(ev.u.execve.filename) - 1);
    return ev;
}

static security_event make_tcp(const char *comm, const char *ip, uint16_t port,
                               uint32_t pid = 1234, uint32_t ppid = 1000) {
    security_event ev{};
    ev.type = PQSEC_EVT_TCP_CONNECT;
    ev.pid = pid;
    ev.ppid = ppid;
    std::strncpy(ev.comm, comm, sizeof(ev.comm) - 1);
    ev.u.tcp.family = 2; // AF_INET
    inet_pton(AF_INET, ip, &ev.u.tcp.daddr);
    ev.u.tcp.dport = port;
    return ev;
}

int main() {
    MockLlmClient llm;
    Correlator corr;

    security_event events[] = {
        // --- 단일 이벤트 룰 + LLM 티어링 ---
        make_execve("bash", "/usr/bin/ls"),            // Drop (화이트리스트)
        make_execve("bash", "/tmp/xmrig"),             // Alert (rule: tmp 실행)
        make_execve("bash", "/usr/bin/nc"),            // Alert (rule: 네트워크 툴)
        make_execve("bash", "/usr/bin/curl"),          // Escalate → Haiku 의심 → Sonnet
        make_execve("bash", "/usr/local/bin/myapp"),   // Escalate → Haiku normal
        make_tcp("app", "10.0.0.5", 443),              // Drop (사설)
        make_tcp("curl", "185.220.101.1", 443),        // Escalate → Haiku(=curl 없음)→normal
        make_tcp("beacon", "45.9.148.99", 4444),       // Alert (rule: 비표준 포트)

        // --- 시퀀스 코릴레이션 (Week 4) ---
        // C1: 같은 부모(ppid=7000)에서 curl 실행 → 임시경로 실행 = 다운로드→실행 체인
        make_execve("bash", "/usr/bin/curl", 7001, 7000),          // 다운로더 관찰
        make_execve("bash", "/tmp/.cache-x/sysupdate", 7002, 7000), // rule High + chain → Critical
        make_execve("bash", "/tmp/other", 7003, 8000),              // 다른 부모 → rule High 만
        // C2: 같은 공인 목적지로 3회 반복 = 비콘
        make_tcp("implant", "198.51.100.7", 4444, 7010, 7000),      // 1회: rule Medium
        make_tcp("implant", "198.51.100.7", 4444, 7010, 7000),      // 2회: rule Medium
        make_tcp("implant", "198.51.100.7", 4444, 7010, 7000),      // 3회: rule+beacon → High
        make_tcp("updater", "203.0.113.9", 443, 7020, 7000),        // 공인 443 1회 → Haiku normal
        make_tcp("updater", "203.0.113.9", 443, 7020, 7000),
        make_tcp("updater", "203.0.113.9", 443, 7020, 7000),        // 3회: beacon → Sonnet 직행
    };

    printf("=== 분류 파이프라인 셀프테스트 (mock LLM) ===\n");
    printf("(JSON 로그=stdout, 사람요약=stderr)\n\n");
    for (const security_event &ev : events)
        process_event(ev, llm, corr);

    printf("\n[done] 위 이벤트들을 prefilter+correlator → Haiku → Sonnet 로 처리 완료.\n");
    return 0;
}
