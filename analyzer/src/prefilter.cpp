// analyzer/src/prefilter.cpp — 룰 기반 1차 필터

#include "prefilter.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>

namespace pqsec::analyzer {

namespace {

// 읽기 위주의 흔한 시스템/파일 도구 — 명백 정상으로 간주(화이트리스트)
const std::set<std::string> kBenignBins = {
    "ls",  "cat", "grep", "ps",   "id",   "whoami", "which", "uname", "wc",
    "head","tail","sed",  "awk",  "dirname","basename","env","date", "sleep",
    "git", "cmake","make", "cc",  "gcc",  "g++",   "clang", "ld",    "node",
    "rm",  "mkdir","mktemp","cp", "mv",   "touch", "chmod", "getcap",
};

// 리버스셸·다운로더 등에 흔히 쓰이는 바이너리 — 명백 악성 신호
const std::set<std::string> kMaliciousBins = {
    "nc", "ncat", "netcat", "socat",
};

PrefilterResult prefilter_execve(const security_event &ev) {
    std::string bin = basename_of(ev.u.execve.filename);
    std::string path = ev.u.execve.filename;

    // 명백 악성: 임시 디렉토리에서 실행 or 알려진 툴
    if (path.rfind("/tmp/", 0) == 0 || path.rfind("/dev/shm/", 0) == 0)
        return {PrefilterDecision::Alert, Severity::High, "임시 디렉토리에서 실행"};
    if (kMaliciousBins.count(bin))
        return {PrefilterDecision::Alert, Severity::High, "리버스셸/네트워크 툴 실행: " + bin};

    // 명백 정상: 화이트리스트 도구
    if (kBenignBins.count(bin))
        return {PrefilterDecision::Drop, Severity::Info, "화이트리스트 도구: " + bin};

    // 애매 → LLM
    return {PrefilterDecision::Escalate, Severity::Info, "미분류 실행: " + bin};
}

PrefilterResult prefilter_tcp(const security_event &ev) {
    if (is_private_ipv4(ev.u.tcp.daddr))
        return {PrefilterDecision::Drop, Severity::Info, "사설/루프백 대역 접속"};

    uint16_t dport = ev.u.tcp.dport;
    // 공인 IP: 흔한 웹/DNS 포트는 애매(정상적 트래픽일 수도, 유출일 수도) → LLM
    if (dport == 443 || dport == 80 || dport == 53)
        return {PrefilterDecision::Escalate, Severity::Info, "공인 IP 표준 포트 아웃바운드"};

    // 그 외 포트로의 공인 아웃바운드 → 의심 (즉시 alert)
    return {PrefilterDecision::Alert, Severity::Medium, "공인 IP 비표준 포트 아웃바운드"};
}

} // namespace

std::string basename_of(const char *path) {
    const char *slash = std::strrchr(path, '/');
    return slash ? std::string(slash + 1) : std::string(path);
}

bool is_private_ipv4(uint32_t daddr_net) {
    uint8_t o0 = daddr_net & 0xff;
    uint8_t o1 = (daddr_net >> 8) & 0xff;
    if (o0 == 10) return true;                          // 10.0.0.0/8
    if (o0 == 127) return true;                         // 127.0.0.0/8 loopback
    if (o0 == 192 && o1 == 168) return true;            // 192.168.0.0/16
    if (o0 == 172 && o1 >= 16 && o1 <= 31) return true; // 172.16.0.0/12
    return false;
}

PrefilterResult prefilter(const security_event &ev) {
    switch (ev.type) {
    case PQSEC_EVT_EXECVE:      return prefilter_execve(ev);
    case PQSEC_EVT_TCP_CONNECT: return prefilter_tcp(ev);
    default:
        return {PrefilterDecision::Escalate, Severity::Info, "알 수 없는 이벤트 타입"};
    }
}

std::string event_summary(const security_event &ev) {
    char buf[256];
    if (ev.type == PQSEC_EVT_EXECVE) {
        std::snprintf(buf, sizeof(buf), "execve comm=%s file=%s", ev.comm,
                      ev.u.execve.filename);
    } else if (ev.type == PQSEC_EVT_TCP_CONNECT) {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ev.u.tcp.daddr, ip, sizeof(ip));
        std::snprintf(buf, sizeof(buf), "connect comm=%s dst=%s:%u", ev.comm, ip,
                      ev.u.tcp.dport);
    } else {
        std::snprintf(buf, sizeof(buf), "unknown type=%u", ev.type);
    }
    return std::string(buf);
}

} // namespace pqsec::analyzer
