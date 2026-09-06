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
    // 아래는 탐지 평가(docs/EVAL.md)의 정상 코퍼스에서 LLM 오탐원으로 나와 추가 —
    // 빌드·읽기 위주 시스템 도구. (measure → tune → re-measure)
    "gmake", "ss", "ldconfig", "ctest", "dirname",
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

PrefilterResult prefilter_file(const security_event &ev) {
    // 민감파일 읽기(inode 매칭) → 즉시 High. 인자를 못 보던 사각지대(cat /etc/shadow)를 닫는다.
    if (ev.u.file.access & PQSEC_FA_SENSITIVE) {
        std::string what = ev.u.file.path[0] ? std::string(ev.u.file.path)
                                             : "ino=" + std::to_string(ev.u.file.ino);
        return {PrefilterDecision::Alert, Severity::High, "민감파일 접근: " + what};
    }
    // 스테이징 쓰기 자체는 정상 도구도 늘 한다 → Drop. 코릴레이터가 실행이 뒤따를 때만 체인으로.
    return {PrefilterDecision::Drop, Severity::Info, "스테이징 쓰기 (코릴레이션 맥락)"};
}

} // namespace

// 커널에서 온 comm/filename 은 신뢰할 수 없는 바이트열 — 제어문자(개행 등)를 '?' 로 바꿔
// 로그 줄 위조와 LLM 컨텍스트 오염을 소스에서 막는다. 길이는 스키마가 이미 제한(16B/128B).
std::string printable(const char *s, size_t max_len) {
    std::string out;
    for (size_t i = 0; i < max_len && s[i] != '\0'; ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        out += (c < 0x20 || c == 0x7f) ? '?' : static_cast<char>(c);
    }
    return out;
}

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
    case PQSEC_EVT_FILE_OPEN:   return prefilter_file(ev);
    default:
        return {PrefilterDecision::Escalate, Severity::Info, "알 수 없는 이벤트 타입"};
    }
}

// 프로세스 계보 문자열: comm<-parent<-... (조상이 있을 때만)
std::string process_tree(const security_event &ev) {
    std::string comm(ev.comm, strnlen(ev.comm, sizeof(ev.comm)));
    std::string t = comm.empty() ? "?" : comm;
    for (int i = 0; i < PQSEC_ANCESTORS; ++i) {
        if (ev.anc[i].pid == 0 && ev.anc[i].comm[0] == '\0')
            break;
        std::string ac(ev.anc[i].comm, strnlen(ev.anc[i].comm, sizeof(ev.anc[i].comm)));
        t += "<-" + (ac.empty() ? "?" : ac);
    }
    return t;
}

std::string event_summary(const security_event &ev) {
    char buf[256];
    const std::string comm = printable(ev.comm, sizeof(ev.comm));
    if (ev.type == PQSEC_EVT_EXECVE) {
        const std::string file = printable(ev.u.execve.filename, sizeof(ev.u.execve.filename));
        std::snprintf(buf, sizeof(buf), "execve comm=%s file=%s", comm.c_str(), file.c_str());
    } else if (ev.type == PQSEC_EVT_TCP_CONNECT) {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ev.u.tcp.daddr, ip, sizeof(ip));
        std::snprintf(buf, sizeof(buf), "connect comm=%s dst=%s:%u", comm.c_str(), ip,
                      ev.u.tcp.dport);
    } else if (ev.type == PQSEC_EVT_FILE_OPEN) {
        const std::string comm = printable(ev.comm, sizeof(ev.comm));
        const std::string path = ev.u.file.path[0] ? printable(ev.u.file.path, sizeof(ev.u.file.path))
                                                    : ("ino=" + std::to_string(ev.u.file.ino));
        const char *kind = (ev.u.file.access & PQSEC_FA_SENSITIVE) ? "read-sensitive" : "write";
        std::snprintf(buf, sizeof(buf), "fileopen comm=%s %s %s", comm.c_str(), kind, path.c_str());
    } else if (ev.type == PQSEC_EVT_AGENT_DROP) {
        std::snprintf(buf, sizeof(buf), "agent-drop dropped=%llu total=%llu sent=%llu",
                      static_cast<unsigned long long>(ev.u.drop.dropped),
                      static_cast<unsigned long long>(ev.u.drop.dropped_total),
                      static_cast<unsigned long long>(ev.u.drop.sent_total));
    } else {
        std::snprintf(buf, sizeof(buf), "unknown type=%u", ev.type);
    }
    std::string out(buf);
    if (ev.anc[0].pid != 0 || ev.anc[0].comm[0] != '\0') // 계보가 있으면 트리 부착
        out += " tree=[" + process_tree(ev) + "]";
    return out;
}

} // namespace pqsec::analyzer
