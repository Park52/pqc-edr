// analyzer/src/correlator.cpp — 시퀀스 코릴레이션 (download→exec 체인, 비콘)

#include "correlator.h"
#include "prefilter.h" // is_private_ipv4, basename_of

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <set>

namespace pqsec::analyzer {

namespace {

const std::set<std::string> kDownloaders = {"curl", "wget"};

// 실행 파일이 쓰기 가능한 임시 경로인가 (드롭·실행 스테이징에 흔히 쓰임)
bool is_temp_path(const char *path) {
    return std::strncmp(path, "/tmp/", 5) == 0 || std::strncmp(path, "/dev/shm/", 9) == 0 ||
           std::strncmp(path, "/var/tmp/", 9) == 0;
}

double to_sec(uint64_t ns) { return static_cast<double>(ns) / 1e9; }
uint64_t elapsed(uint64_t now, uint64_t then) { return now >= then ? now - then : 0; }

constexpr size_t kMaxDownloads = 64;   // 상태 상한 (PoC: 단순 FIFO)
constexpr size_t kMaxHistPerKey = 256;
constexpr size_t kSweepKeys = 4096;    // 키가 이만큼 쌓이면 만료 키 정리

} // namespace

Correlator::Correlator(uint64_t window_ns, size_t beacon_threshold)
    : window_ns_(window_ns), beacon_threshold_(beacon_threshold) {}

CorrelationHit Correlator::observe(const security_event &ev) {
    switch (ev.type) {
    case PQSEC_EVT_EXECVE:      return observe_execve(ev);
    case PQSEC_EVT_TCP_CONNECT: return observe_connect(ev);
    default:                    return {};
    }
}

// C1: 다운로더 실행을 기억해 두고, 같은 부모에서 임시경로 실행이 뒤따르면 체인으로 판정
CorrelationHit Correlator::observe_execve(const security_event &ev) {
    const uint64_t now = ev.ts_ns;
    while (!downloads_.empty() && now > downloads_.front().ts_ns + window_ns_)
        downloads_.pop_front(); // 윈도우 밖 만료

    const std::string bin = basename_of(ev.u.execve.filename);
    if (kDownloaders.count(bin)) {
        downloads_.push_back({ev.pid, ev.ppid, now, bin});
        if (downloads_.size() > kMaxDownloads)
            downloads_.pop_front();
        return {}; // 다운로더 자체는 hit 아님 (prefilter 가 LLM 으로 올림)
    }
    if (!is_temp_path(ev.u.execve.filename))
        return {};

    for (const DownloadSeen &d : downloads_) {
        if (d.ppid != ev.ppid)
            continue;
        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "다운로드→실행 체인: 동일 부모(ppid=%u)에서 %s 실행 후 %.1f초 내 임시경로 실행",
                      ev.ppid, d.tool.c_str(), to_sec(elapsed(now, d.ts_ns)));
        return {true, Severity::Critical, "download-exec-chain", buf};
    }
    return {};
}

// C2: 공인 목적지별 접속 시각을 쌓아, 윈도우 내 반복 횟수가 임계 이상이면 비콘으로 판정
CorrelationHit Correlator::observe_connect(const security_event &ev) {
    if (is_private_ipv4(ev.u.tcp.daddr))
        return {}; // 사설/루프백은 추적하지 않음

    const uint64_t now = ev.ts_ns;
    const std::string comm(ev.comm, strnlen(ev.comm, sizeof(ev.comm)));
    std::deque<uint64_t> &hist = conns_[ConnKey{comm, ev.u.tcp.daddr, ev.u.tcp.dport}];
    while (!hist.empty() && now > hist.front() + window_ns_)
        hist.pop_front();
    hist.push_back(now);
    if (hist.size() > kMaxHistPerKey)
        hist.pop_front();

    if (conns_.size() > kSweepKeys) { // 오래된 키 정리 (메모리 상한)
        for (auto it = conns_.begin(); it != conns_.end();) {
            const bool expired = it->second.empty() || now > it->second.back() + window_ns_;
            it = expired ? conns_.erase(it) : std::next(it);
        }
    }

    if (hist.size() < beacon_threshold_)
        return {};

    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &ev.u.tcp.daddr, ip, sizeof(ip));
    char buf[256];
    std::snprintf(buf, sizeof(buf), "비콘 의심: %s → %s:%u 로 %.0f초 윈도우 내 %zu회 반복 접속",
                  comm.c_str(), ip, ev.u.tcp.dport, to_sec(window_ns_), hist.size());
    return {true, Severity::High, "beacon", buf};
}

} // namespace pqsec::analyzer
