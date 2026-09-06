// analyzer/src/correlator.cpp — 시퀀스 코릴레이션 (download/write→exec 체인, 비콘)

#include "correlator.h"
#include "prefilter.h" // is_private_ipv4, basename_of

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <set>

namespace pqsec::analyzer {

namespace {

const std::set<std::string> kDownloaders = {"curl", "wget"};

bool is_temp_path(const char *path) {
    return std::strncmp(path, "/tmp/", 5) == 0 || std::strncmp(path, "/dev/shm/", 9) == 0 ||
           std::strncmp(path, "/var/tmp/", 9) == 0;
}
double to_sec(uint64_t ns) { return static_cast<double>(ns) / 1e9; }
uint64_t elapsed(uint64_t now, uint64_t then) { return now >= then ? now - then : 0; }

// 두 조상 집합이 공통 조상을 공유하면 그 pid, 아니면 0
uint32_t common_ancestor(const std::set<uint32_t> &a, const std::set<uint32_t> &b) {
    for (uint32_t p : a)
        if (b.count(p))
            return p;
    return 0;
}

constexpr size_t kMaxDownloads = 64;
constexpr size_t kMaxStaged = 512;
constexpr size_t kMaxHistPerKey = 256;
constexpr size_t kSweepKeys = 4096;

} // namespace

std::set<uint32_t> ancestor_set(const security_event &ev) {
    std::set<uint32_t> s;
    if (ev.ppid > 1)
        s.insert(ev.ppid);
    for (int i = 0; i < PQSEC_ANCESTORS; ++i)
        if (ev.anc[i].pid > 1)
            s.insert(ev.anc[i].pid);
    return s;
}

Correlator::Correlator(uint64_t window_ns, size_t beacon_threshold)
    : window_ns_(window_ns), beacon_threshold_(beacon_threshold) {}

CorrelationHit Correlator::observe(const security_event &ev) {
    switch (ev.type) {
    case PQSEC_EVT_EXECVE:      return observe_execve(ev);
    case PQSEC_EVT_TCP_CONNECT: return observe_connect(ev);
    case PQSEC_EVT_FILE_OPEN:   return observe_file(ev);
    default:                    return {};
    }
}

// 스테이징 쓰기를 경로별로 기억 (C3 의 join 키). 민감읽기는 prefilter 가 룰로 처리 → 여기선 {}.
CorrelationHit Correlator::observe_file(const security_event &ev) {
    if (!(ev.u.file.access & PQSEC_FA_WRITE))
        return {};
    const char *p = ev.u.file.path;
    if (p[0] == '\0' || !is_temp_path(p))
        return {};
    std::string comm(ev.comm, strnlen(ev.comm, sizeof(ev.comm)));
    staged_[std::string(p)] = {ev.ts_ns, comm};
    if (staged_.size() > kMaxStaged) { // 만료 정리
        const uint64_t now = ev.ts_ns;
        for (auto it = staged_.begin(); it != staged_.end();)
            it = (now > it->second.ts_ns + window_ns_) ? staged_.erase(it) : std::next(it);
    }
    return {}; // 쓰기 자체는 alert 아님 — 실행이 뒤따를 때 체인
}

// C3(경로 기반, 부모 무관) 우선, 그다음 C1(조상 교집합)
CorrelationHit Correlator::observe_execve(const security_event &ev) {
    const uint64_t now = ev.ts_ns;
    while (!downloads_.empty() && now > downloads_.front().ts_ns + window_ns_)
        downloads_.pop_front();

    const std::string bin = basename_of(ev.u.execve.filename);
    if (kDownloaders.count(bin)) {
        downloads_.push_back({now, ancestor_set(ev), bin});
        if (downloads_.size() > kMaxDownloads)
            downloads_.pop_front();
        return {};
    }
    if (!is_temp_path(ev.u.execve.filename))
        return {};

    // C3: 이 경로가 스테이징에 쓰였던 적이 있나 (부모 무관)
    auto it = staged_.find(ev.u.execve.filename);
    if (it != staged_.end() && now <= it->second.ts_ns + window_ns_) {
        char buf[300];
        std::snprintf(buf, sizeof(buf),
                      "쓰기→실행 체인: %s 가 스테이징에 쓴 %s 를 %.1f초 내 실행 (부모 무관)",
                      it->second.writer.c_str(), ev.u.execve.filename,
                      to_sec(elapsed(now, it->second.ts_ns)));
        return {true, Severity::Critical, "write-exec-chain", buf};
    }

    // C1: 다운로더 실행과 조상을 공유하는가 (서브셸 우회 견딤)
    const std::set<uint32_t> mine = ancestor_set(ev);
    for (const Lineage &d : downloads_) {
        uint32_t shared = common_ancestor(d.anc, mine);
        if (!shared)
            continue;
        char buf[300];
        std::snprintf(buf, sizeof(buf),
                      "다운로드→실행 체인: %s 실행과 임시경로 실행이 공통 조상(pid=%u) 공유, %.1f초 내",
                      d.comm.c_str(), shared, to_sec(elapsed(now, d.ts_ns)));
        return {true, Severity::Critical, "download-exec-chain", buf};
    }
    return {};
}

CorrelationHit Correlator::observe_connect(const security_event &ev) {
    if (is_private_ipv4(ev.u.tcp.daddr))
        return {};
    const uint64_t now = ev.ts_ns;
    const std::string comm(ev.comm, strnlen(ev.comm, sizeof(ev.comm)));
    std::deque<uint64_t> &hist = conns_[ConnKey{comm, ev.u.tcp.daddr, ev.u.tcp.dport}];
    while (!hist.empty() && now > hist.front() + window_ns_)
        hist.pop_front();
    hist.push_back(now);
    if (hist.size() > kMaxHistPerKey)
        hist.pop_front();

    if (conns_.size() > kSweepKeys) {
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
