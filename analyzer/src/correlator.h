// analyzer/src/correlator.h
//
// 시퀀스(상태 기반) 코릴레이션 — 단일 이벤트 룰(prefilter)이 못 보는 "순서·반복" 패턴을 본다.
//   C1 download→exec : 같은 부모(ppid) 아래에서 다운로더(curl/wget) 실행 후 W초 내 임시경로 실행
//   C2 beacon        : 같은 (comm, dst ip, port) 공인 목적지로 W초 내 N회 이상 반복 접속
// 상태는 최근 항목만 유지하고 윈도우를 벗어난 항목은 만료시킨다 (메모리 상한 있음).
//
// 파이프라인에서의 위치 (pipeline.cpp):
//   룰 hit → 즉시 alert  /  코릴레이션 hit → Sonnet 직행  /  애매 → Haiku 1차

#ifndef PQSEC_CORRELATOR_H
#define PQSEC_CORRELATOR_H

#include "alert.h" // Severity

#include "event.h" // security_event

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <tuple>

namespace pqsec::analyzer {

struct CorrelationHit {
    bool hit = false;
    Severity severity = Severity::Info;
    std::string rule;   // "download-exec-chain" | "beacon"
    std::string reason; // 사람이 읽는 근거 (alert/LLM 컨텍스트에 포함)
};

class Correlator {
public:
    // window_ns: 상관 윈도우. beacon_threshold: 윈도우 내 반복 접속 횟수 임계.
    explicit Correlator(uint64_t window_ns = 60ull * 1000000000ull,
                        size_t beacon_threshold = 3);

    // 이벤트를 관찰(상태 갱신)하고, 시퀀스 룰에 걸리면 hit 를 반환.
    CorrelationHit observe(const security_event &ev);

private:
    CorrelationHit observe_execve(const security_event &ev);
    CorrelationHit observe_connect(const security_event &ev);

    struct DownloadSeen {
        uint32_t pid;
        uint32_t ppid;
        uint64_t ts_ns;
        std::string tool;
    };
    using ConnKey = std::tuple<std::string, uint32_t, uint16_t>; // comm, daddr, dport

    uint64_t window_ns_;
    size_t beacon_threshold_;
    std::deque<DownloadSeen> downloads_;            // 최근 다운로더 실행 (FIFO, 만료)
    std::map<ConnKey, std::deque<uint64_t>> conns_; // 목적지별 최근 접속 시각
};

} // namespace pqsec::analyzer

#endif // PQSEC_CORRELATOR_H
