// analyzer/src/correlator.h
//
// 시퀀스(상태 기반) 코릴레이션 — 단일 이벤트 룰(prefilter)이 못 보는 "순서·반복" 패턴.
//   C1 download→exec : 다운로더(curl/wget) 실행 후 W초 내 임시경로 실행. 매칭은 **조상 교집합**
//                      (부모/조부 등 공통 조상 공유) — 서브셸 한두 겹 우회에 견딤.
//   C3 write→exec    : 스테이징(/tmp 등)에 쓰인 경로가 W초 내 실행됨. **부모 무관**(파일이 조인 키)
//                      — 다운로드와 실행의 부모가 달라도 잡는다(split-parent).
//   C2 beacon        : 같은 (comm, dst ip, port) 공인 목적지로 W초 내 N회 이상 반복 접속.
// 상태는 최근 항목만 유지하고 윈도우를 벗어난 항목은 만료시킨다 (메모리 상한 있음).

#ifndef PQSEC_CORRELATOR_H
#define PQSEC_CORRELATOR_H

#include "alert.h" // Severity

#include "event.h" // security_event

#include <cstdint>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <tuple>

namespace pqsec::analyzer {

struct CorrelationHit {
    bool hit = false;
    Severity severity = Severity::Info;
    std::string rule;   // "download-exec-chain" | "write-exec-chain" | "beacon"
    std::string reason; // 사람이 읽는 근거 (alert/LLM 컨텍스트에 포함)
};

// 이벤트를 낸 프로세스의 조상 pid 집합 (ppid + anc[], init/커널 0·1 제외)
std::set<uint32_t> ancestor_set(const security_event &ev);

class Correlator {
public:
    explicit Correlator(uint64_t window_ns = 60ull * 1000000000ull,
                        size_t beacon_threshold = 3);
    CorrelationHit observe(const security_event &ev);

private:
    CorrelationHit observe_execve(const security_event &ev);
    CorrelationHit observe_connect(const security_event &ev);
    CorrelationHit observe_file(const security_event &ev);

    struct Lineage {         // 조상 교집합 매칭용
        uint64_t ts_ns;
        std::set<uint32_t> anc;
        std::string comm;    // 행위 주체(툴/작성자) 이름
    };
    struct StagedWrite {     // 경로 기반 write→exec 매칭용
        uint64_t ts_ns;
        std::string writer;
    };
    using ConnKey = std::tuple<std::string, uint32_t, uint16_t>;

    uint64_t window_ns_;
    size_t beacon_threshold_;
    std::deque<Lineage> downloads_;                 // 최근 다운로더 실행
    std::map<std::string, StagedWrite> staged_;     // 스테이징 경로 → 최근 쓰기
    std::map<ConnKey, std::deque<uint64_t>> conns_; // 목적지별 최근 접속 시각
};

} // namespace pqsec::analyzer

#endif // PQSEC_CORRELATOR_H
