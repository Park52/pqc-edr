// analyzer/src/prefilter.h
//
// 룰 기반 1차 필터. LLM 앞단에서 "명백한 것"을 걸러 API 호출량(비용)과 오탐을 줄인다.
//   Drop     : 명백 정상 → LLM 안 보냄
//   Alert    : 명백 악성 → 즉시 alert (LLM 안 보냄)
//   Escalate : 애매      → LLM 으로 (Haiku 1차 → 필요시 Sonnet 심층)

#ifndef PQSEC_PREFILTER_H
#define PQSEC_PREFILTER_H

#include "alert.h" // Severity

#include "event.h" // security_event

#include <cstdint>
#include <string>

namespace pqsec::analyzer {

enum class PrefilterDecision { Drop, Escalate, Alert };

struct PrefilterResult {
    PrefilterDecision decision;
    Severity severity;  // Alert 일 때 의미
    std::string reason;
};

PrefilterResult prefilter(const security_event &ev);

// LLM 컨텍스트 / 로그용 이벤트 요약 문자열
std::string event_summary(const security_event &ev);

// 공용 헬퍼 (correlator 도 사용)
// daddr(네트워크 바이트오더 저장)이 사설/루프백 대역인지 (리틀엔디안 호스트 가정)
bool is_private_ipv4(uint32_t daddr_net);
std::string basename_of(const char *path);

} // namespace pqsec::analyzer

#endif // PQSEC_PREFILTER_H
