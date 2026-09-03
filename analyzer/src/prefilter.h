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

} // namespace pqsec::analyzer

#endif // PQSEC_PREFILTER_H
