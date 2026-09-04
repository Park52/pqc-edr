// analyzer/src/pipeline.h
//
// 이벤트 1건 처리 파이프라인:
//   룰 프리필터 + 시퀀스 코릴레이션 → (룰 hit) 즉시 alert
//                                  → (코릴레이션 hit) Sonnet 심층 직행
//                                  → (애매) Haiku 1차 → (의심) Sonnet 심층 → alert
// 데몬과 셀프테스트가 공유한다.

#ifndef PQSEC_PIPELINE_H
#define PQSEC_PIPELINE_H

#include "correlator.h"
#include "llm_client.h"

#include "event.h" // security_event

namespace pqsec::analyzer {

void process_event(const security_event &ev, LlmClient &llm, Correlator &corr);

} // namespace pqsec::analyzer

#endif // PQSEC_PIPELINE_H
