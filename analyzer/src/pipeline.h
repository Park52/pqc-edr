// analyzer/src/pipeline.h
//
// 이벤트 1건 처리 파이프라인:
//   룰 프리필터 + 시퀀스 코릴레이션 → (룰 hit) 즉시 alert
//                                  → (코릴레이션 hit) Sonnet 심층 직행
//                                  → (애매) Haiku 1차 → (의심) Sonnet 심층 → alert
//
// classify_event 는 순수 함수처럼 결과(Outcome)만 돌려준다 — 데몬은 그걸 출력하고(process_event),
// 평가 하네스(analyzer_eval)는 그걸 집계한다. 두 경로가 같은 코드를 탄다.

#ifndef PQSEC_PIPELINE_H
#define PQSEC_PIPELINE_H

#include "alert.h"
#include "correlator.h"
#include "llm_client.h"

#include "event.h" // security_event

#include <cstdint>
#include <string>

namespace pqsec::analyzer {

// 어느 층이 최종 결정을 냈나
enum class Layer {
    Drop,              // 룰: 명백 정상
    Rule,              // 룰: 명백 악성 → alert
    RuleCorrelation,   // 룰 + 코릴레이션 hit → alert
    CorrelationSonnet, // 룰은 애매, 코릴레이션 hit → Sonnet 직행 → alert
    HaikuNormal,       // Haiku 1차: 정상 → alert 없음
    Sonnet,            // Haiku 의심 → Sonnet → alert
    AgentDrop,         // agent 백프레셔 통지 → alert(unknown)
};
const char *to_string(Layer l);

struct Outcome {
    Layer layer = Layer::Drop;
    bool alerted = false;
    Alert alert;                 // alerted 일 때 유효
    std::string log_line;        // alert 가 아닐 때 stderr 에 남길 한 줄
    int haiku_calls = 0;         // 이 이벤트 처리에 쓴 LLM 호출 수
    int sonnet_calls = 0;
    uint64_t input_tokens = 0;   // 실 API usage 합 (mock 은 0)
    uint64_t output_tokens = 0;
};

Outcome classify_event(const security_event &ev, LlmClient &llm, Correlator &corr);

// 데몬용: classify → alert 출력 / 로그
void process_event(const security_event &ev, LlmClient &llm, Correlator &corr);

} // namespace pqsec::analyzer

#endif // PQSEC_PIPELINE_H
