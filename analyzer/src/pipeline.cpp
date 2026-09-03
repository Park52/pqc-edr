// analyzer/src/pipeline.cpp — 이벤트 처리 파이프라인

#include "pipeline.h"
#include "alert.h"
#include "prefilter.h"

#include <cstdio>

namespace pqsec::analyzer {

namespace {
Alert make_alert(const security_event &ev, const std::string &summary, Verdict v, Severity s,
                 const std::string &source, const std::string &reason) {
    Alert a;
    a.verdict = v;
    a.severity = s;
    a.source = source;
    a.reason = reason;
    a.event_summary = summary;
    a.pid = ev.pid;
    a.comm = ev.comm;
    return a;
}
} // namespace

void process_event(const security_event &ev, LlmClient &llm) {
    const std::string summary = event_summary(ev);
    const PrefilterResult pr = prefilter(ev);

    switch (pr.decision) {
    case PrefilterDecision::Drop:
        // LLM 안 감 — 명백 정상
        fprintf(stderr, "  [drop]  %s  (%s)\n", summary.c_str(), pr.reason.c_str());
        return;

    case PrefilterDecision::Alert:
        // LLM 안 감 — 명백 악성
        emit_alert(make_alert(ev, summary, Verdict::Malicious, pr.severity, "rule", pr.reason));
        return;

    case PrefilterDecision::Escalate: {
        // 1차: Haiku
        Classification h = llm.classify(summary);
        if (h.verdict == Verdict::Normal) {
            fprintf(stderr, "  [llm:%s normal] %s  (%s, conf=%.2f)\n", h.model.c_str(),
                    summary.c_str(), h.reason.c_str(), h.confidence);
            return;
        }
        // 의심 → 심층: Sonnet
        Classification s = llm.deep_analyze(summary);
        emit_alert(make_alert(ev, summary, s.verdict, s.severity, "sonnet", s.reason));
        return;
    }
    }
}

} // namespace pqsec::analyzer
