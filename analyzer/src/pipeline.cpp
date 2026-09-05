// analyzer/src/pipeline.cpp — 이벤트 처리 파이프라인

#include "pipeline.h"
#include "alert.h"
#include "prefilter.h"

#include <algorithm>
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

void process_event(const security_event &ev, LlmClient &llm, Correlator &corr) {
    const std::string summary = event_summary(ev);

    // agent 백프레셔 통지: 이 구간에 탐지 공백이 있었다는 사실을 alert 로 surface (조용히 넘기지 않음)
    if (ev.type == PQSEC_EVT_AGENT_DROP) {
        char buf[240];
        std::snprintf(buf, sizeof(buf),
                      "agent 백프레셔 드롭: 이 구간에서 %llu개 이벤트 유실 (누적 %llu, 전송 %llu) — 탐지 공백 가능",
                      static_cast<unsigned long long>(ev.u.drop.dropped),
                      static_cast<unsigned long long>(ev.u.drop.dropped_total),
                      static_cast<unsigned long long>(ev.u.drop.sent_total));
        emit_alert(make_alert(ev, summary, Verdict::Unknown, Severity::Medium, "agent", buf));
        return;
    }
    const PrefilterResult pr = prefilter(ev);
    const CorrelationHit ch = corr.observe(ev);

    // 시퀀스 증거(코릴레이션)는 단일 이벤트 판정보다 강하다 — 결정론적 근거이므로 항상 alert.
    if (ch.hit) {
        if (pr.decision == PrefilterDecision::Alert) {
            // 룰도 걸림 → LLM 없이 즉시. 심각도는 둘 중 높은 쪽.
            emit_alert(make_alert(ev, summary, Verdict::Malicious,
                                  std::max(pr.severity, ch.severity), "rule+" + ch.rule,
                                  pr.reason + "; " + ch.reason));
            return;
        }
        // 룰은 애매/정상 → Haiku 건너뛰고 Sonnet 심층 직행 (시퀀스 근거를 컨텍스트로 제공).
        // LLM 은 설명·심각도 보정 역할이며, 결정론적 근거를 '정상'으로 뒤집지는 못한다.
        Classification s = llm.deep_analyze(summary + " | correlation: " + ch.reason);
        const Verdict v = (s.verdict == Verdict::Normal || s.verdict == Verdict::Unknown)
                              ? Verdict::Suspicious
                              : s.verdict;
        emit_alert(make_alert(ev, summary, v, std::max(s.severity, ch.severity),
                              ch.rule + "+sonnet", ch.reason + " / " + s.reason));
        return;
    }

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
