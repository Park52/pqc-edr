// analyzer/src/pipeline.cpp — 이벤트 처리 파이프라인

#include "pipeline.h"
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

void account(Outcome &o, const Classification &c, bool sonnet) {
    (sonnet ? o.sonnet_calls : o.haiku_calls) += 1;
    o.input_tokens += c.input_tokens;
    o.output_tokens += c.output_tokens;
}
} // namespace

const char *to_string(Layer l) {
    switch (l) {
    case Layer::Drop:              return "drop";
    case Layer::Rule:              return "rule";
    case Layer::RuleCorrelation:   return "rule+correlation";
    case Layer::CorrelationSonnet: return "correlation+sonnet";
    case Layer::HaikuNormal:       return "haiku-normal";
    case Layer::Sonnet:            return "sonnet";
    case Layer::AgentDrop:         return "agent-drop";
    }
    return "?";
}

Outcome classify_event(const security_event &ev, LlmClient &llm, Correlator &corr) {
    Outcome o;
    const std::string summary = event_summary(ev);

    // agent 백프레셔 통지: 이 구간에 탐지 공백이 있었다는 사실을 alert 로 surface (조용히 넘기지 않음)
    if (ev.type == PQSEC_EVT_AGENT_DROP) {
        char buf[240];
        std::snprintf(buf, sizeof(buf),
                      "agent 백프레셔 드롭: 이 구간에서 %llu개 이벤트 유실 (누적 %llu, 전송 %llu) — 탐지 공백 가능",
                      static_cast<unsigned long long>(ev.u.drop.dropped),
                      static_cast<unsigned long long>(ev.u.drop.dropped_total),
                      static_cast<unsigned long long>(ev.u.drop.sent_total));
        o.layer = Layer::AgentDrop;
        o.alerted = true;
        o.alert = make_alert(ev, summary, Verdict::Unknown, Severity::Medium, "agent", buf);
        return o;
    }

    const PrefilterResult pr = prefilter(ev);
    const CorrelationHit ch = corr.observe(ev);

    // 시퀀스 증거(코릴레이션)는 단일 이벤트 판정보다 강하다 — 결정론적 근거이므로 항상 alert.
    if (ch.hit) {
        if (pr.decision == PrefilterDecision::Alert) {
            // 룰도 걸림 → LLM 없이 즉시. 심각도는 둘 중 높은 쪽.
            o.layer = Layer::RuleCorrelation;
            o.alerted = true;
            o.alert = make_alert(ev, summary, Verdict::Malicious, std::max(pr.severity, ch.severity),
                                 "rule+" + ch.rule, pr.reason + "; " + ch.reason);
            return o;
        }
        // 룰은 애매/정상 → Haiku 건너뛰고 Sonnet 심층 직행 (시퀀스 근거를 컨텍스트로 제공).
        // LLM 은 설명·심각도 보정 역할이며, 결정론적 근거를 '정상'으로 뒤집지는 못한다.
        Classification s = llm.deep_analyze(summary + " | correlation: " + ch.reason);
        account(o, s, /*sonnet=*/true);
        const Verdict v = (s.verdict == Verdict::Normal || s.verdict == Verdict::Unknown)
                              ? Verdict::Suspicious
                              : s.verdict;
        o.layer = Layer::CorrelationSonnet;
        o.alerted = true;
        o.alert = make_alert(ev, summary, v, std::max(s.severity, ch.severity), ch.rule + "+sonnet",
                             ch.reason + " / " + s.reason);
        return o;
    }

    switch (pr.decision) {
    case PrefilterDecision::Drop:
        o.layer = Layer::Drop;
        o.log_line = "  [drop]  " + summary + "  (" + pr.reason + ")";
        return o;

    case PrefilterDecision::Alert:
        o.layer = Layer::Rule;
        o.alerted = true;
        o.alert = make_alert(ev, summary, Verdict::Malicious, pr.severity, "rule", pr.reason);
        return o;

    case PrefilterDecision::Escalate: {
        Classification h = llm.classify(summary); // 1차: Haiku
        account(o, h, /*sonnet=*/false);
        if (h.verdict == Verdict::Normal) {
            char conf[32];
            std::snprintf(conf, sizeof(conf), "%.2f", h.confidence);
            o.layer = Layer::HaikuNormal;
            o.log_line = "  [llm:" + h.model + " normal] " + summary + "  (" + h.reason +
                         ", conf=" + conf + ")";
            return o;
        }
        Classification s = llm.deep_analyze(summary); // 의심 → 심층: Sonnet
        account(o, s, /*sonnet=*/true);
        o.layer = Layer::Sonnet;
        o.alerted = true;
        o.alert = make_alert(ev, summary, s.verdict, s.severity, "sonnet", s.reason);
        return o;
    }
    }
    return o;
}

void process_event(const security_event &ev, LlmClient &llm, Correlator &corr) {
    Outcome o = classify_event(ev, llm, corr);
    if (o.alerted)
        emit_alert(o.alert);
    else
        fprintf(stderr, "%s\n", o.log_line.c_str());
}

} // namespace pqsec::analyzer
