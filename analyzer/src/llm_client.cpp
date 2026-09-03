// analyzer/src/llm_client.cpp — Mock LLM 분류기 (결정론적)

#include "llm_client.h"

#include <string>

namespace pqsec::analyzer {

namespace {
bool contains(const std::string &s, const char *sub) {
    return s.find(sub) != std::string::npos;
}
} // namespace

// 1차(Haiku 대역): 빠른 normal/suspicious 판정. 다운로더/스크립트/실행기 정황을 의심.
Classification MockLlmClient::classify(const std::string &context) {
    Classification c;
    c.model = "mock-haiku";
    const bool suspicious = contains(context, "curl") || contains(context, "wget") ||
                            contains(context, "python") || contains(context, "perl") ||
                            contains(context, "/tmp") || contains(context, ":4444") ||
                            contains(context, "powershell");
    if (suspicious) {
        c.verdict = Verdict::Suspicious;
        c.confidence = 0.7;
        c.reason = "다운로더/스크립트 실행 또는 비정상 아웃바운드 정황";
    } else {
        c.verdict = Verdict::Normal;
        c.confidence = 0.8;
        c.reason = "특이사항 없음";
    }
    return c;
}

// 심층(Sonnet 대역): 사유 설명 + 심각도. (mock 은 고정 서술)
Classification MockLlmClient::deep_analyze(const std::string &context) {
    Classification c;
    c.model = "mock-sonnet";
    c.verdict = Verdict::Suspicious;
    c.severity = Severity::Medium;
    c.confidence = 0.75;
    c.reason = "심층 분석(mock): 실행/아웃바운드 패턴이 데이터 유출 또는 C2 통신 정황과 부합. "
               "컨텍스트=[" + context + "]";
    return c;
}

} // namespace pqsec::analyzer
