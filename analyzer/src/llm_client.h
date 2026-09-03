// analyzer/src/llm_client.h
//
// LLM 분류기 인터페이스. 티어링: classify(Haiku 1차) → deep_analyze(Sonnet 심층).
//   - MockLlmClient : 결정론적 스텁 (오프라인/CI, API 키 불필요)
//   - (part 3) 실 libcurl 기반 Claude API 클라이언트가 같은 인터페이스로 추가됨

#ifndef PQSEC_LLM_CLIENT_H
#define PQSEC_LLM_CLIENT_H

#include "alert.h" // Verdict, Severity

#include <string>

namespace pqsec::analyzer {

struct Classification {
    Verdict verdict = Verdict::Unknown;
    Severity severity = Severity::Info;
    double confidence = 0.0; // 0..1
    std::string reason;
    std::string model; // 어떤 모델이 판정했는지
};

class LlmClient {
public:
    virtual ~LlmClient() = default;
    virtual Classification classify(const std::string &context) = 0;     // 1차 (Haiku)
    virtual Classification deep_analyze(const std::string &context) = 0;  // 심층 (Sonnet)
};

// 결정론적 스텁 — 키워드 휴리스틱. 파이프라인을 오프라인에서 관통시키기 위한 것.
class MockLlmClient : public LlmClient {
public:
    Classification classify(const std::string &context) override;
    Classification deep_analyze(const std::string &context) override;
};

// 실 Claude API 클라이언트 (libcurl raw HTTPS → /v1/messages).
// classify=Haiku 1차, deep_analyze=Sonnet 심층. 호출 실패는 fail-safe(Unknown, 크래시 X).
class ClaudeLlmClient : public LlmClient {
public:
    ClaudeLlmClient(std::string api_key, std::string haiku_model = "claude-haiku-4-5",
                    std::string sonnet_model = "claude-sonnet-5");
    Classification classify(const std::string &context) override;
    Classification deep_analyze(const std::string &context) override;

private:
    Classification call(const std::string &model, const std::string &system_prompt,
                        const std::string &user_msg, int max_tokens, bool deep);
    std::string api_key_;
    std::string haiku_model_;
    std::string sonnet_model_;
};

} // namespace pqsec::analyzer

#endif // PQSEC_LLM_CLIENT_H
