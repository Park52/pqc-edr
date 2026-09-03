// analyzer/src/llm_probe.cpp
//
// 실 Claude API 경로 수동 점검 도구.
//   ANTHROPIC_API_KEY 가 있으면 샘플 이벤트를 Haiku→(의심 시)Sonnet 로 분류해 출력.
//   없으면 아무 API 호출 없이 안내만 하고 종료.
//
//   사용: ANTHROPIC_API_KEY=sk-... ./llm_probe ["execve comm=bash file=/tmp/x"]

#include "llm_client.h"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace pqsec::analyzer;

static void show(const char *label, const Classification &c) {
    printf("[%s] model=%s verdict=%s severity=%s conf=%.2f\n      reason=%s\n", label,
           c.model.c_str(), to_string(c.verdict), to_string(c.severity), c.confidence,
           c.reason.c_str());
}

int main(int argc, char **argv) {
    const char *key = std::getenv("ANTHROPIC_API_KEY");
    if (!key || !*key) {
        fprintf(stderr, "ANTHROPIC_API_KEY 미설정 — 실 API 테스트 생략.\n"
                        "  ANTHROPIC_API_KEY=sk-... %s 로 실행하세요.\n",
                argv[0]);
        return 2;
    }

    std::string ctx = (argc > 1) ? argv[1] : "execve comm=bash file=/tmp/xmrig";
    ClaudeLlmClient llm(key);
    printf("컨텍스트: %s\n\n", ctx.c_str());

    Classification h = llm.classify(ctx); // Haiku 1차
    show("Haiku classify", h);
    if (h.verdict != Verdict::Normal) {
        Classification s = llm.deep_analyze(ctx); // Sonnet 심층
        show("Sonnet deep  ", s);
    } else {
        printf("(normal → 심층 분석 생략)\n");
    }
    return 0;
}
