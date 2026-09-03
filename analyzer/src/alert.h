// analyzer/src/alert.h
//
// 분류 결과를 구조화 alert 로 출력. 판정/심각도 enum 은 파이프라인 전반에서 공유.

#ifndef PQSEC_ALERT_H
#define PQSEC_ALERT_H

#include <cstdint>
#include <string>

namespace pqsec::analyzer {

enum class Verdict { Normal, Suspicious, Malicious, Unknown };
enum class Severity { Info, Low, Medium, High, Critical };

const char *to_string(Verdict v);
const char *to_string(Severity s);

struct Alert {
    Verdict verdict = Verdict::Unknown;
    Severity severity = Severity::Info;
    std::string source;        // "rule" | "haiku" | "sonnet"
    std::string reason;        // 사유 설명
    std::string event_summary; // 이벤트 요약
    uint32_t pid = 0;
    std::string comm;
};

// 구조화 JSON 한 줄(stdout, 로그용) + 사람이 읽는 요약(stderr).
void emit_alert(const Alert &a);

} // namespace pqsec::analyzer

#endif // PQSEC_ALERT_H
