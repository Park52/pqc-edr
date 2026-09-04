// analyzer/src/alert.cpp — 구조화 alert 출력

#include "alert.h"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <ctime>

namespace pqsec::analyzer {

const char *to_string(Verdict v) {
    switch (v) {
    case Verdict::Normal:     return "normal";
    case Verdict::Suspicious: return "suspicious";
    case Verdict::Malicious:  return "malicious";
    case Verdict::Unknown:    return "unknown";
    }
    return "unknown";
}

const char *to_string(Severity s) {
    switch (s) {
    case Severity::Info:     return "info";
    case Severity::Low:      return "low";
    case Severity::Medium:   return "medium";
    case Severity::High:     return "high";
    case Severity::Critical: return "critical";
    }
    return "info";
}

void emit_alert(const Alert &a) {
    // 구조화 로그: JSON 한 줄 (stdout) — 후속 수집/SIEM 연동 대비
    nlohmann::json j = {
        {"ts", static_cast<long>(std::time(nullptr))},
        {"verdict", to_string(a.verdict)},
        {"severity", to_string(a.severity)},
        {"source", a.source},
        {"pid", a.pid},
        {"comm", a.comm},
        {"event", a.event_summary},
        {"reason", a.reason},
    };
    // 유효하지 않은 UTF-8 은 U+FFFD 로 대체 (dump 예외로 데몬이 죽지 않게)
    printf("%s\n", j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace).c_str());
    fflush(stdout);

    // 사람이 읽는 요약 (stderr)
    fprintf(stderr, "  [ALERT] %-10s sev=%-8s src=%-6s | %s | %s\n", to_string(a.verdict),
            to_string(a.severity), a.source.c_str(), a.event_summary.c_str(),
            a.reason.c_str());
}

} // namespace pqsec::analyzer
