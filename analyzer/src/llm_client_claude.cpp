// analyzer/src/llm_client_claude.cpp
//
// 실 Claude API 클라이언트 (libcurl). C++ 는 공식 SDK 가 없어 raw HTTPS POST 로 호출.
//   POST https://api.anthropic.com/v1/messages
//   헤더: x-api-key, anthropic-version, content-type
// 응답 text 를 JSON 으로 파싱해 판정에 매핑. 어떤 실패든 fail-safe(Unknown) — 데몬은 안 죽는다.

#include "llm_client.h"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <mutex>
#include <string>
#include <utility>

namespace pqsec::analyzer {

namespace {

size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *s = static_cast<std::string *>(userdata);
    s->append(ptr, size * nmemb);
    return size * nmemb;
}

Verdict parse_verdict(const std::string &s) {
    if (s == "normal") return Verdict::Normal;
    if (s == "suspicious") return Verdict::Suspicious;
    if (s == "malicious") return Verdict::Malicious;
    return Verdict::Unknown;
}

Severity parse_severity(const std::string &s) {
    if (s == "low") return Severity::Low;
    if (s == "medium") return Severity::Medium;
    if (s == "high") return Severity::High;
    if (s == "critical") return Severity::Critical;
    return Severity::Info;
}

// 모델이 코드펜스/서두를 붙여도 첫 '{' ~ 마지막 '}' 로 JSON 본문만 추출
std::string extract_json(const std::string &text) {
    size_t a = text.find('{');
    size_t b = text.rfind('}');
    if (a == std::string::npos || b == std::string::npos || b <= a)
        return "";
    return text.substr(a, b - a + 1);
}

Classification fail_safe(const std::string &model, const std::string &why) {
    Classification c;
    c.model = model;
    c.verdict = Verdict::Unknown; // 조용히 정상 처리하지 않음 — 상위로 surface
    c.severity = Severity::Medium;
    c.confidence = 0.0;
    c.reason = "LLM 호출 실패(fail-safe): " + why;
    return c;
}

} // namespace

ClaudeLlmClient::ClaudeLlmClient(std::string api_key, std::string haiku_model,
                                 std::string sonnet_model)
    : api_key_(std::move(api_key)), haiku_model_(std::move(haiku_model)),
      sonnet_model_(std::move(sonnet_model)) {
    static std::once_flag once;
    std::call_once(once, []() { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

Classification ClaudeLlmClient::call(const std::string &model, const std::string &system_prompt,
                                     const std::string &user_msg, int max_tokens, bool deep) {
    if (api_key_.empty())
        return fail_safe(model, "ANTHROPIC_API_KEY 없음");

    nlohmann::json req = {
        {"model", model},
        {"max_tokens", max_tokens},
        {"system", system_prompt},
        {"messages", nlohmann::json::array({{{"role", "user"}, {"content", user_msg}}})},
    };
    std::string body = req.dump();

    CURL *curl = curl_easy_init();
    if (!curl)
        return fail_safe(model, "curl 초기화 실패");

    std::string resp;
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "content-type: application/json");
    headers = curl_slist_append(headers, "anthropic-version: 2023-06-01");
    std::string key_hdr = "x-api-key: " + api_key_;
    headers = curl_slist_append(headers, key_hdr.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, "https://api.anthropic.com/v1/messages");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK)
        return fail_safe(model, std::string("전송 실패: ") + curl_easy_strerror(rc));
    if (http_code != 200)
        return fail_safe(model, "HTTP " + std::to_string(http_code) + ": " + resp.substr(0, 200));

    try {
        nlohmann::json api = nlohmann::json::parse(resp);
        // 안전 검사: content[0].text
        std::string text = api.at("content").at(0).at("text").get<std::string>();
        std::string obj = extract_json(text);
        if (obj.empty())
            return fail_safe(model, "응답에서 JSON 미발견");
        nlohmann::json p = nlohmann::json::parse(obj);

        Classification c;
        c.model = model;
        c.verdict = parse_verdict(p.value("verdict", "unknown"));
        c.severity = deep ? parse_severity(p.value("severity", "medium")) : Severity::Info;
        c.confidence = p.value("confidence", 0.0);
        c.reason = p.value("reason", "");
        return c;
    } catch (const std::exception &e) {
        return fail_safe(model, std::string("응답 파싱 실패: ") + e.what());
    }
}

Classification ClaudeLlmClient::classify(const std::string &context) {
    const char *system =
        "You are a security event triage classifier for an endpoint EDR pipeline. "
        "Given one host security event (process exec or outbound TCP connect), decide if it is "
        "benign or worth deeper analysis. Respond with ONLY a compact JSON object, no prose: "
        "{\"verdict\":\"normal\"|\"suspicious\"|\"malicious\",\"confidence\":0.0-1.0,"
        "\"reason\":\"one short sentence\"}.";
    return call(haiku_model_, system, "Event: " + context, 256, /*deep=*/false);
}

Classification ClaudeLlmClient::deep_analyze(const std::string &context) {
    const char *system =
        "You are a senior security analyst. Analyze this suspicious endpoint event in depth, "
        "considering data exfiltration, C2, and living-off-the-land techniques (reference MITRE "
        "ATT&CK where relevant). Respond with ONLY a JSON object, no prose: "
        "{\"verdict\":\"normal\"|\"suspicious\"|\"malicious\","
        "\"severity\":\"low\"|\"medium\"|\"high\"|\"critical\",\"confidence\":0.0-1.0,"
        "\"reason\":\"concise explanation\"}.";
    return call(sonnet_model_, system, "Event: " + context, 512, /*deep=*/true);
}

} // namespace pqsec::analyzer
