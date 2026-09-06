// analyzer/src/eval.cpp — 탐지 평가 하네스 (analyzer_eval)
//
// 라벨된 .events 코퍼스를 소켓 없이 파이프라인(classify_event)에 직접 넣고 층별 결정을 집계한다.
//   --benign PATH...    정상 코퍼스(파일/디렉토리; 모든 이벤트 = benign) → 오탐률·비용
//   --attack PATH...    공격 시나리오(파일 = 시나리오 1개; 줄 라벨 expect:alert|drop) → 탐지율
//   --llm mock|real     real 은 ANTHROPIC_API_KEY 필요 (기본 mock)
//   --max-llm-calls N   실 API 호출 상한(기본 2000). 초과분은 unknown 판정 + 'capped' 집계
//   --json FILE         결과 JSON 저장
//   --gate              '#! known-miss' 가 없는 공격 시나리오가 하나라도 미탐(≥High alert 없음)이면 exit 1
//
// 시계: 가상 단조시계 — 이벤트마다 +1ms, delay 줄은 그만큼 전진(실제로 기다리지 않음).
// LLM 메모: 같은 컨텍스트 문자열은 한 번만 호출(비용 절감·결정론). 메모 히트는 토큰 0 으로 집계.
// 코릴레이터는 파일마다 새로 만든다(시나리오 독립, 정상 세션은 파일 1개 = 세션 1개).

#include "correlator.h"
#include "llm_client.h"
#include "pipeline.h"

#include "event.h"
#include "events_file.h"

#include <nlohmann/json.hpp>

#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace pqsec::analyzer;
using pqsec::events_file::Entry;
using Clock = std::chrono::steady_clock;

namespace {

// ---- 가격 (USD / 1M 토큰, 2026-09 기준 Anthropic 1st-party) --------------
constexpr double kHaikuIn = 1.0, kHaikuOut = 5.0, kSonnetIn = 2.0, kSonnetOut = 10.0;

// ---- LLM 메모·상한 데코레이터 ----------------------------------------------
class MemoLlm : public LlmClient {
public:
    MemoLlm(LlmClient &inner, size_t cap) : inner_(inner), cap_(cap) {}
    Classification classify(const std::string &ctx) override { return get(ctx, haiku_, false); }
    Classification deep_analyze(const std::string &ctx) override { return get(ctx, sonnet_, true); }
    uint64_t calls = 0, hits = 0, capped = 0;
    uint64_t haiku_in = 0, haiku_out = 0, sonnet_in = 0, sonnet_out = 0;

private:
    Classification get(const std::string &ctx, std::map<std::string, Classification> &memo, bool deep) {
        auto it = memo.find(ctx);
        if (it != memo.end()) {
            ++hits;
            Classification c = it->second;
            c.input_tokens = c.output_tokens = 0; // 실제 호출 아님 → 비용 0
            return c;
        }
        if (calls >= cap_) {
            ++capped;
            Classification c;
            c.model = "capped";
            c.verdict = Verdict::Unknown;
            c.reason = "eval --max-llm-calls 도달";
            return c;
        }
        ++calls;
        Classification c = deep ? inner_.deep_analyze(ctx) : inner_.classify(ctx);
        (deep ? sonnet_in : haiku_in) += c.input_tokens;
        (deep ? sonnet_out : haiku_out) += c.output_tokens;
        memo[ctx] = c;
        return c;
    }
    LlmClient &inner_;
    size_t cap_;
    std::map<std::string, Classification> haiku_, sonnet_;
};

// ---- 집계 --------------------------------------------------------------------
struct Stats {
    uint64_t events = 0, alerts = 0;
    std::map<std::string, uint64_t> by_layer;   // to_string(Layer) → n
    std::map<std::string, uint64_t> by_source;  // alert.source → n
    std::map<std::string, uint64_t> fp_summary; // benign: alert 난 요약 → n
    uint64_t haiku_calls = 0, sonnet_calls = 0;
    std::vector<double> lat_rule_us, lat_llm_us;
};

struct Scenario {
    std::string name;
    std::string known_miss;                 // 비어 있으면 게이트 대상
    std::string expect_max_sev;             // "critical" 등 (선택)
    uint64_t events = 0, expect_alert = 0, hit_alert = 0, expect_drop = 0, fp = 0;
    Severity max_sev = Severity::Info;
    bool any_alert = false;
    std::map<std::string, uint64_t> layers;
};

Severity parse_sev(const std::string &s) {
    if (s == "low") return Severity::Low;
    if (s == "medium") return Severity::Medium;
    if (s == "high") return Severity::High;
    if (s == "critical") return Severity::Critical;
    return Severity::Info;
}
double pct(uint64_t a, uint64_t b) { return b ? 100.0 * static_cast<double>(a) / static_cast<double>(b) : 0.0; }
double p50(std::vector<double> v) { if (v.empty()) return 0; std::sort(v.begin(), v.end()); return v[v.size() / 2]; }
double p90(std::vector<double> v) { if (v.empty()) return 0; std::sort(v.begin(), v.end()); return v[v.size() * 9 / 10]; }

std::vector<std::string> expand(const std::vector<std::string> &paths) {
    std::vector<std::string> out;
    for (const std::string &p : paths) {
        struct stat st{};
        if (stat(p.c_str(), &st) != 0) { fprintf(stderr, "경로 없음: %s\n", p.c_str()); std::exit(2); }
        if (S_ISDIR(st.st_mode)) {
            std::vector<std::string> files;
            if (DIR *d = opendir(p.c_str())) {
                while (dirent *e = readdir(d)) {
                    std::string n = e->d_name;
                    if (n.size() > 7 && n.substr(n.size() - 7) == ".events") files.push_back(p + "/" + n);
                }
                closedir(d);
            }
            std::sort(files.begin(), files.end());
            out.insert(out.end(), files.begin(), files.end());
        } else {
            out.push_back(p);
        }
    }
    return out;
}
std::string basename_noext(const std::string &p) {
    size_t s = p.find_last_of('/');
    std::string b = s == std::string::npos ? p : p.substr(s + 1);
    size_t d = b.rfind(".events");
    return d == std::string::npos ? b : b.substr(0, d);
}

// 한 파일을 파이프라인에 흘리고 콜백으로 (Entry, Outcome, 지연) 전달
template <class F> void run_file(const std::string &path, LlmClient &llm, F &&on_event,
                                 const std::function<void(const std::string &)> &on_directive) {
    std::ifstream in(path);
    if (!in) { fprintf(stderr, "열기 실패: %s\n", path.c_str()); std::exit(2); }
    Correlator corr;
    uint64_t vclock = 1'000'000'000ull; // 가상 시계 (ns)
    pqsec::events_file::parse(in, path, [&](const Entry &e) {
        if (e.kind == Entry::Kind::Directive) { on_directive(e.directive); return; }
        if (e.kind == Entry::Kind::Delay) { vclock += static_cast<uint64_t>(e.delay_ms) * 1'000'000ull; return; }
        security_event ev = e.ev;
        vclock += 1'000'000ull;
        ev.ts_ns = vclock;
        auto t0 = Clock::now();
        Outcome o = classify_event(ev, llm, corr);
        double us = std::chrono::duration<double, std::micro>(Clock::now() - t0).count();
        on_event(e, o, us);
    });
}

void tally(Stats &st, const Outcome &o, double us, bool benign) {
    ++st.events;
    st.by_layer[to_string(o.layer)]++;
    st.haiku_calls += static_cast<uint64_t>(o.haiku_calls);
    st.sonnet_calls += static_cast<uint64_t>(o.sonnet_calls);
    ((o.haiku_calls + o.sonnet_calls) ? st.lat_llm_us : st.lat_rule_us).push_back(us);
    if (o.alerted) {
        ++st.alerts;
        st.by_source[o.alert.source]++;
        if (benign) st.fp_summary[o.alert.event_summary]++;
    }
}

} // namespace

int main(int argc, char **argv) {
    std::vector<std::string> benign, attack;
    std::string llm_mode = "mock", json_out;
    size_t cap = 2000;
    bool gate = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { if (i + 1 >= argc) { fprintf(stderr, "%s 인자 필요\n", a.c_str()); std::exit(2); } return argv[++i]; };
        auto collect = [&](std::vector<std::string> &v) { while (i + 1 < argc && argv[i + 1][0] != '-') v.push_back(argv[++i]); };
        if (a == "--benign") collect(benign);
        else if (a == "--attack") collect(attack);
        else if (a == "--llm") llm_mode = next();
        else if (a == "--max-llm-calls") cap = static_cast<size_t>(std::stoul(next()));
        else if (a == "--json") json_out = next();
        else if (a == "--gate") gate = true;
        else { fprintf(stderr, "알 수 없는 인자: %s\n", a.c_str()); return 2; }
    }
    if (benign.empty() && attack.empty()) { fprintf(stderr, "--benign 또는 --attack 필요\n"); return 2; }

    std::unique_ptr<LlmClient> inner;
    if (llm_mode == "real") {
        const char *key = std::getenv("ANTHROPIC_API_KEY");
        if (!key || !*key) { fprintf(stderr, "--llm real 에는 ANTHROPIC_API_KEY 필요\n"); return 2; }
        inner = std::make_unique<ClaudeLlmClient>(key);
    } else if (llm_mode == "mock") {
        inner = std::make_unique<MockLlmClient>();
    } else { fprintf(stderr, "--llm 은 mock|real\n"); return 2; }
    MemoLlm llm(*inner, cap);

    nlohmann::json J;
    J["llm"] = llm_mode;

    // ===== 정상 코퍼스 =====
    Stats bs;
    std::vector<std::string> bfiles = expand(benign);
    for (const std::string &f : bfiles)
        run_file(f, llm, [&](const Entry &, const Outcome &o, double us) { tally(bs, o, us, true); },
                 [](const std::string &) {});
    const uint64_t b_haiku_calls_before_attack = llm.calls; // 정상 코퍼스에 쓴 실 호출 수
    const uint64_t b_hin = llm.haiku_in, b_hout = llm.haiku_out, b_sin = llm.sonnet_in, b_sout = llm.sonnet_out;

    // ===== 공격 코퍼스 =====
    std::vector<Scenario> scen;
    Stats as;
    for (const std::string &f : expand(attack)) {
        Scenario sc;
        sc.name = basename_noext(f);
        run_file(f, llm,
                 [&](const Entry &e, const Outcome &o, double us) {
                     tally(as, o, us, false);
                     ++sc.events;
                     sc.layers[to_string(o.layer)]++;
                     if (e.expect == "alert") { ++sc.expect_alert; if (o.alerted) ++sc.hit_alert; }
                     else if (e.expect == "drop") { ++sc.expect_drop; if (o.alerted) ++sc.fp; }
                     if (o.alerted) { sc.any_alert = true; sc.max_sev = std::max(sc.max_sev, o.alert.severity); }
                 },
                 [&](const std::string &d) {
                     if (d.rfind("known-miss", 0) == 0) sc.known_miss = pqsec::events_file::trim(d.substr(d.find(':') == std::string::npos ? d.size() : d.find(':') + 1));
                     else if (d.rfind("expect-max-severity", 0) == 0) sc.expect_max_sev = pqsec::events_file::trim(d.substr(d.find(':') + 1));
                 });
        scen.push_back(sc);
    }

    // ===== 비용 =====
    auto usd = [](uint64_t hin, uint64_t hout, uint64_t sin, uint64_t sout) {
        return (hin * kHaikuIn + hout * kHaikuOut + sin * kSonnetIn + sout * kSonnetOut) / 1e6;
    };
    const double benign_usd = usd(b_hin, b_hout, b_sin, b_sout);
    const double total_usd = usd(llm.haiku_in, llm.haiku_out, llm.sonnet_in, llm.sonnet_out);

    // ===== 출력 (markdown) =====
    printf("# 탐지 평가 결과 (llm=%s)\n\n", llm_mode.c_str());
    if (!bfiles.empty()) {
        printf("## 1. 정상 코퍼스 — 오탐률·비용 (%zu 파일, %llu 이벤트)\n\n", bfiles.size(),
               static_cast<unsigned long long>(bs.events));
        printf("| 지표 | 값 |\n|---|---:|\n");
        printf("| alert (= 오탐) | %llu / %llu = **%.2f%%** |\n", (unsigned long long)bs.alerts, (unsigned long long)bs.events, pct(bs.alerts, bs.events));
        for (auto &[src, n] : bs.by_source) printf("| &nbsp;&nbsp;오탐 by source `%s` | %llu (%.2f%%) |\n", src.c_str(), (unsigned long long)n, pct(n, bs.events));
        printf("| LLM 도달 (Haiku 호출 이벤트) | %llu (%.1f%%) |\n", (unsigned long long)bs.haiku_calls, pct(bs.haiku_calls, bs.events));
        printf("| Sonnet 도달 | %llu (%.2f%%) |\n", (unsigned long long)bs.sonnet_calls, pct(bs.sonnet_calls, bs.events));
        printf("| 실 API 호출 (메모 후) | %llu (메모 히트 %llu) |\n", (unsigned long long)b_haiku_calls_before_attack, (unsigned long long)(bs.haiku_calls + bs.sonnet_calls - b_haiku_calls_before_attack));
        if (llm_mode == "real") {
            printf("| 토큰 (Haiku in/out, Sonnet in/out) | %llu/%llu, %llu/%llu |\n", (unsigned long long)b_hin, (unsigned long long)b_hout, (unsigned long long)b_sin, (unsigned long long)b_sout);
            printf("| 비용 | $%.4f 총, **$%.4f / 1k 이벤트** (메모 없이면 ×%.1f) |\n", benign_usd, bs.events ? benign_usd * 1000 / bs.events : 0.0,
                   b_haiku_calls_before_attack ? static_cast<double>(bs.haiku_calls + bs.sonnet_calls) / b_haiku_calls_before_attack : 0.0);
        } else {
            printf("| 비용 | n/a (mock) |\n");
        }
        printf("| 지연 룰 경로 median / p90 | %.1f / %.1f µs |\n", p50(bs.lat_rule_us), p90(bs.lat_rule_us));
        printf("| 지연 LLM 경로 median / p90 | %.1f / %.1f µs |\n", p50(bs.lat_llm_us), p90(bs.lat_llm_us));
        printf("\n층별 분포: ");
        for (auto &[l, n] : bs.by_layer) printf("`%s` %.1f%%  ", l.c_str(), pct(n, bs.events));
        printf("\n\n상위 오탐 요약 (top 10):\n\n| n | 이벤트 | source |\n|---:|---|---|\n");
        std::vector<std::pair<uint64_t, std::string>> top;
        for (auto &[s, n] : bs.fp_summary) top.push_back({n, s});
        std::sort(top.rbegin(), top.rend());
        for (size_t i = 0; i < top.size() && i < 10; ++i) printf("| %llu | `%s` | |\n", (unsigned long long)top[i].first, top[i].second.c_str());
        printf("\n");
        J["benign"] = {{"files", bfiles.size()}, {"events", bs.events}, {"alerts", bs.alerts}, {"fpr_pct", pct(bs.alerts, bs.events)},
                       {"by_source", bs.by_source}, {"by_layer", bs.by_layer}, {"haiku_calls", bs.haiku_calls}, {"sonnet_calls", bs.sonnet_calls},
                       {"api_calls", b_haiku_calls_before_attack}, {"tokens", {{"haiku_in", b_hin}, {"haiku_out", b_hout}, {"sonnet_in", b_sin}, {"sonnet_out", b_sout}}},
                       {"usd", benign_usd}, {"lat_rule_us_p50", p50(bs.lat_rule_us)}, {"lat_rule_us_p90", p90(bs.lat_rule_us)},
                       {"lat_llm_us_p50", p50(bs.lat_llm_us)}, {"lat_llm_us_p90", p90(bs.lat_llm_us)}, {"top_fp", top}};
    }

    bool gate_fail = false;
    if (!scen.empty()) {
        printf("## 2. 공격 시나리오 — 탐지율 (%zu 시나리오)\n\n", scen.size());
        printf("| 시나리오 | 이벤트 | expect:alert 탐지 | expect:drop 오탐 | 시나리오 탐지 (≥High) | 최대 심각도 | 기대 심각도 | 결정 층 | 비고 |\n|---|---:|---:|---:|:---:|---|---|---|---|\n");
        uint64_t detected = 0, gated = 0, gated_ok = 0;
        for (Scenario &sc : scen) {
            const bool det = sc.max_sev >= Severity::High;
            const bool sev_ok = sc.expect_max_sev.empty() || sc.max_sev >= parse_sev(sc.expect_max_sev);
            if (det) ++detected;
            if (sc.known_miss.empty()) { ++gated; if (det) ++gated_ok; else gate_fail = true; }
            std::string layers;
            for (auto &[l, n] : sc.layers) if (l != "drop" && l != "haiku-normal") layers += l + "×" + std::to_string(n) + " ";
            printf("| %s | %llu | %llu/%llu | %llu/%llu | %s | %s | %s | %s | %s |\n", sc.name.c_str(), (unsigned long long)sc.events,
                   (unsigned long long)sc.hit_alert, (unsigned long long)sc.expect_alert, (unsigned long long)sc.fp, (unsigned long long)sc.expect_drop,
                   det ? "✅" : "❌", to_string(sc.max_sev),
                   sc.expect_max_sev.empty() ? "-" : (sev_ok ? ("≥" + sc.expect_max_sev + " ✅").c_str() : ("≥" + sc.expect_max_sev + " ❌ (미달)").c_str()),
                   layers.c_str(), sc.known_miss.empty() ? "" : ("known-miss: " + sc.known_miss).c_str());
            J["attack"]["scenarios"].push_back({{"name", sc.name}, {"events", sc.events}, {"expect_alert", sc.expect_alert}, {"hit_alert", sc.hit_alert},
                                                {"expect_drop", sc.expect_drop}, {"fp", sc.fp}, {"detected", det}, {"max_severity", to_string(sc.max_sev)},
                                                {"expect_max_severity", sc.expect_max_sev}, {"severity_met", sev_ok}, {"layers", sc.layers}, {"known_miss", sc.known_miss}});
        }
        printf("\n시나리오 탐지 **%llu/%zu**, 게이트 대상(known-miss 제외) **%llu/%llu**. 공격 코퍼스 LLM 호출: Haiku %llu, Sonnet %llu.\n\n",
               (unsigned long long)detected, scen.size(), (unsigned long long)gated_ok, (unsigned long long)gated,
               (unsigned long long)as.haiku_calls, (unsigned long long)as.sonnet_calls);
        J["attack"]["detected"] = detected; J["attack"]["gated"] = gated; J["attack"]["gated_ok"] = gated_ok;
    }
    if (llm_mode == "real")
        printf("실 API 호출 합계 %llu (메모 히트 %llu, 상한 도달 %llu), 총 비용 $%.4f\n", (unsigned long long)llm.calls, (unsigned long long)llm.hits, (unsigned long long)llm.capped, total_usd);
    J["llm_calls"] = llm.calls; J["memo_hits"] = llm.hits; J["capped"] = llm.capped; J["usd_total"] = total_usd;

    if (!json_out.empty()) {
        std::ofstream out(json_out);
        out << J.dump(2) << "\n";
        fprintf(stderr, "[eval] JSON → %s\n", json_out.c_str());
    }
    if (gate && gate_fail) {
        fprintf(stderr, "[eval] GATE FAIL: known-miss 가 아닌 시나리오 미탐\n");
        return 1;
    }
    return 0;
}
