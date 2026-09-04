// analyzer/src/main.cpp — analyzer 데몬
//
// PQC 채널 서버 엔드포인트. 상호인증 핸드셰이크 → 암호 레코드 수신·복호 →
// security_event 디코드 → 분류 파이프라인(prefilter+correlator → Haiku → Sonnet) → alert.
//
// LLM 선택: --mock-llm 이거나 ANTHROPIC_API_KEY 가 없으면 Mock, 아니면 Claude API.
// --bind   : 리슨 주소. 기본 127.0.0.1, 컨테이너 안에서는 0.0.0.0 (포트 매핑용).
//
//   analyzer --id analyzer --peer agent.pub [--bind 127.0.0.1] [--port 9443] [--mock-llm] [--once]

#include "correlator.h"
#include "llm_client.h"
#include "pipeline.h"

#include "pqsec/handshake.h"
#include "pqsec/identity.h"
#include "pqsec/socket.h"

#include "event.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using namespace pqsec;
using namespace pqsec::analyzer;

static volatile sig_atomic_t g_exiting = 0;
static void on_signal(int) { g_exiting = 1; }

struct Options {
    uint16_t port = 9443;
    std::string bind_ip = "127.0.0.1";
    std::string id_prefix = "analyzer";
    std::string peer_pub = "agent.pub";
    bool mock_llm = false;
    bool once = false;
};

static Options parse_args(int argc, char **argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char *name) -> std::string {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s 인자 필요\n", name);
                std::exit(1);
            }
            return argv[++i];
        };
        if (a == "--port") o.port = static_cast<uint16_t>(std::stoi(next("--port")));
        else if (a == "--bind") o.bind_ip = next("--bind");
        else if (a == "--id") o.id_prefix = next("--id");
        else if (a == "--peer") o.peer_pub = next("--peer");
        else if (a == "--mock-llm") o.mock_llm = true;
        else if (a == "--once") o.once = true;
        else { fprintf(stderr, "알 수 없는 인자: %s\n", a.c_str()); std::exit(1); }
    }
    return o;
}

static std::unique_ptr<LlmClient> make_llm(const Options &o) {
    const char *key = std::getenv("ANTHROPIC_API_KEY");
    if (!o.mock_llm && key && *key) {
        fprintf(stderr, "[analyzer] LLM: Claude API (Haiku→Sonnet)\n");
        return std::make_unique<ClaudeLlmClient>(key);
    }
    fprintf(stderr, "[analyzer] LLM: mock (%s)\n",
            o.mock_llm ? "--mock-llm" : "ANTHROPIC_API_KEY 없음");
    return std::make_unique<MockLlmClient>();
}

// 한 연결 처리: 핸드셰이크 → 레코드 수신·복호·분류
static void serve_connection(int cfd, const Identity &id, LlmClient &llm, Correlator &corr) {
    Transport t = make_socket_transport(cfd);
    Channel ch = server_handshake(id, t); // 실패 시 예외
    fprintf(stderr, "[analyzer] 핸드셰이크 완료 (agent 인증됨). 이벤트 수신·분류 시작.\n");

    int n = 0;
    for (;;) {
        Bytes rec = recv_record(cfd);
        if (rec.empty())
            break; // agent 종료
        Bytes pt = ch.receiver.open(rec); // 복호+태그검증 (실패 시 예외)
        if (pt.size() < sizeof(security_event)) {
            fprintf(stderr, "[analyzer] 짧은 이벤트 무시\n");
            continue;
        }
        const security_event *ev = reinterpret_cast<const security_event *>(pt.data());
        ++n;
        process_event(*ev, llm, corr);
    }
    fprintf(stderr, "[analyzer] 연결 종료 (%d개 이벤트 처리).\n", n);
}

int main(int argc, char **argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    Options o = parse_args(argc, argv);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    Identity id;
    try {
        id = load_identity(o.id_prefix + ".pub", o.id_prefix + ".key", o.peer_pub);
    } catch (const std::exception &e) {
        fprintf(stderr, "[analyzer] 신원 로드 실패: %s\n", e.what());
        return 1;
    }
    std::unique_ptr<LlmClient> llm = make_llm(o);
    Correlator corr; // 코릴레이션 상태는 연결을 넘어 데몬 수명 동안 유지

    int lfd = -1;
    try {
        lfd = tcp_listen(o.port, o.bind_ip);
    } catch (const std::exception &e) {
        fprintf(stderr, "[analyzer] 리슨 실패: %s\n", e.what());
        return 1;
    }
    fprintf(stderr, "[analyzer] 리슨: %s:%u (Ctrl-C 종료)\n", o.bind_ip.c_str(), o.port);

    while (!g_exiting) {
        int cfd = -1;
        try {
            cfd = tcp_accept(lfd);
            serve_connection(cfd, id, *llm, corr);
        } catch (const std::exception &e) {
            fprintf(stderr, "[analyzer] 연결 처리 오류: %s\n", e.what());
        }
        if (cfd >= 0)
            close_fd(cfd);
        if (o.once)
            break;
    }
    close_fd(lfd);
    return 0;
}
