// agent/src/main.cpp — eBPF collector + (옵션) PQC 채널 전송
//
// 기본(Week 1): eBPF 이벤트를 stdout 으로 출력.
// --forward   : PQC 채널로 analyzer 에 암호화 전송 (client 역할).
// --synthetic : eBPF 없이 합성 이벤트 생성 (권한 불필요, CI/데모용 폴백).
//
//   agent                                   # Week 1 stdout
//   agent --forward --id agent --peer analyzer.pub [--port 9443] [--synthetic]

#include "collector.skel.h"
#include "event.h"

#include "pqsec/handshake.h"
#include "pqsec/identity.h"
#include "pqsec/socket.h"

#include <bpf/libbpf.h>

#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using namespace pqsec;

static volatile sig_atomic_t g_exiting = 0;
static void on_signal(int) { g_exiting = 1; }

// ---- 이벤트 싱크 (출력 or 채널 전송) --------------------------------------
struct EventSink {
    virtual ~EventSink() = default;
    virtual void handle(const security_event &ev) = 0;
};

// Week 1 동작: stdout 구조화 출력
struct StdoutSink : EventSink {
    void handle(const security_event &e) override {
        if (e.type == PQSEC_EVT_EXECVE) {
            printf("EXECVE   pid=%-6u ppid=%-6u comm=%-16s file=%s\n", e.pid, e.ppid, e.comm,
                   e.u.execve.filename);
        } else if (e.type == PQSEC_EVT_TCP_CONNECT) {
            char ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &e.u.tcp.daddr, ip, sizeof(ip));
            printf("CONNECT  pid=%-6u ppid=%-6u comm=%-16s dst=%s:%u\n", e.pid, e.ppid, e.comm,
                   ip, e.u.tcp.dport);
        }
        fflush(stdout);
    }
};

// --forward: security_event 를 암호화해 채널로 전송
class ChannelSink : public EventSink {
public:
    ChannelSink(int fd, RecordSender sender) : fd_(fd), sender_(std::move(sender)) {}
    ~ChannelSink() override { close_fd(fd_); } // EOF → analyzer 수신 종료
    void handle(const security_event &ev) override {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(&ev);
        Bytes rec = sender_.seal(Bytes(p, p + sizeof(ev)));
        send_record(fd_, rec);
        fprintf(stderr, "[agent] 이벤트 암호화 전송 (%s)\n",
                ev.type == PQSEC_EVT_EXECVE ? "execve" : "connect");
    }

private:
    int fd_;
    RecordSender sender_;
};

// ---- ring buffer 콜백 → 싱크 ----------------------------------------------
static int on_event(void *ctx, void *data, size_t size) {
    if (size < sizeof(security_event))
        return 0;
    static_cast<EventSink *>(ctx)->handle(*static_cast<const security_event *>(data));
    return 0;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

// ---- 합성 이벤트 (eBPF 없이) ----------------------------------------------
static security_event syn_execve(const char *comm, const char *file) {
    security_event e{};
    e.type = PQSEC_EVT_EXECVE;
    e.pid = 4242;
    e.ppid = 4200;
    std::strncpy(e.comm, comm, sizeof(e.comm) - 1);
    std::strncpy(e.u.execve.filename, file, sizeof(e.u.execve.filename) - 1);
    return e;
}
static security_event syn_tcp(const char *comm, const char *ip, uint16_t port) {
    security_event e{};
    e.type = PQSEC_EVT_TCP_CONNECT;
    e.pid = 4242;
    e.ppid = 4200;
    std::strncpy(e.comm, comm, sizeof(e.comm) - 1);
    e.u.tcp.family = 2;
    inet_pton(AF_INET, ip, &e.u.tcp.daddr);
    e.u.tcp.dport = port;
    return e;
}

static void run_synthetic(EventSink &sink) {
    const security_event evs[] = {
        syn_execve("bash", "/usr/bin/ls"),        // → drop
        syn_execve("bash", "/tmp/xmrig"),         // → rule alert
        syn_execve("bash", "/usr/bin/curl"),      // → LLM
        syn_tcp("beacon", "45.9.148.99", 4444),   // → rule alert
        syn_tcp("app", "10.0.0.5", 443),          // → drop
    };
    for (const security_event &e : evs)
        sink.handle(e);
}

// ---- 옵션 ------------------------------------------------------------------
struct Options {
    bool forward = false;
    bool synthetic = false;
    uint16_t port = 9443;
    std::string id_prefix = "agent";
    std::string peer_pub = "analyzer.pub";
};

static Options parse_args(int argc, char **argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char *name) -> std::string {
            if (i + 1 >= argc) { fprintf(stderr, "%s 인자 필요\n", name); std::exit(1); }
            return argv[++i];
        };
        if (a == "--forward") o.forward = true;
        else if (a == "--synthetic") o.synthetic = true;
        else if (a == "--port") o.port = static_cast<uint16_t>(std::stoi(next("--port")));
        else if (a == "--id") o.id_prefix = next("--id");
        else if (a == "--peer") o.peer_pub = next("--peer");
        else { fprintf(stderr, "알 수 없는 인자: %s\n", a.c_str()); std::exit(1); }
    }
    return o;
}

// forward 모드: 핸드셰이크 후 ChannelSink 생성
static std::unique_ptr<EventSink> make_forward_sink(const Options &o) {
    Identity id = load_identity(o.id_prefix + ".pub", o.id_prefix + ".key", o.peer_pub);
    int fd = tcp_connect(o.port);
    Transport t = make_socket_transport(fd);
    Channel ch = client_handshake(id, t); // 실패 시 예외
    fprintf(stderr, "[agent] 핸드셰이크 완료 (analyzer 인증됨). 이벤트 전송 시작.\n");
    return std::make_unique<ChannelSink>(fd, std::move(ch.sender));
}

int main(int argc, char **argv) {
    Options o = parse_args(argc, argv);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    // 싱크 구성
    std::unique_ptr<EventSink> sink;
    try {
        sink = o.forward ? make_forward_sink(o)
                         : std::unique_ptr<EventSink>(new StdoutSink());
    } catch (const std::exception &e) {
        fprintf(stderr, "[agent] 채널 연결 실패: %s\n", e.what());
        return 1;
    }

    // 합성 모드: eBPF 없이 이벤트 생성 (권한 불필요)
    if (o.synthetic) {
        fprintf(stderr, "[agent] 합성 이벤트 모드 (eBPF 미사용)\n");
        run_synthetic(*sink);
        fprintf(stderr, "[agent] 합성 이벤트 전송 완료.\n");
        return 0;
    }

    // 실 eBPF 경로
    libbpf_set_print(libbpf_print);
    struct collector_bpf *skel = collector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[agent] BPF 로드 실패 (권한 확인, 또는 --synthetic 사용)\n");
        return 1;
    }
    if (collector_bpf__attach(skel)) {
        fprintf(stderr, "[agent] BPF attach 실패\n");
        collector_bpf__destroy(skel);
        return 1;
    }
    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, sink.get(), nullptr);
    if (!rb) {
        fprintf(stderr, "[agent] ring buffer 생성 실패\n");
        collector_bpf__destroy(skel);
        return 1;
    }

    fprintf(stderr, "[agent] collector 가동%s. Ctrl-C 종료.\n",
            o.forward ? " (채널 전송)" : " (stdout)");
    while (!g_exiting) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "[agent] poll 오류: %d\n", err);
            break;
        }
    }
    fprintf(stderr, "\n[agent] 종료, 정리 중...\n");
    ring_buffer__free(rb);
    collector_bpf__destroy(skel);
    return 0;
}
