// agent/src/main.cpp — eBPF collector + (옵션) PQC 채널 전송
//
// 기본(Week 1): eBPF 이벤트를 stdout 으로 출력.
// --forward      : PQC 채널로 analyzer 에 암호화 전송 (client 역할).
// --synthetic    : eBPF 없이 내장 합성 이벤트 5건 (권한 불필요, CI/데모용 폴백).
// --replay FILE  : eBPF 없이 이벤트 파일 재생 (위협 시나리오 폴백, scenarios/*.events).
//
//   agent                                   # Week 1 stdout
//   agent --forward --id agent --peer analyzer.pub [--host 127.0.0.1] [--port 9443] [--queue 4096]
//         [--synthetic | --replay FILE]

#include "collector.skel.h"
#include "event.h"

#include "pqsec/handshake.h"
#include "pqsec/identity.h"
#include "pqsec/socket.h"

#include <bpf/libbpf.h>

#include <arpa/inet.h>
#include <unistd.h>

#include <algorithm>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

using namespace pqsec;

static volatile sig_atomic_t g_exiting = 0;
static void on_signal(int) { g_exiting = 1; }

// bpf_ktime_get_ns 와 같은 시계(CLOCK_MONOTONIC) — 합성/재생 이벤트의 ts_ns 용
static uint64_t now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

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

// --forward: security_event 를 암호화해 채널로 전송 — 백프레셔 처리.
//
//   ring buffer 콜백(handle) ──복사──▶ 유한 큐 ──▶ 송신 스레드: seal + send
//
// - handle() 은 절대 블록하지 않는다. analyzer 가 느려(예: 실 LLM 호출 수백 ms) 소켓 버퍼와 큐가
//   차면 커널 ring buffer 폴링을 막는 대신 **유저스페이스에서 드롭하고 개수를 센다.**
//   (커널 드롭은 보이지 않지만 여기 드롭은 셀 수 있다.)
// - RecordSender 의 seq 는 송신 스레드만 만지므로 레코드 순서·nonce 가 흔들리지 않는다.
// - 정체가 풀리면 드롭 수를 PQSEC_EVT_AGENT_DROP 이벤트로 analyzer 에 통지한다 —
//   유실은 조용히 넘기지 않는다(analyzer 가 "탐지 공백" alert 로 surface).
// - 종료 시 큐를 드레인한 뒤 fd 를 닫는다. 전송 실패(analyzer 사망)는 즉시 종료.
class ChannelSink : public EventSink {
public:
    ChannelSink(int fd, RecordSender sender, size_t capacity)
        : fd_(fd), sender_(std::move(sender)), capacity_(capacity),
          thread_([this] { run(); }) {}

    ~ChannelSink() override {
        {
            std::lock_guard<std::mutex> lk(m_);
            stop_ = true;
        }
        cv_.notify_all();
        thread_.join(); // 남은 큐 전송 후 종료
        close_fd(fd_);  // EOF → analyzer 수신 종료
        fprintf(stderr, "[agent] 전송 통계: sent=%llu dropped=%llu queue_peak=%zu/%zu\n",
                static_cast<unsigned long long>(sent_), static_cast<unsigned long long>(dropped_),
                peak_, capacity_);
    }

    // ring buffer 콜백 스레드 — 큐에 복사 or 드롭, 블록 없음
    void handle(const security_event &ev) override {
        std::lock_guard<std::mutex> lk(m_);
        if (broken_)
            return;
        if (q_.size() >= capacity_) {
            ++dropped_;
            ++dropped_pending_;
            return;
        }
        q_.push_back(ev);
        peak_ = std::max(peak_, q_.size());
        cv_.notify_one();
    }

private:
    void run() {
        for (;;) {
            security_event ev{};
            uint64_t report = 0, report_total = 0;
            {
                std::unique_lock<std::mutex> lk(m_);
                cv_.wait(lk, [&] { return stop_ || !q_.empty(); });
                if (q_.empty())
                    return; // stop_ 이고 드레인 완료
                ev = q_.front();
                q_.pop_front();
                // 드롭이 있었고 큐가 절반 이하로 내려왔으면(정체 해소) 통지 1건을 끼운다
                if (dropped_pending_ > 0 && q_.size() <= capacity_ / 2) {
                    report = dropped_pending_;
                    report_total = dropped_;
                    dropped_pending_ = 0;
                }
            }
            if (!send_one(ev))
                return;
            if (report > 0 && !send_one(make_drop_notice(report, report_total)))
                return;
        }
    }

    bool send_one(const security_event &ev) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(&ev);
        try {
            send_record(fd_, sender_.seal(Bytes(p, p + sizeof(ev))));
        } catch (const std::exception &e) {
            fprintf(stderr, "[agent] 채널 전송 실패, 종료: %s\n", e.what());
            std::lock_guard<std::mutex> lk(m_);
            broken_ = true;
            g_exiting = 1;
            return false;
        }
        ++sent_;
        if (ev.type == PQSEC_EVT_AGENT_DROP)
            fprintf(stderr, "[agent] 백프레셔 드롭 통지 전송: %llu개 유실 (누적 %llu)\n",
                    static_cast<unsigned long long>(ev.u.drop.dropped),
                    static_cast<unsigned long long>(ev.u.drop.dropped_total));
        else
            fprintf(stderr, "[agent] 이벤트 암호화 전송 (%s)\n",
                    ev.type == PQSEC_EVT_EXECVE ? "execve" : "connect");
        return true;
    }

    security_event make_drop_notice(uint64_t dropped, uint64_t dropped_total) const {
        security_event e{};
        e.type = PQSEC_EVT_AGENT_DROP;
        e.pid = static_cast<uint32_t>(getpid());
        e.ts_ns = now_ns();
        std::strncpy(e.comm, "agent", sizeof(e.comm) - 1);
        e.u.drop.dropped = dropped;
        e.u.drop.dropped_total = dropped_total;
        e.u.drop.sent_total = sent_;
        return e;
    }

    int fd_;
    RecordSender sender_;  // 송신 스레드 전용
    size_t capacity_;

    std::mutex m_;
    std::condition_variable cv_;
    std::deque<security_event> q_;
    bool stop_ = false;
    bool broken_ = false;
    uint64_t dropped_ = 0;         // 누적 드롭 (lock)
    uint64_t dropped_pending_ = 0; // 아직 통지하지 않은 드롭 (lock)
    size_t peak_ = 0;              // 큐 최대 점유 (lock)
    uint64_t sent_ = 0;            // 송신 스레드 전용

    std::thread thread_; // 마지막에 선언 — 위 멤버가 모두 초기화된 뒤 시작
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
static security_event syn_execve(const char *comm, const char *file, uint32_t pid = 4242,
                                 uint32_t ppid = 4200) {
    security_event e{};
    e.type = PQSEC_EVT_EXECVE;
    e.pid = pid;
    e.ppid = ppid;
    e.ts_ns = now_ns();
    std::strncpy(e.comm, comm, sizeof(e.comm) - 1);
    std::strncpy(e.u.execve.filename, file, sizeof(e.u.execve.filename) - 1);
    return e;
}
static security_event syn_tcp(const char *comm, const char *ip, uint16_t port,
                              uint32_t pid = 4242, uint32_t ppid = 4200) {
    security_event e{};
    e.type = PQSEC_EVT_TCP_CONNECT;
    e.pid = pid;
    e.ppid = ppid;
    e.ts_ns = now_ns();
    std::strncpy(e.comm, comm, sizeof(e.comm) - 1);
    e.u.tcp.family = 2;
    if (inet_pton(AF_INET, ip, &e.u.tcp.daddr) != 1)
        throw std::runtime_error(std::string("잘못된 IPv4 주소: ") + ip);
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

// 재생 파일 (scenarios/*.events). 한 줄 = 한 항목, '#' 이후는 주석.
//   execve  <pid> <ppid> <comm> <filename>
//   connect <pid> <ppid> <comm> <ipv4> <port>
//   delay   <ms>
// 형식 오류는 예외(fail-closed) — 잘못된 시나리오를 조용히 절반만 재생하지 않는다.
static void run_replay(const std::string &path, EventSink &sink) {
    std::ifstream in(path);
    if (!in)
        throw std::runtime_error("재생 파일 열기 실패: " + path);

    std::string line;
    int lineno = 0, n = 0;
    while (std::getline(in, line)) {
        ++lineno;
        std::istringstream is(line.substr(0, line.find('#')));
        std::string kind;
        if (!(is >> kind))
            continue; // 빈 줄/주석
        auto bad = [&](const char *why) {
            throw std::runtime_error(path + ":" + std::to_string(lineno) + " " + why);
        };

        if (kind == "delay") {
            long ms = -1;
            if (!(is >> ms) || ms < 0)
                bad("delay <ms> 형식 오류");
            timespec ts{ms / 1000, (ms % 1000) * 1000000L};
            nanosleep(&ts, nullptr);
            continue;
        }

        uint32_t pid = 0, ppid = 0;
        std::string comm;
        if (!(is >> pid >> ppid >> comm))
            bad("<pid> <ppid> <comm> 형식 오류");

        if (kind == "execve") {
            std::string file;
            if (!(is >> file))
                bad("execve <filename> 누락");
            sink.handle(syn_execve(comm.c_str(), file.c_str(), pid, ppid));
        } else if (kind == "connect") {
            std::string ip;
            unsigned port = 0;
            if (!(is >> ip >> port) || port > 65535)
                bad("connect <ipv4> <port> 형식 오류");
            sink.handle(syn_tcp(comm.c_str(), ip.c_str(), static_cast<uint16_t>(port), pid, ppid));
        } else {
            bad("알 수 없는 항목 종류");
        }
        ++n;
    }
    fprintf(stderr, "[agent] 재생 완료: %d 이벤트 (%s)\n", n, path.c_str());
}

// ---- 옵션 ------------------------------------------------------------------
struct Options {
    bool forward = false;
    bool synthetic = false;
    std::string replay_file;
    std::string host = "127.0.0.1";
    uint16_t port = 9443;
    std::string id_prefix = "agent";
    std::string peer_pub = "analyzer.pub";
    size_t queue = 4096; // 송신 큐 용량(이벤트 수). 168B × 4096 ≈ 690KB
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
        else if (a == "--replay") o.replay_file = next("--replay");
        else if (a == "--host") o.host = next("--host");
        else if (a == "--port") o.port = static_cast<uint16_t>(std::stoi(next("--port")));
        else if (a == "--queue") o.queue = static_cast<size_t>(std::stoul(next("--queue")));
        else if (a == "--id") o.id_prefix = next("--id");
        else if (a == "--peer") o.peer_pub = next("--peer");
        else { fprintf(stderr, "알 수 없는 인자: %s\n", a.c_str()); std::exit(1); }
    }
    if (o.synthetic && !o.replay_file.empty()) {
        fprintf(stderr, "--synthetic 과 --replay 는 동시에 쓸 수 없음\n");
        std::exit(1);
    }
    if (o.queue == 0) {
        fprintf(stderr, "--queue 는 1 이상\n");
        std::exit(1);
    }
    return o;
}

// forward 모드: 핸드셰이크 후 ChannelSink 생성
static std::unique_ptr<EventSink> make_forward_sink(const Options &o) {
    Identity id = load_identity(o.id_prefix + ".pub", o.id_prefix + ".key", o.peer_pub);
    int fd = tcp_connect(o.port, o.host);
    Transport t = make_socket_transport(fd);
    Channel ch = client_handshake(id, t); // 실패 시 예외
    fprintf(stderr, "[agent] 핸드셰이크 완료 (analyzer %s:%u 인증됨). 이벤트 전송 시작.\n",
            o.host.c_str(), o.port);
    return std::make_unique<ChannelSink>(fd, std::move(ch.sender), o.queue);
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

    // eBPF 없는 경로: 합성 / 재생 (권한 불필요)
    if (o.synthetic || !o.replay_file.empty()) {
        try {
            if (o.synthetic) {
                fprintf(stderr, "[agent] 합성 이벤트 모드 (eBPF 미사용)\n");
                run_synthetic(*sink);
                fprintf(stderr, "[agent] 합성 이벤트 전송 완료.\n");
            } else {
                fprintf(stderr, "[agent] 재생 모드 (eBPF 미사용): %s\n", o.replay_file.c_str());
                run_replay(o.replay_file, *sink);
            }
        } catch (const std::exception &e) {
            fprintf(stderr, "[agent] 재생 실패: %s\n", e.what());
            return 1;
        }
        return 0;
    }

    // 실 eBPF 경로
    libbpf_set_print(libbpf_print);
    struct collector_bpf *skel = collector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[agent] BPF 로드 실패 (권한 확인, 또는 --synthetic/--replay 사용)\n");
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
    ring_buffer__consume(rb); // 종료 직전 ring buffer 에 남은 이벤트 드레인
    ring_buffer__free(rb);
    collector_bpf__destroy(skel);
    return 0;
}
