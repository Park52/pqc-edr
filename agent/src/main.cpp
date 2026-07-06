// agent/src/main.cpp
//
// eBPF collector 유저스페이스 로더.
//   skeleton 로드/attach → ring buffer 폴링 → security_event 디코드 → stdout 출력.
// Week 1 범위: 네트워크·암호화 없음. 콘솔로 이벤트가 흐르는 것까지.

#include "collector.skel.h"
#include "event.h"

#include <bpf/libbpf.h>

#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>

static volatile sig_atomic_t g_exiting = 0;

static void on_signal(int) { g_exiting = 1; }

// libbpf 내부 로그: 경고 이상만 출력
static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void print_execve(const security_event *e)
{
    printf("EXECVE   pid=%-6u ppid=%-6u comm=%-16s file=%s\n",
           e->pid, e->ppid, e->comm, e->u.execve.filename);
}

static void print_tcp(const security_event *e)
{
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &e->u.tcp.daddr, ip, sizeof(ip));
    printf("CONNECT  pid=%-6u ppid=%-6u comm=%-16s dst=%s:%u\n",
           e->pid, e->ppid, e->comm, ip, e->u.tcp.dport);
}

// ring buffer 콜백: 커널이 올린 레코드 하나
static int handle_event(void * /*ctx*/, void *data, size_t size)
{
    if (size < sizeof(security_event)) {
        fprintf(stderr, "짧은 이벤트 무시 (%zu bytes)\n", size);
        return 0;
    }
    const security_event *e = static_cast<const security_event *>(data);

    switch (e->type) {
    case PQSEC_EVT_EXECVE:      print_execve(e); break;
    case PQSEC_EVT_TCP_CONNECT: print_tcp(e);    break;
    default:
        fprintf(stderr, "알 수 없는 이벤트 타입 %u\n", e->type);
        break;
    }
    fflush(stdout);
    return 0;
}

int main()
{
    libbpf_set_print(libbpf_print);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct collector_bpf *skel = collector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "BPF skeleton open/load 실패 (권한/커널 확인)\n");
        return 1;
    }

    if (collector_bpf__attach(skel)) {
        fprintf(stderr, "BPF 프로그램 attach 실패\n");
        collector_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, nullptr, nullptr);
    if (!rb) {
        fprintf(stderr, "ring buffer 생성 실패\n");
        collector_bpf__destroy(skel);
        return 1;
    }

    fprintf(stderr, "[agent] collector 가동. Ctrl-C 로 종료.\n");

    while (!g_exiting) {
        int err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "ring buffer poll 오류: %d\n", err);
            break;
        }
    }

    fprintf(stderr, "\n[agent] 종료, 정리 중...\n");
    ring_buffer__free(rb);
    collector_bpf__destroy(skel);
    return 0;
}
