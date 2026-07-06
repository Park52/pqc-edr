// collector.bpf.c
//
// 두 개의 훅을 하나의 BPF 오브젝트에 담고, 공유 ring buffer 로 이벤트를 올린다.
//   - tp/syscalls/sys_enter_execve : 프로세스 실행 (filename)
//   - fentry/tcp_v4_connect        : IPv4 아웃바운드 커넥션 시도
//
// CO-RE: 커널 타입은 vmlinux.h 로만 접근하고, 필드 접근은 BPF_CORE_READ 로
// 재배치 가능하게 한다 → 커널 버전이 달라도 재컴파일 없이 로드 가능.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

// UAPI 상수 (vmlinux.h 에는 커널 struct 만 있고 이런 상수는 없음)
#define AF_INET 2

// 공유 ring buffer (256 KB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 두 훅이 공통으로 채우는 필드 (pid/ppid/comm/ts)
static __always_inline void fill_common(struct security_event *e, __u32 type)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->type  = type;
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->ppid  = BPF_CORE_READ(task, real_parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->_pad  = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// --- execve ----------------------------------------------------------------
// 레거시 tracepoint(tp/syscalls/...) 는 attach 시 tracefs 의 root 전용 id 파일을
// 읽어야 해서 CAP_BPF/CAP_PERFMON 만으로는 non-root attach 가 불가능하다.
// ksyscall 은 kprobe PMU 로 붙어 그 파일을 읽지 않으므로 최소권한으로 동작한다.
// BPF_KSYSCALL 이 아키텍처 접두사와 syscall 인자 언래핑을 자동 처리한다.
SEC("ksyscall/execve")
int BPF_KSYSCALL(handle_execve, const char *filename,
                 const char *const *argv, const char *const *envp)
{
    struct security_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, PQSEC_EVT_EXECVE);
    bpf_probe_read_user_str(&e->u.execve.filename, sizeof(e->u.execve.filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- tcp connect (IPv4) ----------------------------------------------------
// tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
// 진입 시점에는 sk 의 목적지가 아직 안 채워졌을 수 있어 uaddr 에서 직접 읽는다.
SEC("fentry/tcp_v4_connect")
int BPF_PROG(handle_tcp_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;

    struct security_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, PQSEC_EVT_TCP_CONNECT);

    e->u.tcp.family = AF_INET;
    e->u.tcp._pad   = 0;
    e->u.tcp.daddr  = BPF_CORE_READ(sin, sin_addr.s_addr);            // 네트워크 바이트오더 유지
    e->u.tcp.dport  = bpf_ntohs(BPF_CORE_READ(sin, sin_port));        // 호스트 바이트오더로 변환

    bpf_ringbuf_submit(e, 0);
    return 0;
}
