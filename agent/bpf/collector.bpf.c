// collector.bpf.c
//
// 세 훅을 하나의 BPF 오브젝트에 담고, 공유 ring buffer 로 이벤트를 올린다.
//   - ksyscall/execve        : 프로세스 실행 (filename)
//   - fentry/tcp_v4_connect  : IPv4 아웃바운드 커넥션 시도
//   - fentry/security_file_open : 스테이징 쓰기(/tmp 등) or 민감파일 읽기(inode 매칭)
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
#define AF_INET      2
#define FMODE_WRITE  0x2    // include/linux/fs.h
#define FMODE_EXEC   0x20
#define O_CREAT      0x40   // 0100 octal

// 공유 ring buffer (256 KB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 민감파일 inode 집합 — 유저스페이스가 stat 으로 (ino,dev) 를 채운다.
// 경로가 아니라 inode 아이덴티티로 매칭 → 심링크·하드링크·바인드마운트 우회에 강함.
struct sens_key {
    __u64 ino;
    __u32 dev;
    __u32 _pad;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct sens_key);
    __type(value, __u8);
} sensitive_inodes SEC(".maps");

// d_path 용 per-cpu 스크래치 (스택 절약 + 매 쓰기마다 ringbuf 예약 회피)
struct path_buf { char buf[PQSEC_FILENAME_LEN]; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_buf);
} scratch SEC(".maps");

// 이벤트 시점 조상 스냅샷 (부모 real_parent 체인 PQSEC_ANCESTORS 세대)
static __always_inline void fill_ancestry(struct security_event *e, struct task_struct *task)
{
    struct task_struct *t = task;
#pragma unroll
    for (int i = 0; i < PQSEC_ANCESTORS; i++) {
        t = BPF_CORE_READ(t, real_parent);
        if (!t)
            break;
        e->anc[i].pid = BPF_CORE_READ(t, tgid);
        BPF_CORE_READ_STR_INTO(&e->anc[i].comm, t, comm);
    }
}

// 공통 필드 (pid/ppid/comm/ts + 조상)
static __always_inline void fill_common(struct security_event *e, __u32 type)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->type  = type;
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->ppid  = BPF_CORE_READ(task, real_parent, tgid);
    e->ts_ns = bpf_ktime_get_ns();
    e->_pad  = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    fill_ancestry(e, task);
}

// --- execve ----------------------------------------------------------------
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
    e->u.tcp.daddr  = BPF_CORE_READ(sin, sin_addr.s_addr);
    e->u.tcp.dport  = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 절대경로가 스테이징 디렉토리(/tmp, /var/tmp, /dev/shm)인지
static __always_inline int is_staging(const char *p)
{
    if (p[0] != '/')
        return 0;
    if (p[1] == 't' && p[2] == 'm' && p[3] == 'p' && p[4] == '/')
        return 1; // /tmp/
    if (p[1] == 'v' && p[2] == 'a' && p[3] == 'r' && p[4] == '/' &&
        p[5] == 't' && p[6] == 'm' && p[7] == 'p' && p[8] == '/')
        return 1; // /var/tmp/
    if (p[1] == 'd' && p[2] == 'e' && p[3] == 'v' && p[4] == '/' &&
        p[5] == 's' && p[6] == 'h' && p[7] == 'm' && p[8] == '/')
        return 1; // /dev/shm/
    return 0;
}

// --- file open -------------------------------------------------------------
// 시스템 전체 open 마다 실행되므로 커널 안에서 강하게 필터하고, 흥미로운 것만 ringbuf 에 올린다.
//   민감파일 읽기: inode 집합 매칭 (경로 불필요)
//   스테이징 쓰기: FMODE_WRITE + d_path 접두사(/tmp 등) — 실행이 뒤따르면 코릴레이터가 체인으로 판정
SEC("fentry/security_file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
    fmode_t mode = BPF_CORE_READ(file, f_mode);
    struct inode *inode = BPF_CORE_READ(file, f_inode);

    struct sens_key k = {};
    k.ino = BPF_CORE_READ(inode, i_ino);
    k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    __u8 *sens = bpf_map_lookup_elem(&sensitive_inodes, &k);

    const int is_write = (mode & FMODE_WRITE) != 0;
    if (!sens && !is_write)
        return 0; // 대다수(순수 읽기·실행 open)는 여기서 버림

    __u32 access = 0;
    char *path = NULL;
    if (is_write) {
        // d_path 로 절대경로를 스크래치에 받아 스테이징인지 커널에서 판정 (아니면 예약 안 함)
        __u32 zero = 0;
        struct path_buf *pb = bpf_map_lookup_elem(&scratch, &zero);
        if (!pb)
            return 0;
        long n = bpf_d_path(&file->f_path, pb->buf, sizeof(pb->buf));
        if (n < 0)
            return 0;
        if (!sens && !is_staging(pb->buf))
            return 0; // 스테이징도 민감도 아니면 버림 (일반 쓰기는 무시)
        access |= PQSEC_FA_WRITE;
        path = pb->buf;
    }
    if (sens)
        access |= PQSEC_FA_SENSITIVE;
    if (mode & FMODE_EXEC)
        access |= PQSEC_FA_EXEC;

    struct security_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    fill_common(e, PQSEC_EVT_FILE_OPEN);
    e->u.file.access = access;
    e->u.file._pad = 0;
    e->u.file._pad2 = 0;
    e->u.file.ino = k.ino;
    e->u.file.dev = k.dev;
    e->u.file.path[0] = '\0';
    if (path)
        bpf_probe_read_kernel_str(&e->u.file.path, sizeof(e->u.file.path), path);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
