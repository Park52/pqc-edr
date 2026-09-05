/* common/event.h
 *
 * Agent(eBPF) ↔ 유저스페이스 ↔ (Week 2+) Analyzer 가 공유하는 이벤트 스키마.
 * 고정 크기 POD 구조체 하나. 직렬화 = 바이트 그대로(호스트 엔디안).
 * Week 2에서 네트워크 채널이 생기면 이 앞에 length-prefix 프레이밍만 덧댄다.
 *
 * 주의: BPF 소스는 vmlinux.h 를 먼저 include 한 뒤 이 헤더를 include 해야 한다
 * (아래 __u* 타입 정의가 vmlinux.h 와 충돌하지 않도록).
 */
#ifndef PQSEC_EVENT_H
#define PQSEC_EVENT_H

/* BPF 측은 vmlinux.h 가 __u8/__u16/__u32/__u64 를 제공한다.
 * 유저스페이스(vmlinux.h 없음)는 커널과 동일한 정의를 <linux/types.h> 에서 가져온다. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define PQSEC_COMM_LEN     16   /* TASK_COMM_LEN */
#define PQSEC_FILENAME_LEN 128  /* execve 실행 경로 최대 길이 */

enum pqsec_event_type {
    PQSEC_EVT_EXECVE      = 1,
    PQSEC_EVT_TCP_CONNECT = 2,
    PQSEC_EVT_AGENT_DROP  = 3,  /* agent 유저스페이스 생성: 백프레셔로 유실된 이벤트 수 통지 */
};

/* IPv4 아웃바운드 커넥션 시도 */
struct pqsec_tcp_event {
    __u32 daddr;   /* 목적지 IPv4 (네트워크 바이트오더) */
    __u16 dport;   /* 목적지 포트 (호스트 바이트오더로 변환해 저장) */
    __u8  family;  /* AF_INET */
    __u8  _pad;
};

/* execve 실행 */
struct pqsec_execve_event {
    char filename[PQSEC_FILENAME_LEN];
};

/* agent 백프레셔 드롭 통지 (커널이 아니라 agent 유저스페이스가 만든다).
 * analyzer 가 느려 송신 큐가 찼을 때 버린 이벤트 수 — 유실을 조용히 넘기지 않기 위한 것. */
struct pqsec_drop_event {
    __u64 dropped;        /* 이번 통지 구간에서 유실된 이벤트 수 */
    __u64 dropped_total;  /* agent 시작 이후 누적 유실 */
    __u64 sent_total;     /* agent 시작 이후 누적 전송 (이 통지 직전까지) */
};

/* ring buffer 로 전달되는 단일 이벤트 레코드 */
struct security_event {
    __u32 type;                 /* enum pqsec_event_type */
    __u32 pid;
    __u32 ppid;
    __u32 _pad;
    __u64 ts_ns;                /* bpf_ktime_get_ns() */
    char  comm[PQSEC_COMM_LEN]; /* 프로세스 이름 */
    union {
        struct pqsec_execve_event execve;
        struct pqsec_tcp_event    tcp;
        struct pqsec_drop_event   drop;
    } u;
};

#endif /* PQSEC_EVENT_H */
