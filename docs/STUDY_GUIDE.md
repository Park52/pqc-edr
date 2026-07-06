# PQSec-Pipeline 학습 가이드 (Week 1 ~ Week 2 Part 2)

> **전제: eBPF·암호학을 처음 본다고 가정.** 지금까지 만든 코드를 밑바닥부터
> 이해하는 것이 목표. 각 개념을 실제 우리 코드에 연결해서 설명한다.
> 순서대로 읽으면 되고, 이미 아는 부분은 건너뛰어도 된다.

## 목차
- [Part 0. 큰 그림](#part-0-큰-그림)
- [Part 1. 리눅스 기초](#part-1-리눅스-기초-꼭-필요한-것만)
- [Part 2. eBPF 제로베이스](#part-2-ebpf-제로베이스)
- [Part 3. Week 1 코드 리뷰](#part-3-week-1-코드-리뷰)
- [Part 4. 암호학 기초](#part-4-암호학-기초-제로베이스)
- [Part 5. 양자내성암호(PQC)](#part-5-양자내성암호-pqc)
- [Part 6. Week 2 코드 리뷰](#part-6-week-2-코드-리뷰)
- [Part 7. C++ / 빌드 관용구](#part-7-c--빌드-관용구)

---

## Part 0. 큰 그림

우리가 만드는 것: **엔드포인트(호스트)에서 보안 이벤트를 수집해, 양자내성 암호로
보호된 채널로 보내고, 서버에서 분석**하는 파이프라인.

```
  [호스트]                           암호화 채널                     [서버/컨테이너]
  agent                        (PQC 하이브리드 mTLS)                analyzer
  ┌─────────────┐                                                 ┌──────────────┐
  │ eBPF 프로그램 │  프로세스 실행/접속 감시                          │ 이벤트 복호   │
  │ (커널 안)    │──┐                                              │ LLM 분류     │
  └─────────────┘  │ ring buffer                                  └──────────────┘
  ┌─────────────┐  ▼                    핸드셰이크 →                      ▲
  │ 유저 프로그램 │ 이벤트 수신 → 직렬화 → 암호화 ───────────────────────────┘
  └─────────────┘
      Week 1                          Week 2                        Week 3
```

- **Week 1** = 왼쪽(eBPF 수집). 커널에서 일어나는 일을 잡아 유저 프로그램으로 올린다.
- **Week 2** = 가운데(암호 채널). 두 프로그램이 안전하게 대화하는 법.
- **Week 3** = 오른쪽(LLM 분석). 아직.

---

## Part 1. 리눅스 기초 (꼭 필요한 것만)

### 1.1 커널 vs 유저스페이스
운영체제는 두 세계로 나뉜다:
- **커널(kernel)**: 하드웨어를 직접 다루는 특권 코드. 메모리·CPU·디스크·네트워크를
  전부 통제. 하나뿐이고 항상 떠 있다.
- **유저스페이스(userspace)**: 우리가 실행하는 일반 프로그램들(브라우저, `ls`, 우리 agent).
  하드웨어를 직접 못 만지고, 필요하면 **커널에게 부탁**한다.

이 "부탁"이 **시스템콜(syscall)**. 예: 파일 읽기(`read`), 프로세스 실행(`execve`),
네트워크 연결(`connect`). 유저 프로그램이 뭔가 의미 있는 일을 하려면 거의 항상 syscall을
거친다. → **그래서 syscall을 감시하면 시스템에서 일어나는 일을 대부분 관측할 수 있다.**
이게 우리 eBPF 수집의 핵심 발상.

### 1.2 프로세스, PID, execve
- **프로세스**: 실행 중인 프로그램 하나. 각자 고유 번호 **PID**를 가진다.
- 프로세스는 다른 프로세스가 낳는다(부모→자식). 부모의 PID = **PPID**.
- 새 프로그램을 실행할 때 `execve` syscall을 호출한다: "지금 이 프로세스를 이 실행파일로
  바꿔치기해라". 예를 들어 셸에서 `ls`를 치면 셸이 자식을 만들고 그 자식이 `execve("/usr/bin/ls")`.
- → **우리 collector가 execve를 잡는 이유**: "누가 무엇을 실행했나"가 침입 탐지의 1순위 신호.
  (악성코드 실행, 수상한 명령 체인 등)

우리 코드에서 이벤트에 `pid`, `ppid`, `comm`(프로세스 이름), `filename`(실행파일 경로)을
담는 이유가 이것 — "어떤 프로세스가 무엇을 실행했나"를 재구성하려고.

### 1.3 TCP connect
- 프로그램이 외부와 통신하려면 **소켓(socket)**을 만들고 `connect(목적지 IP:포트)` syscall을 호출.
- → **collector가 tcp connect를 잡는 이유**: "이 호스트가 어디로 접속을 시도하나"가
  악성 아웃바운드(C2 서버 접속, 데이터 유출)의 신호.

### 1.4 권한: root, capability, DAC (Week 1에서 크게 데인 부분)
리눅스 권한은 **두 개의 독립된 검사**로 이뤄진다. 이걸 구분하는 게 핵심:

| 검사 | 질문 | 우회 열쇠 |
|---|---|---|
| **Capability** | "이 프로세스가 이 *특권 연산(syscall)* 을 할 자격이 있나?" | `CAP_BPF`, `CAP_PERFMON` 등 |
| **DAC** (파일권한) | "이 프로세스가 이 *파일* 을 읽/쓸 자격이 있나?" | 파일 소유자거나, `CAP_DAC_*` |

- 옛날엔 특권 작업 = **root(uid 0) 전부 아니면 전무**였다.
- 현대 리눅스는 root의 권한을 **capability 수십 개로 쪼갰다**. 예: `CAP_NET_ADMIN`(네트워크
  설정), `CAP_BPF`(eBPF 로드). 프로그램에 딱 필요한 것만 주면 = **최소권한**.
- **핵심 함정(우리가 겪음)**: `CAP_BPF`는 *bpf() syscall*을 부를 자격일 뿐, *파일 읽기*
  자격이 아니다. 그래서 eBPF는 로드됐는데(bpf syscall OK), tracepoint에 붙을 때 root-only
  파일(`/sys/kernel/tracing/.../id`)을 읽어야 해서 막혔다. → `ksyscall`로 우회.
  (자세한 건 [Part 3.5](#35-왜-tracepoint에서-막혔나), `INTERVIEW_NOTES.md`)

### 1.5 파일이 아닌 것도 파일: /sys, /proc
리눅스는 "모든 것은 파일" 철학. 커널 내부 정보/설정도 **가상 파일**로 노출한다:
- `/sys/kernel/btf/vmlinux` — 커널 타입 정보(BTF, 아래 설명). 진짜 디스크 파일이 아니라
  커널이 즉석에서 만들어주는 것.
- `/proc/<pid>/...` — 각 프로세스 정보.
- `/sys/kernel/tracing/...` — 추적(trace) 설정.

우리가 `bpftool btf dump file /sys/kernel/btf/vmlinux`로 커널 타입을 뽑아낸 게 이 가상파일에서
읽은 것.

### 1.6 setcap이 왜 리빌드하면 사라지나
- capability를 **파일(정확히는 inode)의 확장속성**에 각인하는 게 `setcap`.
- 컴파일러가 링크할 때 기존 파일을 수정하는 게 아니라 **새 파일을 만들어 이름을 갈아끼운다**
  (새 inode). 그래서 리빌드 = 다른 inode → 예전 capability는 무의미.
- 이래서 우리는 리빌드 후 매번 `setcap`이 필요했고, 그걸 NOPASSWD sudoers로 자동화했다.

---

## Part 2. eBPF 제로베이스

### 2.1 eBPF가 대체 뭔가
**커널을 재부팅·수정 없이, 커널 안에서 돌아가는 작은 프로그램을 안전하게 끼워넣는 기술.**

비유: 커널이 고속도로라면, eBPF는 특정 지점(예: "execve 실행 순간")에 **검문소**를 설치해
지나가는 것을 관찰/기록하는 것. 검문소 코드는 우리가 짜지만, 커널이 "이 코드가 커널을
망가뜨리지 않는지" 엄격히 검사한 뒤에만 설치를 허락한다.

**왜 굳이 커널 안에서?**
- 관측하려는 사건(syscall 등)이 커널에서 일어난다. 유저스페이스에서 폴링하면 느리고 놓친다.
- 커널 안에서 잡으면 오버헤드가 극히 작고, 놓치지 않는다.

**대안 대비**: 예전엔 커널 모듈(kernel module)을 짜서 넣었는데, 버그 하나면 커널 전체가
죽었다(패닉). eBPF는 **검증기(verifier)** 가 안전성을 보장하므로 훨씬 안전. 이게 eBPF의 존재 이유.

### 2.2 eBPF 프로그램의 일생
```
 1. 작성    : C로 eBPF 프로그램 작성 (collector.bpf.c)
 2. 컴파일  : clang이 특수 타깃(-target bpf)으로 "eBPF 바이트코드"로 변환
 3. 로드    : 유저 프로그램이 bpf() syscall로 커널에 바이트코드를 넘김
 4. 검증    : 커널 verifier가 "무한루프 없나, 잘못된 메모리 접근 없나" 전수 검사
              (통과 못 하면 로드 거부 — 이게 안전성의 핵심)
 5. attach  : "이 프로그램을 execve 순간에 실행해라" 하고 이벤트에 연결
 6. 실행    : 그 사건이 날 때마다 커널이 우리 프로그램을 자동 실행
```

우리 `main.cpp`가 하는 일이 정확히 3~5단계(로드·검증은 libbpf가 대신 호출, attach도).

### 2.3 어디에 붙일 수 있나 (attach point)
관찰하려는 "지점"의 종류:
- **tracepoint**: 커널 개발자가 미리 박아둔 안정적인 관측점. 예: `sys_enter_execve`.
  ABI가 안정적이라 커널 버전이 바뀌어도 잘 안 깨진다.
- **kprobe**: 아무 커널 함수 진입/반환에 동적으로 붙임. 유연하지만 함수 이름이 커널마다 다를 수 있음.
- **fentry/fexit**: kprobe의 현대판(더 빠름). BTF 필요.
- **ksyscall**: syscall용 kprobe 편의 매크로. **우리가 execve에 최종적으로 쓴 것.**
  (tracepoint가 권한 문제로 막혀서 — Part 3.5)

우리 코드: execve = `ksyscall/execve`, tcp connect = `fentry/tcp_v4_connect`.

### 2.4 map: 커널 ↔ 유저 데이터 공유
eBPF 프로그램은 커널 안에서 도는데, 결과를 유저스페이스로 어떻게 꺼낼까? → **map**.
map은 커널과 유저가 공유하는 자료구조(해시맵, 배열, 큐 등). 여러 종류가 있다.

우리가 쓴 건 **ring buffer**(원형 버퍼) map:
- eBPF 프로그램이 이벤트를 버퍼에 **밀어넣고(submit)**, 유저 프로그램이 **꺼내(poll)** 읽는다.
- **ring buffer vs perf buffer**(면접 단골):
  - perf buffer: CPU마다 버퍼가 따로. → CPU 간 이벤트 순서가 섞이고 메모리 낭비.
  - ring buffer(커널 5.8+): 모든 CPU가 공유하는 버퍼 하나. → **전역 순서 보존 + 메모리 효율**.
  - 보안 이벤트는 시간순서가 중요해서 ring buffer가 자연스러운 선택.

### 2.5 BTF와 CO-RE (한 번에 이해하기)
**문제**: eBPF 프로그램이 커널 구조체(예: `task_struct`)의 필드를 읽고 싶은데, 그 구조체의
메모리 배치(어느 필드가 몇 바이트째)가 **커널 버전마다 다르다**. 예전엔 실행할 커널의 헤더로
매번 다시 컴파일해야 했다. 배포에 악몽.

**해결 = CO-RE (Compile Once, Run Everywhere)**:
- **BTF (BPF Type Format)**: 커널이 자기 타입 정보(구조체 배치)를 통째로 갖고 있는 것.
  `/sys/kernel/btf/vmlinux`에 있다.
- 컴파일할 때 "task_struct의 real_parent 필드"라는 **의미만** 기록하고 실제 오프셋은 비워둠.
- **로드 시점**에 커널 BTF를 보고 실제 오프셋을 채워넣음.
- → 한 번 컴파일한 바이너리가 여러 커널 버전에서 동작.

우리 빌드가 하는 `bpftool btf dump ... > vmlinux.h`가 커널 BTF를 C 헤더로 뽑는 것.
코드의 `BPF_CORE_READ(task, real_parent, tgid)`가 "CO-RE 방식으로 필드 읽기".

---

## Part 3. Week 1 코드 리뷰

### 3.1 `common/event.h` — 공유 스키마
커널 eBPF와 유저 C++이 **같은 구조체**로 이벤트를 주고받아야 한다. 그래서 헤더 하나를 양쪽이 공유.

```c
struct security_event {
    __u32 type;                 // 이벤트 종류 (execve? connect?)
    __u32 pid, ppid;            // 프로세스 번호, 부모 번호
    __u64 ts_ns;                // 발생 시각 (나노초)
    char  comm[16];             // 프로세스 이름
    union { ... } u;            // 종류에 따라 execve 또는 tcp 필드
};
```
- **POD(Plain Old Data) 고정 구조체**: 복잡한 직렬화 라이브러리(flatbuffers 등) 안 쓰고
  구조체 바이트를 그대로 전송. 양 끝을 우리가 다 통제하므로 이게 가장 단순.
- **`union`**: execve와 tcp는 서로 다른 필드가 필요한데, 한 이벤트는 둘 중 하나. union으로
  메모리를 겹쳐 써서 크기 절약.
- **타입 트릭**: BPF 쪽은 `vmlinux.h`가 `__u32` 등을 정의. 유저스페이스는 `<linux/types.h>`
  에서 가져옴. `#ifndef __VMLINUX_H__`로 중복 정의를 피함. (이거 때문에 빌드 한 번 깨졌었다.)

### 3.2 `collector.bpf.c` — 커널에서 도는 코드
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");                    // ← ring buffer map 선언 (256KB)
```
`SEC(...)`는 "이 심볼을 ELF의 이 섹션에 넣어라"는 표시 — libbpf가 이걸 보고 map/프로그램을 인식.

```c
SEC("ksyscall/execve")
int BPF_KSYSCALL(handle_execve, const char *filename, ...) {
    struct security_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;                     // ← 버퍼 꽉 차면 이벤트 버림 (fail-safe)
    fill_common(e, PQSEC_EVT_EXECVE);     // ← pid/ppid/comm/ts 채움
    bpf_probe_read_user_str(&e->u.execve.filename, sizeof(...), filename);
    bpf_ringbuf_submit(e, 0);             // ← 유저스페이스로 밀어냄
    return 0;
}
```
- **reserve → 채움 → submit** 2단계: 버퍼 공간을 먼저 예약하고, 다 채운 뒤 커밋. 실패하면
  버릴 수 있어 깔끔.
- **`bpf_probe_read_user_str`**: `filename`은 *유저스페이스* 메모리 주소. 커널 코드가 유저
  메모리를 직접 접근하면 위험하므로, 전용 헬퍼로 안전하게 복사. (eBPF는 아무 메모리나 못 읽음 —
  verifier가 막는다.)
- `BPF_KSYSCALL` 매크로: syscall의 아키텍처별 이름(`__x64_sys_execve`)과 인자 언래핑을 자동 처리.

```c
SEC("fentry/tcp_v4_connect")
int BPF_PROG(handle_tcp_connect, struct sock *sk, struct sockaddr *uaddr, ...) {
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    ...
    e->u.tcp.daddr = BPF_CORE_READ(sin, sin_addr.s_addr);   // 목적지 IP
    e->u.tcp.dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port)); // 목적지 포트
}
```
- `tcp_v4_connect(sk, uaddr, ...)`의 인자에서 목적지를 읽는다. **진입 시점**엔 소켓에 목적지가
  아직 안 채워졌을 수 있어서, 인자 `uaddr`(호출자가 준 목적지 주소)에서 직접 읽음.
- `bpf_ntohs`: 네트워크는 빅엔디안(network byte order), 호스트는 보통 리틀엔디안. 포트 숫자를
  사람이 읽는 순서로 바꿈. (n-to-h-s = network to host, short)
- `char LICENSE[] SEC("license") = "GPL"`: 많은 eBPF 헬퍼가 GPL 라이선스 프로그램에서만
  동작. 없으면 로드 거부.

### 3.3 `main.cpp` — 유저스페이스 로더
```cpp
struct collector_bpf *skel = collector_bpf__open_and_load();  // 로드+검증
collector_bpf__attach(skel);                                   // 이벤트에 연결
struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                          handle_event, ...);   // ring buffer 열기
while (!g_exiting)
    ring_buffer__poll(rb, 100);                                // 100ms마다 이벤트 폴링
```
- **skeleton(`collector.skel.h`)**: 빌드 때 `bpftool gen skeleton`이 자동 생성한 헤더.
  eBPF 바이트코드가 통째로 이 헤더에 박혀 있어서, `open_and_load()` 한 번이면 로드까지 끝.
- **`handle_event` 콜백**: ring buffer에서 이벤트가 나올 때마다 호출됨. 우리는 타입 보고
  execve/connect 형식으로 출력.
- **fail-closed 신호 처리**: Ctrl-C(SIGINT) 오면 루프 빠져나와 정리(`ring_buffer__free`,
  `destroy`). 크립토뿐 아니라 자원 관리도 "조용히 죽지 않는다".

### 3.4 빌드 파이프라인 (`cmake/BpfObject.cmake`)
eBPF는 일반 컴파일과 달라서 특수 단계가 필요. 우리 CMake 함수가 자동화한 흐름:
```
① bpftool btf dump  → vmlinux.h        (커널 타입 헤더)
② clang -target bpf → collector.bpf.o  (eBPF 바이트코드)
③ llvm-strip -g     → (불필요 디버그심볼 제거, BTF는 유지)
④ bpftool gen skeleton → collector.skel.h  (C++이 include할 헤더)
⑤ g++ main.cpp + libbpf 링크 → agent   (최종 실행파일)
```
`libbpf`는 eBPF 로드/attach/ring buffer를 다루는 표준 C 라이브러리. `pkg-config`로 링크 경로를
찾는다.

### 3.5 왜 tracepoint에서 막혔나 (권한 사건 복습)
- 처음엔 execve를 `tp/syscalls/sys_enter_execve`(레거시 tracepoint)로 붙였다.
- 그 attach는 libbpf가 `/sys/kernel/tracing/events/.../id` 파일을 읽어야 하는데, 이 파일이
  **root 전용**. `CAP_BPF`는 파일 권한을 우회 못 함 → `Permission denied`.
- 해결: `ksyscall`(kprobe 기반)로 바꿈. 이건 그 root 파일을 안 읽고 kprobe PMU로 붙어서
  `CAP_BPF`+`CAP_PERFMON`만으로 동작.
- **교훈**: "권한은 필요한 최소 단위로 쪼개서 정확히 필요한 것만." (`INTERVIEW_NOTES.md`에 정리)

---

## Part 4. 암호학 기초 (제로베이스)

### 4.1 대칭 vs 비대칭
- **대칭키(symmetric)**: 암호화·복호화에 **같은 키**. 빠르다. 예: AES.
  문제 → 그 키를 상대에게 어떻게 안전하게 전달하지? (도청자가 보는 채널에서)
- **비대칭키(asymmetric/public-key)**: **공개키/개인키 한 쌍**. 공개키로 잠그면 개인키로만 열림.
  느리지만 "키 전달 문제"를 푼다. 예: RSA, 타원곡선.

**실전 조합**: 비대칭으로 "대칭키를 안전하게 합의"하고, 실제 데이터는 빠른 대칭키로 암호화.
우리 채널도 정확히 이 구조(핸드셰이크=비대칭, record layer=대칭 AES).

### 4.2 키 교환 문제와 Diffie-Hellman(DH)
도청되는 채널에서 두 사람이 **같은 비밀**을 갖는 마법:
- 각자 비밀 숫자(개인키)를 정하고, 그로부터 공개값(공개키)을 계산해 교환.
- 각자 "내 개인키 × 상대 공개값"을 계산하면 **같은 결과**가 나온다(수학적 성질).
- 도청자는 공개값들만 봐선 그 결과를 못 구한다.
- 우리가 쓰는 **X25519**가 이 DH의 현대적·빠른 버전(타원곡선 기반). 공개키 32바이트.

### 4.3 KEM (Key Encapsulation Mechanism)
DH의 사촌. "상대 공개키로 **랜덤 대칭키를 캡슐에 넣어(encapsulate)** 보내고, 상대는 개인키로
**깐다(decapsulate)**":
```
[수신자] keypair()          → 공개키, 개인키
[송신자] encaps(공개키)      → (캡슐=ciphertext, 공유비밀)   ← 랜덤 비밀을 만들어 캡슐화
[수신자] decaps(ciphertext) → 공유비밀                       ← 같은 비밀을 얻음
```
- DH는 대칭적(양쪽이 공개키 교환), KEM은 **비대칭적**(한쪽은 공개키, 다른쪽은 캡슐).
- **PQC(양자내성)는 KEM 형태로 나온다** → 우리 ML-KEM이 이것.

### 4.4 서명 (signature)
- 개인키로 메시지에 **서명**하고, 공개키로 **검증**. "이 메시지는 개인키 소유자가 만들었고
  변조 안 됨"을 증명. → **인증(authentication)**.
- KEM/DH가 *기밀성*(비밀 공유)이라면, 서명은 *신원 증명*.
- 우리 **ML-DSA**가 양자내성 서명. 핸드셰이크에서 "너 진짜 그 서버 맞아?"를 서명으로 확인.

### 4.5 해시, HMAC, KDF/HKDF
- **해시(SHA-256)**: 임의 데이터 → 고정 32바이트 지문. 같은 입력 = 같은 지문, 조금만 바뀌어도
  완전히 다른 지문. 되돌릴 수 없음. → 우리 "트랜스크립트 해시"에 사용.
- **KDF (Key Derivation Function)**: 하나의 비밀에서 여러 용도의 키를 안전하게 파생.
- **왜 HKDF가 필요한가**: DH/KEM이 준 "공유비밀"은 **균일하게 랜덤한 비트열이 아니다**(수학적
  구조가 있음). 이걸 바로 AES 키로 쓰면 위험. HKDF가:
  - **Extract**: 들쭉날쭉한 비밀에서 균일한 키재료(PRK)를 뽑음.
  - **Expand**: PRK에서 "이 방향, 이 용도"별 키들을 필요한 길이만큼 파생.
  - 우리 코드: `hkdf_extract` → `hkdf_expand`로 c2s/s2c 키와 IV를 분리 생성.

### 4.6 AEAD와 AES-256-GCM (record layer의 심장)
- **AEAD (Authenticated Encryption with Associated Data)**: 암호화(기밀성) + 변조탐지(무결성)를
  한 번에. 복호 시 **태그(tag)**를 검증해서, 한 비트라도 변조됐으면 복호 거부.
- **AES-256-GCM**: 대표적 AEAD. 256비트 키, 128비트 태그.
- **nonce (number used once)**: GCM은 매 암호화마다 **다른** nonce(96비트)가 필요.
  **같은 키+같은 nonce를 두 번 쓰면 보안이 완전히 붕괴**(GCM의 절대 금기).
  - 우리 해법(TLS 1.3 방식): `nonce = iv_base XOR 시퀀스번호`. 레코드마다 seq를 1씩 늘려서
    절대 겹치지 않게. seq가 다 소진되면(2^64) 연결을 끊음(fail-closed).

---

## Part 5. 양자내성암호 (PQC)

### 5.1 양자 위협 — 왜 지금?
- 큰 양자컴퓨터는 **쇼어 알고리즘**으로 RSA·타원곡선(=현재 키교환/서명)을 깬다.
- 아직 그런 컴퓨터는 없지만, 위협은 **지금** 존재: **"harvest-now, decrypt-later"** —
  공격자가 오늘 암호문을 저장해뒀다가, 미래에 양자컴퓨터로 복호. → **오늘의 기밀성이 미래에 뚫림.**
- 그래서 **키교환(기밀성)의 PQC 전환이 1순위**. (서명 위조는 "미래 시점" 공격이라 상대적으로 덜 급함.)

### 5.2 ML-KEM, ML-DSA
NIST가 2024년 표준화한 PQC 알고리즘:
- **ML-KEM** (구 Kyber): 양자내성 **KEM**(기밀성). 우리는 ML-KEM-768(NIST level 3).
- **ML-DSA** (구 Dilithium): 양자내성 **서명**(인증). 우리는 ML-DSA-65(level 3).
- **비용**: 고전 대비 크다. X25519 공개키 32B vs ML-KEM 공개키 1184B, ML-DSA 서명 ~3.3KB.
  → PQC의 대가는 **대역폭**. (우리 핸드셰이크 총 ~9KB)

### 5.3 하이브리드 — 왜 둘 다 쓰나
`ss = X25519_공유비밀 ∥ ML-KEM_공유비밀` 을 이어붙여 HKDF에 넣는다. 이유는 **양쪽 보험**:
- ML-KEM은 신생이라 실전 검증이 RSA/ECDH만큼 안 쌓임(미래에 결함 발견될 수도).
- X25519는 양자컴퓨터에 취약.
- **둘 중 하나만 안전하면 세션키가 안전** → 고전이 양자로 깨져도 PQC가, PQC에 결함 나도 고전이 지킴.
- 이게 실제 TLS 1.3 하이브리드(X25519MLKEM768)와 같은 발상.

---

## Part 6. Week 2 코드 리뷰

전체 구조: `crypto/` 아래 `pqsec_channel` 라이브러리. 각 파일이 한 가지 프리미티브를 감싼다.

### 6.1 PQC 래퍼 (`pqc.h`, `pqc_kem.cpp`, `pqc_sig.cpp`)
liboqs(오픈소스 PQC 라이브러리)를 얇게 감싼 C++ 클래스.
```cpp
class MlKem {
    KeyPair keypair() const;                       // 키쌍 생성
    EncapsResult encaps(peer_public_key) const;    // 캡슐화 → ct + 공유비밀
    Bytes decaps(ciphertext, secret_key) const;    // 복호 → 공유비밀
};
```
- **RAII**([Part 7.1](#71-raii)): 생성자에서 `OQS_KEM_new`, 소멸자에서 `OQS_KEM_free`. 자원 누수 방지.
- **fail-closed**: 실패는 예외(`throw`), 서명 검증 실패는 `false` 리턴(조용히 넘어가지 않음).
- **직접 구현 안 함**: 크립토 알고리즘은 검증된 liboqs 것을 *조합만*. 우리 몫은 "어떻게 엮을까".

### 6.2 X25519 (`x25519.cpp`) + HKDF/SHA-256 (`kdf.cpp`)
- OpenSSL EVP API로 X25519 키교환과 HKDF·SHA-256을 구현(역시 조합만).
- `X25519` 클래스: 생성 시 임시 키쌍 만들고, `compute_shared(상대공개키)`로 ECDH 공유비밀.
- `hkdf_extract` / `hkdf_expand` / `sha256` 함수: OpenSSL의 `EVP_KDF`, `EVP_Digest` 호출.

### 6.3 세션 키 스케줄 (`session.cpp`)
설계 문서(`docs/handshake-design.md` §5)를 코드로:
```cpp
Bytes ikm  = ss_classical ∥ ss_pq;          // 하이브리드 결합
Bytes salt = client_random ∥ server_random;
Bytes prk  = hkdf_extract(salt, ikm);
c2s_key = hkdf_expand(prk, "pqsec c2s key" ∥ transcript_hash, 32);
s2c_key = hkdf_expand(prk, "pqsec s2c key" ∥ transcript_hash, 32);
```
- **방향별 키 분리**: agent→analyzer(c2s)와 analyzer→agent(s2c)가 다른 키. 한 방향 키가 새도
  반대 방향은 안전.
- **transcript_hash를 섞음**: 핸드셰이크 바이트가 변조되면 파생키가 달라져 → 첫 레코드 복호 실패
  → 변조 자동 탐지.

### 6.4 record layer (`record.cpp`)
```cpp
class RecordSender {
    Bytes seal(plaintext);   // 암호화 → [길이][ciphertext][태그]
    uint64_t seq_ = 0;       // 매 레코드 증가
};
class RecordReceiver {
    Bytes open(record);      // 복호+태그검증 (실패 시 예외)
    uint64_t seq_ = 0;       // 송신측과 나란히 증가
};
```
- `nonce = iv_base XOR seq`로 매번 다른 nonce. seq는 송/수신이 각자 셈.
- **순서/재전송 자동 거부**: 레코드가 재정렬·재전송되면 수신측 seq가 어긋나 nonce 불일치 →
  태그 검증 실패 → 예외. (`record_demo`가 이걸 검증)
- **AAD로 길이 인증**: 레코드 길이 헤더를 GCM의 "연관 데이터"로 넣어 길이도 변조 못 하게.

### 6.5 와이어 포맷 (`wire.cpp`) + 핸드셰이크 설계 (`docs/handshake-design.md`)
- 4개 메시지(ClientHello/ServerHello/ServerAuth/ClientAuth)를 바이트로 직렬화/파싱.
- 공통 프레임 `[타입][버전][길이][payload]`. 파싱은 **경계검사 fail-closed**(잘린 입력 = 예외).
- 핸드셰이크 흐름(설계 문서 참조): Hello 교환으로 하이브리드 키 합의 → 양쪽이 트랜스크립트에
  ML-DSA 서명 → 사전보유 공개키로 검증(상호인증) → record layer 전환.
- **역할 배정**: X25519는 대칭이라 양쪽 공개키 교환. ML-KEM은 비대칭이라 클라가 공개키를,
  서버가 캡슐(ciphertext)을 보냄. (TLS 1.3 하이브리드와 동일)

### 6.6 검증 데모들
- `mlkem_demo`: ML-KEM 왕복.
- `channel_selftest`: KEM 왕복 + 서명 위조/타인키 거부 + 와이어 왕복 + 잘린 프레임 거부.
- `hybrid_demo`: 양측 세션키 일치 + ML-DSA 상호인증 + MITM(트랜스크립트 변조) 거부.
- `record_demo`: AES-GCM 왕복 + 변조/재정렬/재전송 거부.

---

## Part 7. C++ / 빌드 관용구

### 7.1 RAII
"Resource Acquisition Is Initialization" — **생성자에서 자원 획득, 소멸자에서 해제**. 객체가
스코프를 벗어나면 소멸자가 자동 호출되어 정리. → 자원 누수·이중해제 방지.
우리 `MlKem`/`MlDsa`/`X25519`가 OQS/EVP 핸들을 이렇게 관리. `= delete`로 복사 금지(핸들 이중해제 방지).

### 7.2 `std::vector<uint8_t>` = `Bytes`
가변 길이 바이트 배열. 크기를 자기가 알고, 스코프 벗어나면 자동 해제. C의 "포인터+길이"보다 안전.
우리 모든 크립토 데이터의 기본 타입(`using Bytes = std::vector<uint8_t>`).

### 7.3 예외(exception)로 fail-closed
크립토/파싱 실패 시 `throw std::runtime_error(...)`. 호출자가 `try/catch`로 잡거나, 안 잡으면
프로그램이 죽는다 — **조용히 잘못된 채로 진행하지 않음**. 보안 코드의 원칙.
(검증 실패처럼 "정상적 거부"는 예외 대신 `false` 리턴으로 구분.)

### 7.4 CMake / 링킹 개념
- **컴파일**: 각 `.cpp` → `.o`(오브젝트 파일).
- **링킹**: 오브젝트들 + 라이브러리(`.so`/`.a`)를 묶어 실행파일.
- **정적(.a) vs 동적(.so)**: 정적은 실행파일에 코드 복사(우리 `libpqsec_channel.a`), 동적은
  실행 시 로드(우리 `liboqs.so`, `libcrypto.so`).
- **`find_package` / `pkg-config`**: 라이브러리의 헤더·링크 경로를 자동으로 찾아줌.
- **rpath**: 동적 라이브러리가 표준 경로에 없어도(우리 liboqs는 `third_party/`), 실행파일에
  "여기서 찾아라"를 심어둠. 그래서 `LD_LIBRARY_PATH` 없이 실행됨.

---

## 다음에 읽으면 좋은 것
- `docs/handshake-design.md` — 핸드셰이크 상세 설계·근거·한계
- `INTERVIEW_NOTES.md` — 면접 예상 Q&A (권한 모델, ring buffer 등)
- `ROADMAP.md` — 전체 4주 계획과 범위 가드레일
- 코드는 `agent/`(Week 1), `crypto/`(Week 2) 순서로 읽으면 이 문서와 대응된다.
