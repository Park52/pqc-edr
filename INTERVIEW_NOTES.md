# INTERVIEW_NOTES

면접 대비 Q&A 누적. 각 답은 3문장 이내(CLAUDE.md 규칙). 프로젝트 진행하며 채운다.

---

## Week 1 — eBPF Collector

### Q. ring buffer vs perf buffer, 왜 ring buffer를 썼나?
perf buffer는 CPU마다 별도 버퍼라 이벤트 순서가 CPU 간 섞이고 메모리도 CPU 수만큼 든다. ring buffer(5.8+)는 모든 CPU가 공유하는 단일 MPSC 버퍼라 전역 순서가 보존되고 메모리 효율이 좋으며, reserve/commit 2단계라 커밋 전 실패 시 이벤트를 버릴 수 있다. 보안 이벤트는 시간순서와 유실 최소화가 중요해서 ring buffer가 자연스러운 선택이다.

### Q. CO-RE가 왜 필요한가?
eBPF 프로그램이 커널 구조체 필드에 접근할 때, 커널 버전마다 구조체 레이아웃(오프셋)이 달라 전통적으로는 타겟 커널 헤더로 매번 재컴파일해야 했다. CO-RE는 컴파일 시 "이 필드"라는 재배치(relocation) 정보만 남기고, 로드 시점에 커널 BTF를 보고 실제 오프셋을 채워넣어 한 번 빌드한 바이너리가 여러 커널에서 돈다. 그래서 vmlinux.h(BTF 덤프) + `BPF_CORE_READ` 조합을 쓴다.

### Q. eBPF attach에 왜 root가 필요했나 — CAP_BPF/CAP_PERFMON로 충분하지 않았나?
CAP_BPF/CAP_PERFMON은 bpf(2)·perf_event_open(2) 시스템콜 호출 권한이지, 파일 DAC(소유자/모드) 검사를 우회하지 않는다. 레거시 tracepoint attach는 libbpf가 tracefs의 `.../events/.../id` 파일(root-only, `-r--r-----`)을 읽어 perf event ID를 얻는 경로라, 그 파일 읽기에서 막힌다. 그래서 tracefs를 읽지 않고 kprobe PMU로 붙는 `ksyscall`(BPF_KSYSCALL)로 전환해 최소권한(cap_bpf,cap_perfmon)만으로 attach했다.

### Q. 개발 중 eBPF 바이너리 권한을 어떻게 관리했나?
매번 sudo로 실행하는 대신 `setcap`으로 바이너리에 필요한 capability만 부여했는데, capability는 inode에 귀속돼 리빌드하면 파일이 교체되며 소실된다. 반복개발을 위해 "이 바이너리에 이 특정 cap 세트를 붙이는 setcap 명령"만 NOPASSWD로 허용하는 sudoers 한 줄을 두어, 임의 명령·임의 파일이 아닌 정확히 그 동작만 무암호로 자동화했다. 이는 최소권한 원칙(least privilege)을 개발 편의와 절충한 예다.

### Q. eBPF collector가 성능/보안에 주는 영향은? (ROADMAP 필수 #4)
_TODO — Week 4에서 벤치와 함께 정리_

---

## Week 4 — 필수 Q&A (진행하며 채움)

1. **왜 하이브리드 KEM인가? 순수 PQC가 아니라?** — _TODO (Week 2)_
2. **ML-KEM 선택, 다른 후보(BIKE, HQC) 대비 트레이드오프는?** — _TODO (Week 2)_
3. **LLM 이상탐지의 오탐/할루시네이션 리스크를 어떻게 통제했나?** — _TODO (Week 3)_
4. **eBPF collector가 성능/보안에 주는 영향은?** — _TODO (위 Week 1 섹션 + 벤치)_
5. **실제 프로덕션에 올린다면 뭐가 부족한가?** — _TODO (Week 4)_
