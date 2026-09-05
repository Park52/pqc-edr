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

---

## Week 2 — PQC 하이브리드 채널

### Q. 서명이 정확히 무엇을 덮기에 MITM·다운그레이드가 막히나?
ML-DSA 서명은 개별 값이 아니라 **트랜스크립트 해시**(ClientHello‖ServerHello 전체 = 양측의 랜덤·X25519·ML-KEM 공개값·스위트)를 덮는다. 중간자가 공개값 하나라도 바꾸면 해시가 달라져 상대의 사전보유 공개키로 검증이 실패하고, 스위트 필드가 트랜스크립트 안에 있어 "약한 알고리즘으로 협상하자"는 다운그레이드도 서명 검증에서 걸린다. 세션키 유도(HKDF info)에도 트랜스크립트 해시를 넣어 키 자체가 대화 내용에 바인딩된다.

### Q. 왜 PSK가 아니라 서명 기반 상호인증인가?
PSK는 한 비밀을 양쪽이 공유하므로 한쪽(특히 노출된 엔드포인트의 agent)이 털리면 상대 신원까지 위조되고, agent가 늘수록 analyzer가 모든 비밀을 보관해야 한다. 서명은 개인키가 각자에게만 있고 상대에겐 공개키만 배포하면 되니 유출 반경이 그 신원 하나로 제한된다. 대가로 핸드셰이크 바이트가 커지지만(ML-DSA 서명 3.3KB×2) 세션당 1회라 감수했다.

### Q. AES-GCM nonce 재사용을 어떻게 원천 차단했나?
GCM은 같은 키로 nonce가 한 번이라도 겹치면 인증키가 복구돼 치명적이므로, TLS 1.3 방식으로 nonce = iv_base(12B, 방향별로 HKDF 유도) XOR 단조증가 seq를 쓴다. 방향(c2s/s2c)마다 키와 iv_base가 다르고 seq는 레코드마다 증가하므로 같은 (키, nonce) 쌍이 두 번 나올 수 없고, 수신측 seq가 어긋나면(재정렬·재전송) 태그 검증이 실패해 fail-closed 된다. 헤더 길이 필드는 AAD로 인증해 프레임 변조도 잡는다.

---

## Week 3 — LLM 이상탐지

### Q. Claude API를 C++에서 어떻게 호출했나?
공식 C++ SDK가 없어 libcurl로 `POST /v1/messages`를 직접 호출하며 `x-api-key`·`anthropic-version` 헤더와 JSON 바디(nlohmann/json)를 구성했다. 응답에서 JSON 판정을 추출하되 파싱·호출 실패는 fail-safe로 `unknown` 판정을 surface하고(데몬은 계속), 키가 없거나 `--mock-llm`이면 결정론적 mock으로 대체해 오프라인·CI에서 파이프라인이 그대로 돈다.

### Q. 왜 Haiku→Sonnet 2단 티어링인가?
입력 토큰당 Haiku($1/1M)와 Sonnet($2/1M)·출력($5 vs $10)이 2배 차이라, 다수인 "애매한 이벤트"를 싼 모델이 1차 스크리닝하고 의심만 비싼 모델이 사유·심각도를 서술하게 했다. 룰 프리필터가 앞단에서 명백 정상/악성을 이미 걸러 LLM에 가는 양 자체를 줄이고, 코릴레이션 hit는 Haiku를 건너뛰어 바로 Sonnet으로 보내 결정론적 근거가 있는 건 지연을 줄였다.

---

## Week 4 — 필수 Q&A

### 1. 왜 하이브리드 KEM인가? 순수 PQC가 아니라?
ML-KEM은 2024년 표준화(FIPS 203)됐지만 실전 검증 기간이 짧아 SIKE·Rainbow처럼 후보가 갑자기 깨진 전례가 있고, 반대로 X25519는 양자엔 깨져도 고전 공격엔 20년 검증됐다. 두 공유비밀을 HKDF로 결합(`IKM = ss_x25519 ‖ ss_mlkem`)하면 **둘 중 하나만 안전해도 세션키가 안전**해서, "지금 수집해 나중에 복호(harvest-now-decrypt-later)" 방어와 PQC 결함 보험을 동시에 얻는다. 비용은 벤치 기준 CPU는 고전과 같고(ML-KEM이 X25519보다 빠름) 와이어만 ~2.3KB 늘어나며, TLS 1.3의 X25519MLKEM768과 같은 선택이다. ([docs/BENCHMARK.md](docs/BENCHMARK.md))

### 2. ML-KEM 선택, 다른 후보(BIKE, HQC 등) 대비 트레이드오프는?
ML-KEM(Kyber)은 격자(MLWE) 기반으로 NIST가 가장 먼저 표준화했고, 키 1.2KB/암호문 1.1KB에 연산이 X25519보다 빠를 만큼 성능·크기 균형이 좋으며 브라우저·클라우드가 이미 배포 중이라 상호운용성과 구현 성숙도(liboqs, OpenSSL 3.5)가 가장 높다. HQC(2025년 NIST 추가 선정)·BIKE는 부호(code) 기반이라 격자 수학이 깨질 때의 백업이지만 키·암호문이 수 KB로 더 크고 느리며 라이브러리 지원이 약하다. 이 프로젝트는 "격자가 깨지는" 리스크를 HQC 대신 고전 X25519 하이브리드로 헤지했고, KEM을 liboqs 래퍼 뒤에 두어 알고리즘 교체(crypto agility)가 가능하게 했다.

### 3. LLM 이상탐지의 오탐/할루시네이션 리스크를 어떻게 통제했나?
LLM을 최종 판정자가 아니라 **"애매한 것의 설명자"**로 두었다 — 룰 프리필터가 명백 정상(화이트리스트·사설망)은 LLM 없이 drop, 명백 악성(임시경로 실행·nc)은 LLM 없이 alert, 시퀀스 코릴레이션(다운로드→실행 체인, 비콘)은 결정론적 근거로 alert하고 LLM은 그 사이의 애매한 이벤트만 본다. 결정론적 근거가 있는 이벤트는 LLM이 '정상'이라 해도 Suspicious 아래로 못 내리고(LLM은 심각도 보정·설명만), 호출·파싱 실패는 fail-safe로 `unknown`을 surface해 조용히 통과시키지 않는다. 오프라인 mock으로 파이프라인을 결정론적으로 회귀 테스트하며, 남은 리스크는 comm/filename에 지시문을 심는 프롬프트 인젝션이다(5번).

> 실측(2026-09-05, 실 Claude API): Haiku는 단독 `curl` execve를 정상(conf 0.95)으로 판정했지만 코릴레이션이 다운로드→실행 체인을 Critical로 잡았다. 비콘 hit를 Sonnet에 직행시키니 MITRE ATT&CK(T1071.001) 매핑과 "정상 업데이터일 수도 있으니 조사 후 격상"이라는 보수적 설명이 나왔다 — LLM은 설명자, 판정 앵커는 결정론적 계층이라는 설계가 실제 모델 출력으로 확인된 사례.

### 4. eBPF collector가 성능/보안에 주는 영향은?
성능: 벤치 기준 이벤트당 ~13–14µs로 execve 경로(fork+exec ~630µs)엔 +2%, connect 커널 경로엔 +31%지만 절대치가 같아 실 워크로드(초당 수백 이벤트)에선 CPU 1% 미만이고, ring buffer는 커널→유저 복사 1회에 reserve/commit이라 부분 이벤트가 나가지 않는다. 보안: eBPF 프로그램은 verifier가 종료·메모리 안전을 증명한 뒤에만 로드돼 커널 모듈보다 안전하고, root 없이 cap_bpf+cap_perfmon 최소권한으로 attach했다. 소비자(analyzer)가 느릴 때는 ring buffer 콜백이 유한 큐에 복사만 하고 송신 스레드가 보내므로 커널이 아니라 유저스페이스에서 드롭이 나고, 그 수를 세어 `AGENT_DROP` 통지로 analyzer 에 알린다(커널 드롭은 보이지 않지만 이 드롭은 셀 수 있다). 남은 한계는 kprobe가 커널 심볼에 의존하는 점(CO-RE로 레이아웃 변화는 흡수, 심볼 삭제는 못 막음)이다. ([docs/BENCHMARK.md §4](docs/BENCHMARK.md))

### 5. 실제 프로덕션에 올린다면 뭐가 부족한가? (솔직하게)
신뢰·세션: PKI 없이 사전공유 공개키 핀닝이라 키 배포·회전·폐기(revocation)가 없고, 세션 재개·키 갱신·재연결 백오프도 없어 링크가 끊기면 이벤트가 유실된다(백프레셔는 유한 큐로 드롭을 세고 알리지만 디스크 큐·재전송은 없다). 탐지: 훅이 2개(execve, IPv4 connect)뿐이라 파일·IPv6/UDP·권한상승을 못 보고, 룰·코릴레이션 임계는 튜닝 안 된 휴리스틱이며 LLM 프롬프트에 프롬프트 인젝션 방어가 없고 root 공격자는 agent 자체를 끌 수 있다. 운영: 핸드셰이크가 TLS 1.3 축약판이라 형식 검증(formal analysis)이 없고, 감사 로그·메트릭·알림 라우팅·멀티테넌시·HA 같은 서비스 요소가 전무하다.
