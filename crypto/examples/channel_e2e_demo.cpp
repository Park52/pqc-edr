// crypto/examples/channel_e2e_demo.cpp
//
// Week 2 캡스톤: 실제 TCP 소켓 위에서 agent↔analyzer 암호화 채널 관통.
//   fork 로 두 프로세스를 만들어 각각 클라(agent)/서버(analyzer) 역할.
//   1) PQC 하이브리드 mTLS 핸드셰이크 (상호인증)
//   2) agent 가 security_event(Week 1 스키마)를 암호화해 전송
//   3) analyzer 가 복호·디코드해 출력
//   소켓에 흐르는 건 암호문뿐임을 hex 로 확인.

#include "pqsec/handshake.h"
#include "pqsec/pqc.h"
#include "pqsec/socket.h"

#include "event.h" // Week 1 공통 스키마 (security_event)

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <sys/wait.h>
#include <unistd.h>

using namespace pqsec;

static Bytes to_bytes(const security_event &ev) {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&ev);
    return Bytes(p, p + sizeof(ev));
}

static void hex_prefix(const Bytes &b, size_t show = 24) {
    for (size_t i = 0; i < show && i < b.size(); ++i)
        printf("%02x", b[i]);
    printf("...");
}

// --- agent(클라이언트): 접속 → 핸드셰이크 → 이벤트 암호화 전송 ---
static void run_agent(uint16_t port, const Identity &id) {
    int fd = tcp_connect(port);
    Transport t = make_socket_transport(fd);
    Channel ch = client_handshake(id, t);
    printf("[agent]    핸드셰이크 완료 (서버 인증됨). 이벤트 전송 시작.\n");

    security_event e1{};
    e1.type = PQSEC_EVT_EXECVE;
    e1.pid = 4242;
    e1.ppid = 4200;
    std::strncpy(e1.comm, "bash", sizeof(e1.comm) - 1);
    std::strncpy(e1.u.execve.filename, "/usr/bin/curl", sizeof(e1.u.execve.filename) - 1);

    security_event e2{};
    e2.type = PQSEC_EVT_TCP_CONNECT;
    e2.pid = 4242;
    e2.ppid = 4200;
    std::strncpy(e2.comm, "curl", sizeof(e2.comm) - 1);
    e2.u.tcp.family = 2; // AF_INET
    inet_pton(AF_INET, "185.220.101.1", &e2.u.tcp.daddr); // 예시 아웃바운드
    e2.u.tcp.dport = 443;

    bool first = true;
    for (const security_event &ev : {e1, e2}) {
        Bytes rec = ch.sender.seal(to_bytes(ev)); // 암호화
        if (first) {
            printf("[agent]    첫 이벤트 평문 크기=%zu → 레코드 와이어(암호문): ", sizeof(ev));
            hex_prefix(rec);
            printf("\n");
            first = false;
        }
        send_record(fd, rec);
    }
    close_fd(fd); // EOF → 서버 수신 루프 종료
    printf("[agent]    이벤트 2건 전송 완료, 연결 종료.\n");
    fflush(stdout); // _exit 는 stdio 버퍼를 flush 하지 않으므로 명시적으로
}

// --- analyzer(서버): 수락 → 핸드셰이크 → 복호·디코드·출력 ---
static void run_analyzer(int listen_fd, const Identity &id) {
    int fd = tcp_accept(listen_fd);
    Transport t = make_socket_transport(fd);
    Channel ch = server_handshake(id, t);
    printf("[analyzer] 핸드셰이크 완료 (클라이언트 인증됨). 이벤트 수신 대기.\n");

    int count = 0;
    for (;;) {
        Bytes rec = recv_record(fd);
        if (rec.empty())
            break; // 정상 종료
        Bytes pt = ch.receiver.open(rec); // 복호+태그검증 (실패 시 예외)
        if (pt.size() < sizeof(security_event)) {
            fprintf(stderr, "[analyzer] 짧은 이벤트 무시\n");
            continue;
        }
        const security_event *ev = reinterpret_cast<const security_event *>(pt.data());
        if (ev->type == PQSEC_EVT_EXECVE) {
            printf("[analyzer] 복호 이벤트 #%d  EXECVE  pid=%u comm=%s file=%s\n", ++count,
                   ev->pid, ev->comm, ev->u.execve.filename);
        } else if (ev->type == PQSEC_EVT_TCP_CONNECT) {
            char ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &ev->u.tcp.daddr, ip, sizeof(ip));
            printf("[analyzer] 복호 이벤트 #%d  CONNECT pid=%u comm=%s dst=%s:%u\n", ++count,
                   ev->pid, ev->comm, ip, ev->u.tcp.dport);
        }
    }
    printf("[analyzer] 총 %d건 복호 완료.\n", count);
    close_fd(fd);
}

int main() {
    setvbuf(stdout, nullptr, _IOLBF, 0); // 라인버퍼: fork 후 두 프로세스 출력 순서 보존

    // === 사전 프로비저닝: 두 장기 ML-DSA 신원 (fork 전 생성 → 자식이 상속) ===
    MlDsa dsa;
    KeyPair agent_id = dsa.keypair();
    KeyPair analyzer_id = dsa.keypair();
    printf("신원 프로비저닝: agent/analyzer ML-DSA 키쌍 생성, 서로 공개키 보유\n");

    int listen_fd = tcp_listen(0); // 커널이 빈 포트 할당
    uint16_t port = tcp_local_port(listen_fd);
    printf("analyzer 리슨: 127.0.0.1:%u\n\n", port);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // 자식 = agent
        close_fd(listen_fd);
        Identity id{agent_id.public_key, agent_id.secret_key, analyzer_id.public_key};
        try {
            run_agent(port, id);
        } catch (const std::exception &e) {
            fprintf(stderr, "[agent] 실패: %s\n", e.what());
            _exit(1);
        }
        _exit(0);
    }

    // 부모 = analyzer
    Identity id{analyzer_id.public_key, analyzer_id.secret_key, agent_id.public_key};
    int rc = 0;
    try {
        run_analyzer(listen_fd, id);
    } catch (const std::exception &e) {
        fprintf(stderr, "[analyzer] 실패: %s\n", e.what());
        rc = 1;
    }
    close_fd(listen_fd);

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        rc = 1;

    printf("\n%s\n", rc == 0 ? "[PASS] 엔드투엔드 암호화 채널 관통 성공" : "[FAIL]");
    return rc;
}
