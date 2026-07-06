// crypto/include/pqsec/socket.h
//
// 최소 TCP 소켓 래퍼 + 스트림 위 프레이밍.
//   - 핸드셰이크 프레임: [u8 type][u8 ver][u16 len][payload]  (4바이트 헤더)
//   - 레코드 프레임    : [u16 len][ciphertext+tag]            (2바이트 헤더)
// 스트림 소켓은 메시지 경계가 없으므로 길이 접두사로 한 메시지씩 잘라 읽는다.

#ifndef PQSEC_SOCKET_H
#define PQSEC_SOCKET_H

#include "pqsec/handshake.h" // Transport, Bytes
#include "pqsec/pqc.h"

#include <cstdint>
#include <stdexcept>

namespace pqsec {

class SocketError : public std::runtime_error {
public:
    explicit SocketError(const std::string &what) : std::runtime_error(what) {}
};

// 127.0.0.1:port 에 listen. port=0 이면 커널이 빈 포트 할당. listen fd 반환.
int tcp_listen(uint16_t port);
// 실제 바인딩된 포트 조회 (port=0 으로 listen 한 경우)
uint16_t tcp_local_port(int listen_fd);
// 한 연결 수락 → conn fd
int tcp_accept(int listen_fd);
// 127.0.0.1:port 로 접속 → conn fd
int tcp_connect(uint16_t port);
void close_fd(int fd);

// fd 위에서 핸드셰이크 프레임(4바이트 헤더)을 주고받는 Transport 생성
Transport make_socket_transport(int fd);

// 레코드(2바이트 헤더) 송수신.
void send_record(int fd, const Bytes &record);
// 한 레코드 수신. 연결이 정상 종료(EOF)면 빈 Bytes 반환.
Bytes recv_record(int fd);

} // namespace pqsec

#endif // PQSEC_SOCKET_H
