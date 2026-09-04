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
#include <string>

namespace pqsec {

class SocketError : public std::runtime_error {
public:
    explicit SocketError(const std::string &what) : std::runtime_error(what) {}
};

// bind_ip:port 에 listen (기본 127.0.0.1, 컨테이너 안에서는 "0.0.0.0").
// port=0 이면 커널이 빈 포트 할당. listen fd 반환.
int tcp_listen(uint16_t port, const std::string &bind_ip = "127.0.0.1");
// 실제 바인딩된 포트 조회 (port=0 으로 listen 한 경우)
uint16_t tcp_local_port(int listen_fd);
// 한 연결 수락 → conn fd
int tcp_accept(int listen_fd);
// host:port 로 접속 (host 는 IPv4 주소 또는 호스트명, 기본 127.0.0.1) → conn fd
int tcp_connect(uint16_t port, const std::string &host = "127.0.0.1");
void close_fd(int fd);

// fd 위에서 핸드셰이크 프레임(4바이트 헤더)을 주고받는 Transport 생성
Transport make_socket_transport(int fd);

// 레코드(2바이트 헤더) 송수신.
void send_record(int fd, const Bytes &record);
// 한 레코드 수신. 연결이 정상 종료(EOF)면 빈 Bytes 반환.
Bytes recv_record(int fd);

} // namespace pqsec

#endif // PQSEC_SOCKET_H
