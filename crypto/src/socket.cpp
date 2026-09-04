// crypto/src/socket.cpp — 최소 TCP 소켓 + 프레이밍

#include "pqsec/socket.h"
#include "pqsec/wire.h" // wire::kHeaderLen

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace pqsec {

namespace {

[[noreturn]] void fail(const char *what) {
    throw SocketError(std::string("socket: ") + what + " (" + std::strerror(errno) + ")");
}

// n 바이트를 확실히 쓴다 (부분전송 처리).
void write_all(int fd, const uint8_t *p, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t k = ::send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        if (k < 0) {
            if (errno == EINTR)
                continue;
            fail("send");
        }
        sent += static_cast<size_t>(k);
    }
}

// n 바이트를 확실히 읽는다. 첫 바이트 전에 EOF 면 false, 중간에 끊기면 예외.
bool read_all(int fd, uint8_t *p, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t k = ::recv(fd, p + got, n - got, 0);
        if (k < 0) {
            if (errno == EINTR)
                continue;
            fail("recv");
        }
        if (k == 0) { // EOF
            if (got == 0)
                return false; // 깔끔한 종료
            fail("메시지 중간에 연결 끊김");
        }
        got += static_cast<size_t>(k);
    }
    return true;
}

} // namespace

int tcp_listen(uint16_t port, const std::string &bind_ip) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (::inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) != 1)
        throw SocketError("socket: 잘못된 bind 주소 " + bind_ip);
    addr.sin_port = htons(port);

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        fail("socket");
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
        fail("bind");
    if (::listen(fd, 1) < 0)
        fail("listen");
    return fd;
}

uint16_t tcp_local_port(int listen_fd) {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    if (::getsockname(listen_fd, reinterpret_cast<sockaddr *>(&addr), &len) < 0)
        fail("getsockname");
    return ntohs(addr.sin_port);
}

int tcp_accept(int listen_fd) {
    int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0)
        fail("accept");
    return fd;
}

int tcp_connect(uint16_t port, const std::string &host) {
    // IPv4 주소 또는 호스트명 해석 (컨테이너 네트워크의 서비스명도 허용)
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res)
        throw SocketError("socket: 호스트 해석 실패 " + host + " (" + ::gai_strerror(rc) + ")");
    sockaddr_in addr = *reinterpret_cast<const sockaddr_in *>(res->ai_addr);
    ::freeaddrinfo(res);
    addr.sin_port = htons(port);

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        fail("socket");
    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        int saved = errno;
        ::close(fd);
        errno = saved;
        fail("connect");
    }
    return fd;
}

void close_fd(int fd) {
    if (fd >= 0)
        ::close(fd);
}

Transport make_socket_transport(int fd) {
    Transport t;
    // 핸드셰이크 프레임: 4바이트 헤더[type,ver,len(be)] 읽고 payload 이어 읽기
    t.send_frame = [fd](const Bytes &frame) { write_all(fd, frame.data(), frame.size()); };
    t.recv_frame = [fd]() -> Bytes {
        Bytes header(wire::kHeaderLen);
        if (!read_all(fd, header.data(), header.size()))
            throw SocketError("socket: 핸드셰이크 도중 연결 종료");
        uint16_t len = static_cast<uint16_t>(header[2] << 8 | header[3]);
        Bytes frame = header;
        frame.resize(wire::kHeaderLen + len);
        if (len > 0 && !read_all(fd, frame.data() + wire::kHeaderLen, len))
            throw SocketError("socket: payload 수신 중 연결 종료");
        return frame;
    };
    return t;
}

void send_record(int fd, const Bytes &record) {
    write_all(fd, record.data(), record.size());
}

Bytes recv_record(int fd) {
    Bytes header(2);
    if (!read_all(fd, header.data(), 2))
        return {}; // EOF: 정상 종료
    uint16_t len = static_cast<uint16_t>(header[0] << 8 | header[1]);
    Bytes record = header;
    record.resize(2 + len);
    if (len > 0 && !read_all(fd, record.data() + 2, len))
        throw SocketError("socket: 레코드 수신 중 연결 종료");
    return record;
}

} // namespace pqsec
