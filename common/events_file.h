// common/events_file.h — 재생/기록 파일(.events) 포맷의 파서·인코더.
// agent --replay / --record 와 analyzer_eval 이 공유한다 (헤더 온리, C++ 전용).
//
//   execve   <pid> <ppid> <comm> <filename>                 [anc:PID:COMM|…] [# … expect:<label>]
//   connect  <pid> <ppid> <comm> <ipv4> <port>              [anc:…]
//   fileopen <pid> <ppid> <comm> <access> <ino> <dev> <path>[anc:…]   access=w/c/s/x 조합 or '-'
//   delay    <ms>
//   #! known-miss: <이유>                         ← 파일 지시어 ('#!' 접두): 평가 게이트에서 제외
//   #! expect-max-severity: critical              ← 파일 지시어: 시나리오가 도달해야 할 최대 심각도
//
// - 필드는 공백 구분. 필드 안의 공백·'#'·'%' 는 %XX 로 퍼센트 인코딩(기록 시 인코딩, 파싱 시 디코딩).
// - 줄 끝 주석의 "expect:alert" / "expect:drop" 은 평가용 기대 라벨. agent 는 무시한다.
// - ts_ns 는 채우지 않는다(0). 호출자가 시계를 정한다: agent 는 실제 시각, eval 은 가상 시계.
// - 형식 오류는 예외(fail-closed) — 잘못된 코퍼스를 조용히 절반만 읽지 않는다.

#ifndef PQSEC_EVENTS_FILE_H
#define PQSEC_EVENTS_FILE_H

#include "event.h"

#include <arpa/inet.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <istream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace pqsec::events_file {

struct Entry {
    enum class Kind { Event, Delay, Directive };
    Kind kind = Kind::Event;
    security_event ev{};    // Kind::Event
    long delay_ms = 0;      // Kind::Delay
    std::string expect;     // 줄 주석의 expect:<label> (없으면 빈 문자열)
    std::string directive;  // Kind::Directive 본문 (예: "known-miss: 화이트리스트가 인자를 못 봄")
    int line = 0;
};

inline std::string encode_field(const std::string &s) {
    std::string o;
    for (unsigned char c : s) {
        if (c == ' ' || c == '#' || c == '%' || c == '\t' || c == '\n' || c == '\r') {
            char b[4];
            std::snprintf(b, sizeof(b), "%%%02X", c);
            o += b;
        } else {
            o += static_cast<char>(c);
        }
    }
    return o;
}

// 조상 스냅샷 인코딩: anc:PID:COMM|PID:COMM|...  (comm 은 퍼센트 인코딩). 빈 세대는 생략.
inline std::string encode_ancestry(const security_event &ev); // 아래 정의

inline std::string decode_field(const std::string &s) {
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) { // %XX
            char *end = nullptr;
            std::string hex = s.substr(i + 1, 2);
            long v = std::strtol(hex.c_str(), &end, 16);
            if (end && *end == '\0') {
                o += static_cast<char>(v);
                i += 2;
                continue;
            }
        }
        o += s[i];
    }
    return o;
}

inline std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

// file access 비트마스크 <-> "wcsx" 문자열 ('-' = 0)
inline std::string access_to_str(uint32_t a) {
    std::string o;
    if (a & PQSEC_FA_WRITE) o += 'w';
    if (a & PQSEC_FA_CREATE) o += 'c';
    if (a & PQSEC_FA_SENSITIVE) o += 's';
    if (a & PQSEC_FA_EXEC) o += 'x';
    return o.empty() ? "-" : o;
}
inline uint32_t access_from_str(const std::string &s) {
    uint32_t a = 0;
    for (char c : s) {
        if (c == 'w') a |= PQSEC_FA_WRITE;
        else if (c == 'c') a |= PQSEC_FA_CREATE;
        else if (c == 's') a |= PQSEC_FA_SENSITIVE;
        else if (c == 'x') a |= PQSEC_FA_EXEC;
    }
    return a;
}

// anc:PID:COMM|... 토큰을 ev.anc[] 로
inline void parse_ancestry(const std::string &tok, security_event &ev) {
    std::string body = tok.substr(4); // "anc:" 제거
    size_t i = 0, gen = 0;
    while (gen < PQSEC_ANCESTORS && i < body.size()) {
        size_t bar = body.find('|', i);
        std::string one = body.substr(i, bar == std::string::npos ? std::string::npos : bar - i);
        size_t colon = one.find(':');
        if (colon != std::string::npos) {
            ev.anc[gen].pid = static_cast<uint32_t>(std::strtoul(one.substr(0, colon).c_str(), nullptr, 10));
            std::string comm = decode_field(one.substr(colon + 1));
            std::strncpy(ev.anc[gen].comm, comm.c_str(), sizeof(ev.anc[gen].comm) - 1);
            ++gen;
        }
        if (bar == std::string::npos) break;
        i = bar + 1;
    }
}

// 스트림을 한 줄씩 파싱해 항목마다 cb 호출. name 은 오류 메시지용.
inline void parse(std::istream &in, const std::string &name,
                  const std::function<void(const Entry &)> &cb) {
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        std::string body = line, comment;
        size_t hash = line.find('#');
        if (hash != std::string::npos) {
            body = line.substr(0, hash);
            comment = line.substr(hash + 1);
        }
        auto bad = [&](const char *why) {
            throw std::runtime_error(name + ":" + std::to_string(lineno) + " " + why);
        };

        std::istringstream is(body);
        std::string kind;
        if (!(is >> kind)) {
            // 주석만 있는 줄 — '#!' 로 시작하면 파일 지시어
            std::string c = trim(comment);
            if (!c.empty() && c[0] == '!') {
                Entry e;
                e.kind = Entry::Kind::Directive;
                e.directive = trim(c.substr(1));
                e.line = lineno;
                cb(e);
            }
            continue;
        }

        Entry e;
        e.line = lineno;
        size_t ex = comment.find("expect:");
        if (ex != std::string::npos) {
            std::istringstream es(comment.substr(ex + 7));
            es >> e.expect;
        }

        if (kind == "delay") {
            long ms = -1;
            if (!(is >> ms) || ms < 0)
                bad("delay <ms> 형식 오류");
            e.kind = Entry::Kind::Delay;
            e.delay_ms = ms;
            cb(e);
            continue;
        }

        uint32_t pid = 0, ppid = 0;
        std::string comm;
        if (!(is >> pid >> ppid >> comm))
            bad("<pid> <ppid> <comm> 형식 오류");
        comm = decode_field(comm);
        e.ev.pid = pid;
        e.ev.ppid = ppid;
        std::strncpy(e.ev.comm, comm.c_str(), sizeof(e.ev.comm) - 1);

        if (kind == "execve") {
            std::string file;
            if (!(is >> file))
                bad("execve <filename> 누락");
            e.ev.type = PQSEC_EVT_EXECVE;
            std::string dfile = decode_field(file);
            std::strncpy(e.ev.u.execve.filename, dfile.c_str(), sizeof(e.ev.u.execve.filename) - 1);
        } else if (kind == "connect") {
            std::string ip;
            unsigned port = 0;
            if (!(is >> ip >> port) || port > 65535)
                bad("connect <ipv4> <port> 형식 오류");
            e.ev.type = PQSEC_EVT_TCP_CONNECT;
            e.ev.u.tcp.family = 2;
            if (inet_pton(AF_INET, ip.c_str(), &e.ev.u.tcp.daddr) != 1)
                bad("잘못된 IPv4 주소");
            e.ev.u.tcp.dport = static_cast<uint16_t>(port);
        } else if (kind == "fileopen") {
            std::string acc, path;
            unsigned long long ino = 0;
            unsigned long dev = 0;
            if (!(is >> acc >> ino >> dev >> path))
                bad("fileopen <access> <ino> <dev> <path> 형식 오류");
            e.ev.type = PQSEC_EVT_FILE_OPEN;
            e.ev.u.file.access = access_from_str(acc);
            e.ev.u.file.ino = ino;
            e.ev.u.file.dev = static_cast<uint32_t>(dev);
            std::string dpath = decode_field(path);
            if (dpath != "-")
                std::strncpy(e.ev.u.file.path, dpath.c_str(), sizeof(e.ev.u.file.path) - 1);
        } else {
            bad("알 수 없는 항목 종류");
        }
        // 선택 토큰: anc:...
        std::string tok;
        while (is >> tok)
            if (tok.rfind("anc:", 0) == 0) parse_ancestry(tok, e.ev);
        cb(e);
    }
}

// 기록: security_event → 한 줄. execve/connect 만 기록하고 그 외 타입은 빈 문자열.
inline std::string format_line(const security_event &ev) {
    std::string comm(ev.comm, strnlen(ev.comm, sizeof(ev.comm)));
    char buf[512];
    if (ev.type == PQSEC_EVT_EXECVE) {
        std::string file(ev.u.execve.filename, strnlen(ev.u.execve.filename, sizeof(ev.u.execve.filename)));
        std::snprintf(buf, sizeof(buf), "execve  %u %u %s %s", ev.pid, ev.ppid,
                      encode_field(comm.empty() ? "?" : comm).c_str(),
                      encode_field(file.empty() ? "?" : file).c_str());
        return std::string(buf) + encode_ancestry(ev);
    }
    if (ev.type == PQSEC_EVT_TCP_CONNECT) {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ev.u.tcp.daddr, ip, sizeof(ip));
        std::snprintf(buf, sizeof(buf), "connect %u %u %s %s %u", ev.pid, ev.ppid,
                      encode_field(comm.empty() ? "?" : comm).c_str(), ip, ev.u.tcp.dport);
        return std::string(buf) + encode_ancestry(ev);
    }
    if (ev.type == PQSEC_EVT_FILE_OPEN) {
        std::string path(ev.u.file.path, strnlen(ev.u.file.path, sizeof(ev.u.file.path)));
        std::snprintf(buf, sizeof(buf), "fileopen %u %u %s %s %llu %u %s", ev.pid, ev.ppid,
                      encode_field(comm.empty() ? "?" : comm).c_str(),
                      access_to_str(ev.u.file.access).c_str(),
                      static_cast<unsigned long long>(ev.u.file.ino), ev.u.file.dev,
                      path.empty() ? "-" : encode_field(path).c_str());
        return std::string(buf) + encode_ancestry(ev);
    }
    return "";
}

inline std::string encode_ancestry(const security_event &ev) {
    std::string o;
    for (int i = 0; i < PQSEC_ANCESTORS; ++i) {
        if (ev.anc[i].pid == 0 && ev.anc[i].comm[0] == '\0') continue;
        std::string comm(ev.anc[i].comm, strnlen(ev.anc[i].comm, sizeof(ev.anc[i].comm)));
        o += (o.empty() ? " anc:" : "|") + std::to_string(ev.anc[i].pid) + ":" +
             encode_field(comm.empty() ? "?" : comm);
    }
    return o;
}

} // namespace pqsec::events_file

#endif // PQSEC_EVENTS_FILE_H
