// crypto/include/pqsec/identity.h
//
// 장기 ML-DSA 신원의 파일 저장/로드. Week 2 fork 데모의 인메모리 신원을
// 실제 2-바이너리 프로비저닝(사전 배포된 상대 공개키)으로 승격한다.

#ifndef PQSEC_IDENTITY_H
#define PQSEC_IDENTITY_H

#include "pqsec/handshake.h" // Identity
#include "pqsec/pqc.h"       // Bytes

#include <string>

namespace pqsec {

// 바이너리 파일 IO. 실패 시 예외.
void write_bytes_file(const std::string &path, const Bytes &data, bool restrict_perms);
Bytes read_bytes_file(const std::string &path);

// ML-DSA 신원 키쌍 생성 → <prefix>.pub (공개키), <prefix>.key (개인키, 0600)
void generate_identity_files(const std::string &prefix);

// 내 공개키/개인키 + 사전보유한 상대 공개키를 읽어 Identity 구성. 길이 검증 포함.
Identity load_identity(const std::string &my_pub_path, const std::string &my_key_path,
                       const std::string &peer_pub_path);

} // namespace pqsec

#endif // PQSEC_IDENTITY_H
