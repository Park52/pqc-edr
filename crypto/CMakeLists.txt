# crypto — PQC 보안 채널 (하이브리드 KEM, record layer) + 예제
#
# 현재: PQC 래퍼(ML-KEM/ML-DSA) + 핸드셰이크 와이어 포맷.
# 이후: 하이브리드 KEM(X25519·HKDF) + record layer(AES-256-GCM) — libssl-dev 필요.

find_package(liboqs REQUIRED)
find_package(OpenSSL REQUIRED) # X25519 / HKDF / (이후) AES-256-GCM

# 보안 채널 라이브러리 (agent/analyzer 공유 예정)
add_library(pqsec_channel STATIC
  src/pqc_kem.cpp
  src/pqc_sig.cpp
  src/wire.cpp
  src/x25519.cpp
  src/kdf.cpp
  src/session.cpp
  src/record.cpp
  src/handshake.cpp
  src/socket.cpp
  src/identity.cpp)
target_include_directories(pqsec_channel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(pqsec_channel PUBLIC OQS::oqs OpenSSL::Crypto)

# ML-KEM keypair/encaps/decaps 왕복 데모
add_executable(mlkem_demo examples/mlkem_demo.cpp)
target_link_libraries(mlkem_demo PRIVATE OQS::oqs)

# 채널 셀프테스트 (ML-KEM/ML-DSA/와이어)
add_executable(channel_selftest examples/channel_selftest.cpp)
target_link_libraries(channel_selftest PRIVATE pqsec_channel OQS::oqs)

# 하이브리드 핸드셰이크 크립토 데모 (키합의 + 상호인증)
add_executable(hybrid_demo examples/hybrid_demo.cpp)
target_link_libraries(hybrid_demo PRIVATE pqsec_channel OQS::oqs)

# record layer 테스트 (AES-256-GCM 왕복 + 변조/재정렬/재전송 거부)
add_executable(record_demo examples/record_demo.cpp)
target_link_libraries(record_demo PRIVATE pqsec_channel OQS::oqs)

# 엔드투엔드 암호화 채널 데모 (실제 TCP 소켓, fork 로 agent/analyzer)
add_executable(channel_e2e_demo examples/channel_e2e_demo.cpp)
target_link_libraries(channel_e2e_demo PRIVATE pqsec_channel pqsec_common)

# 벤치마크: 프리미티브·핸드셰이크 지연, 하이브리드 vs 고전 오버헤드 (docs/BENCHMARK.md)
find_package(Threads REQUIRED)
add_executable(bench_handshake examples/bench_handshake.cpp)
target_link_libraries(bench_handshake PRIVATE pqsec_channel OQS::oqs OpenSSL::Crypto Threads::Threads)
